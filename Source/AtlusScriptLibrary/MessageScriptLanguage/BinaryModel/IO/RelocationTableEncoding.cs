using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage.IO
{
    public static class RelocationTableEncoding
    {
        private const byte ADDRESS_SIZE = sizeof( int );
        private const byte SEQ_BASE = 0x07;
        private const byte SEQ_BASE_NUM_LOOP = 2;
        private const byte SEQ_FLAG_ODD = 1 << 3;

        public static int[] Decode( byte[] relocationTable, int addressBaseOffset )
        {
            List<int> addressLocs = new List<int>();
            int prevRelocSum = 0;

            for ( int i = 0; i < relocationTable.Length; i++ )
            {
                int reloc = relocationTable[i];

                // Check if the value is odd
                if ( ( reloc % 2 ) != 0 )
                {
                    // Check if the value indicates a sequence run of addresses
                    if ( ( reloc & SEQ_BASE ) == SEQ_BASE )
                    {
                        // Get the base loop multiplier
                        int baseLoopMult = ( reloc & 0xF0 ) >> 4;

                        // Get the number of loops, base loop number is 2
                        int numLoop = SEQ_BASE_NUM_LOOP + ( baseLoopMult * SEQ_BASE_NUM_LOOP );

                        // Check if the number of loops is odd
                        if ( ( reloc & SEQ_FLAG_ODD ) == SEQ_FLAG_ODD )
                        {
                            // If so then add an extra loop cycle.
                            numLoop += 1;
                        }

                        for ( int j = 0; j < numLoop; j++ )
                        {
                            addressLocs.Add( addressBaseOffset + prevRelocSum + ADDRESS_SIZE );
                            prevRelocSum += ADDRESS_SIZE;
                        }

                        // Continue the loop early so we skip adding the reloc value to the list later on
                        continue;
                    }
                    // If value isn't a sequence run then read the next byte and bitwise OR it onto the value

                    // Decrement the reloc value to remove the extra bit added to make it an odd number
                    reloc -= 1;
                    reloc |= relocationTable[++i] << 8;
                }
                else
                {
                    // If the value isn't odd, shift the value 1 bit to the left
                    reloc <<= 1;
                }

                addressLocs.Add( addressBaseOffset + prevRelocSum + reloc );
                prevRelocSum += reloc;
            }

            return addressLocs.ToArray();
        }

        public static byte[] Encode( IList<int> addressLocations, int addressBaseOffset )
        {
            int prevRelocSum = 0;
            List<byte> relocationTable = new List<byte>();

            // Detect address sequence runs
            List<AddressSequence> sequences = DetectAddressSequenceRuns( addressLocations );

            for ( int addressLocationIndex = 0; addressLocationIndex < addressLocations.Count; addressLocationIndex++ )
            {
                int seqIdx = sequences.FindIndex( item => item.AddressLocationListStartIndex == addressLocationIndex );
                int reloc = ( addressLocations[addressLocationIndex] - prevRelocSum ) - addressBaseOffset;

                // Check if a matching sequence was found
                if ( seqIdx == -1 )
                {
                    // Encode address and add it to the list of bytes
                    EncodeAddress( reloc, relocationTable, ref prevRelocSum );
                }
                else
                {
                    // We have a sequence to add.
                    // Use the first entry to position to the start of the sequence

                    // Encode the first entries' address and add it to the list of bytes
                    EncodeAddress( reloc, relocationTable, ref prevRelocSum );

                    // Subtract one because the first entry is used to locate to the start of the sequence
                    int numberOfAddressesInSequence = sequences[seqIdx].SequenceAddressCount - 1;

                    int baseLoopMult = ( numberOfAddressesInSequence - SEQ_BASE_NUM_LOOP ) / SEQ_BASE_NUM_LOOP;
                    bool isOdd = ( numberOfAddressesInSequence % 2 ) == 1;

                    reloc = SEQ_BASE;
                    reloc |= baseLoopMult << 4;

                    if ( isOdd )
                    {
                        reloc |= SEQ_FLAG_ODD;
                    }

                    relocationTable.Add( ( byte )reloc );

                    addressLocationIndex += numberOfAddressesInSequence;
                    prevRelocSum += numberOfAddressesInSequence * ADDRESS_SIZE;
                }
            }

            return relocationTable.ToArray();
        }

        private static void EncodeAddress( int reloc, List<byte> relocationTable, ref int sumOfPreviousRelocations )
        {
            // First we check if we can shift it to the right to shrink the value.
            // Check if lowest bit is set to see if we an shift it to the right
            if ( ( reloc & 0x01 ) == 0 )
            {
                // We can shift to the right without losing data
                int newReloc = reloc >> 1;

                if ( newReloc <= byte.MaxValue )
                {
                    // If the shifted reloc is within the byte size boundary, add it to the reloc byte list
                    relocationTable.Add( ( byte )newReloc );
                }
                else
                {
                    // If it's still too big, extend it.
                    ExtendAddressRelocation( reloc, relocationTable );
                }
            }
            else
            {
                // If we can't shift to the right to shrink it, we must extend it.
                ExtendAddressRelocation( reloc, relocationTable );
            }

            // Add the reloc value to the current sum of reloc values
            sumOfPreviousRelocations += reloc;
        }

        private static void ExtendAddressRelocation( int reloc, List<byte> addressRelocBytes )
        {
            // Make the low bits odd by adding 1 to them to indicate that it's an extended reloc.
            byte relocLo = ( byte )( ( reloc & 0x00FF ) + 1 );
            byte relocHi = ( byte )( ( reloc & 0xFF00 ) >> 8 );

            addressRelocBytes.Add( relocLo );
            addressRelocBytes.Add( relocHi );
        }

        private static List<AddressSequence> DetectAddressSequenceRuns( IList<int> addressLocations )
        {
            List<AddressSequence> sequences = new List<AddressSequence>();

            for ( int addressIndex = 0; addressIndex < addressLocations.Count; addressIndex++ )
            {
                // There can't be any more sequences if we're on the last iteration
                if ( addressIndex + 1 == addressLocations.Count )
                {
                    break;
                }

                if ( addressLocations[addressIndex + 1] - addressLocations[addressIndex] == ADDRESS_SIZE )
                {
                    // We have found a sequence of at least 2 addresses
                    AddressSequence seq = new AddressSequence
                    {
                        AddressLocationListStartIndex = addressIndex++,
                        SequenceAddressCount = 2
                    };

                    while ( addressIndex + 1 < addressLocations.Count )
                    {
                        if ( addressLocations[addressIndex + 1] - addressLocations[addressIndex] == ADDRESS_SIZE )
                        {
                            // We have found another sequence to add.
                            seq.SequenceAddressCount++;
                            addressIndex++;
                        }
                        else
                        {
                            // The consecutive sequence ends.
                            break;
                        }
                    }

                    // Check if there are more than 2 addresses in a sequence.
                    if ( seq.SequenceAddressCount > 2 )
                    {
                        // Add the sequence to the list of sequences.
                        sequences.Add( seq );
                    }
                }
            }

            return sequences;
        }

        private struct AddressSequence
        {
            public int AddressLocationListStartIndex;
            public int SequenceAddressCount;
        }
    }
}
