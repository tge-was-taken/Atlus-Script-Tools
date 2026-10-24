using System;
using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

public static class RelocationTableEncoding
{
    private const byte ADDRESS_SIZE = sizeof(int);
    private const byte SEQ_LOOP = 0xF8;
    private const byte SEQ_BASE = 0x07;
    private const byte SEQ_BASE_NUM_LOOP = 2;
    private const byte SEQ_MAX_NUM_LOOP = 33;

    public static int[] Decode(byte[] relocationTable, int addressBaseOffset)
    {
        List<int> addressLocs = new List<int>();
        int prevRelocSum = 0;

        for (int i = 0; i < relocationTable.Length; i++)
        {
            int reloc = relocationTable[i];

            // Check if the value is odd
            if (reloc % 2 != 0)
            {
                // Check if the value indicates a sequence run of addresses
                if ((reloc & SEQ_BASE) == SEQ_BASE)
                {
                    // Get the encoded loop number
                    int loop = (reloc & SEQ_LOOP) >> 3;

                    // Get the number of loops, base loop number is 2
                    int numLoop = SEQ_BASE_NUM_LOOP + loop;

                    for (int j = 0; j < numLoop; j++)
                    {
                        addressLocs.Add(addressBaseOffset + prevRelocSum + ADDRESS_SIZE);
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

            addressLocs.Add(addressBaseOffset + prevRelocSum + reloc);
            prevRelocSum += reloc;
        }

        return addressLocs.ToArray();
    }

    // nullExtendedEntries reproduces the original V2 writer, which emits two zero bytes instead of
    // the real delta for a pointer more than 0x1FE bytes past the previous one.
    public static byte[] Encode(IList<int> addressLocations, int addressBaseOffset, bool nullExtendedEntries = false)
    {
        int prevRelocSum = 0;
        var relocationTable = new List<byte>();

        for (int i = 0; i < addressLocations.Count;)
        {
            // A sequence byte walks forward one address at a time, so it can only cover addresses
            // that are consecutive and start right after the addresses encoded so far.
            int runLength = 0;
            while (i + runLength < addressLocations.Count &&
                   addressLocations[i + runLength] - addressBaseOffset == prevRelocSum + ADDRESS_SIZE * (runLength + 1))
            {
                runLength++;
            }

            if (runLength < SEQ_BASE_NUM_LOOP)
            {
                EncodeAddress(addressLocations[i] - prevRelocSum - addressBaseOffset, relocationTable, ref prevRelocSum, nullExtendedEntries);
                i++;
                continue;
            }

            while (runLength >= SEQ_BASE_NUM_LOOP)
            {
                var count = Math.Min(runLength, SEQ_MAX_NUM_LOOP);
                relocationTable.Add((byte)((count - SEQ_BASE_NUM_LOOP) << 3 | SEQ_BASE));
                prevRelocSum += count * ADDRESS_SIZE;
                runLength -= count;
                i += count;
            }
        }

        return relocationTable.ToArray();
    }

    private static void EncodeAddress(int reloc, List<byte> relocationTable, ref int sumOfPreviousRelocations, bool nullExtendedEntries)
    {
        // First we check if we can shift it to the right to shrink the value.
        // Check if lowest bit is set to see if we an shift it to the right
        if ((reloc & 0x01) == 0)
        {
            // We can shift to the right without losing data
            int newReloc = reloc >> 1;

            if (newReloc <= byte.MaxValue)
            {
                // If the shifted reloc is within the byte size boundary, add it to the reloc byte list
                relocationTable.Add((byte)newReloc);
            }
            else
            {
                // If it's still too big, extend it.
                ExtendAddressRelocation(reloc, relocationTable, nullExtendedEntries);
            }
        }
        else
        {
            // If we can't shift to the right to shrink it, we must extend it.
            ExtendAddressRelocation(reloc, relocationTable, nullExtendedEntries);
        }

        // Add the reloc value to the current sum of reloc values
        sumOfPreviousRelocations += reloc;
    }

    private static void ExtendAddressRelocation(int reloc, List<byte> addressRelocBytes, bool nullEntry)
    {
        if (nullEntry)
        {
            addressRelocBytes.Add(0);
            addressRelocBytes.Add(0);
            return;
        }

        // Make the low bits odd by adding 1 to them to indicate that it's an extended reloc.
        byte relocLo = (byte)((reloc & 0x00FF) + 1);
        byte relocHi = (byte)((reloc & 0xFF00) >> 8);

        addressRelocBytes.Add(relocLo);
        addressRelocBytes.Add(relocHi);
    }

}
