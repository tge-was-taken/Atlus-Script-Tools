using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using AtlusScriptLib.FlowScriptLanguage.BinaryModel;
using AtlusScriptLib.FlowScriptLanguage;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class FlowScriptTests
    {
        private FlowScript FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion version, FlowScriptBinaryFormatVersion actualVersion )
        {
            var script = FlowScript.FromFile( $"TestResources\\{actualVersion}.bf", version );

            Assert.IsNotNull( script, "Script object should not be null" );
            Assert.AreEqual( (FlowScriptFormatVersion)actualVersion, script.FormatVersion );

            return script;
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithSameVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version1, FlowScriptBinaryFormatVersion.Version1 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.Version1 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithWrongVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version3BigEndian, FlowScriptBinaryFormatVersion.Version1 );
        }

        [TestMethod()]
        public void FromFile_ShouldNotFailIntegrityCheck_Version1()
        {
            var script = FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version1, FlowScriptBinaryFormatVersion.Version1 );

            var instructions = script.EnumerateInstructions().ToList();
            Assert.AreEqual( 10061, instructions.Count );
            //Assert.AreEqual( 742, script.JumpLabels.Count );
            //Assert.AreEqual(77521, script.MessageScript);
            Assert.AreEqual( 96, script.Procedures.Count );
            Assert.AreEqual( FlowScriptOpcode.COMM, instructions[2].Opcode );
            Assert.AreEqual( 102, instructions[2].Operand.GetInt16Value() );
            Assert.ThrowsException<InvalidOperationException>( () => instructions[2].Operand.GetInt32Value() );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithSameVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version2, FlowScriptBinaryFormatVersion.Version2 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.Version2 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithWrongVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version3BigEndian, FlowScriptBinaryFormatVersion.Version2 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3WithSameVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version3BigEndian, FlowScriptBinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3WithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3WithWrongVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version1, FlowScriptBinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod()]
        public void FromFile_ShouldThrowInvalidDataException_InvalidFileFormatSmall()
        {
            Assert.ThrowsException<InvalidDataException>( () => FlowScript.FromFile( "TestResources\\dummy_small.bin", FlowScriptBinaryFormatVersion.Unknown ) );
        }

        [TestMethod()]
        public void FromFile_ShouldThrowInvalidDataException_InvalidFileFormatBig()
        {
            Assert.ThrowsException<InvalidDataException>( () => FlowScript.FromFile( "TestResources\\dummy_big.bin", FlowScriptBinaryFormatVersion.Unknown ) );
        }

        [TestMethod()]
        public void FromFile_ShouldNotThrow_Batch()
        {
            foreach ( var path in Directory.EnumerateFiles( "TestResources\\Batch\\", "*.bf" ) )
            {
                var script = FlowScript.FromFile( path );
            }
        }

        [TestMethod()]
        public void FromStream_ShouldNotBeNullAndIsSameVersion_Version3BigEndian()
        {
            using ( var fileStream = File.OpenRead( "TestResources\\Version3BigEndian.bf" ) )
            {
                var script = FlowScript.FromStream( fileStream, FlowScriptBinaryFormatVersion.Version3BigEndian );

                Assert.IsNotNull( script );
                Assert.AreEqual( FlowScriptFormatVersion.Version3BigEndian, script.FormatVersion );
            }
        }

        [TestMethod()]
        public void FromBinary_ContentsShouldMatchThatOfBinary_Version3BigEndian()
        {
            var binary = FlowScriptBinary.FromFile( "TestResources\\Version3BigEndian.bf", FlowScriptBinaryFormatVersion.Version3BigEndian );
            var script = FlowScript.FromBinary( binary );

            Assert.AreEqual( script.UserId, binary.Header.UserId );

            // Compare label names
            for ( int i = 0; i < script.Procedures.Count; i++ )
            {
                Assert.AreEqual( binary.ProcedureLabelSection[i].Name, script.Procedures[i].Name );
            }

            /*
            for ( int i = 0; i < script.JumpLabels.Count; i++ )
            {
                Assert.AreEqual( binary.JumpLabelSection[i].Name, script.JumpLabels[i].Name );
            }
            */

            // Compare instructions
            int binaryIndex = 0;
            foreach ( var instruction in script.EnumerateInstructions() )
            {
                var binaryInstruction = binary.TextSection[binaryIndex++];
                Assert.AreEqual( binaryInstruction.Opcode, instruction.Opcode );

                if ( instruction.Operand != null )
                {
                    switch ( instruction.Operand.Type )
                    {
                        case FlowScriptInstruction.OperandValue.ValueType.Int16:
                            if ( instruction.Opcode != FlowScriptOpcode.IF && instruction.Opcode != FlowScriptOpcode.GOTO )
                                Assert.AreEqual( binaryInstruction.OperandShort, instruction.Operand.GetInt16Value() );
                            break;
                        case FlowScriptInstruction.OperandValue.ValueType.Int32:
                            Assert.AreEqual( binary.TextSection[binaryIndex++].OperandInt, instruction.Operand.GetInt32Value() );
                            break;
                        case FlowScriptInstruction.OperandValue.ValueType.Single:
                            Assert.AreEqual( binary.TextSection[binaryIndex++].OperandFloat, instruction.Operand.GetSingleValue() );
                            break;
                        case FlowScriptInstruction.OperandValue.ValueType.String:
                            break;
                    }
                }
            }
        }

        [TestMethod()]
        public void ToBinary_ContentsShouldMatchThatOfSourceBinary_Version3BigEndian()
        {
            var binaryIn = FlowScriptBinary.FromFile( "TestResources\\Version3BigEndian.bf" );
            var script = FlowScript.FromBinary( binaryIn );
            var binaryOut = script.ToBinary();

            // Compare headers
            Assert.AreEqual( binaryIn.Header.FileType, binaryOut.Header.FileType );
            Assert.AreEqual( binaryIn.Header.Compressed, binaryOut.Header.Compressed );
            Assert.AreEqual( binaryIn.Header.UserId, binaryOut.Header.UserId );
            Assert.AreEqual( binaryIn.Header.FileSize, binaryOut.Header.FileSize );
            Assert.IsTrue( binaryIn.Header.Magic.SequenceEqual( binaryOut.Header.Magic ) );
            Assert.AreEqual( binaryIn.Header.Field0C, binaryOut.Header.Field0C );
            Assert.AreEqual( binaryIn.Header.SectionCount, binaryOut.Header.SectionCount );
            Assert.AreEqual( binaryIn.Header.LocalIntVariableCount, binaryOut.Header.LocalIntVariableCount );
            Assert.AreEqual( binaryIn.Header.LocalFloatVariableCount, binaryOut.Header.LocalFloatVariableCount );
            Assert.AreEqual( binaryIn.Header.Endianness, binaryOut.Header.Endianness );
            Assert.AreEqual( binaryIn.Header.Field1A, binaryOut.Header.Field1A );
            Assert.AreEqual( binaryIn.Header.Padding, binaryOut.Header.Padding );

            // Compare section headers
            for ( int i = 0; i < binaryIn.SectionHeaders.Count; i++ )
            {
                Assert.AreEqual( binaryIn.SectionHeaders[i].SectionType, binaryOut.SectionHeaders[i].SectionType );
                Assert.AreEqual( binaryIn.SectionHeaders[i].ElementSize, binaryOut.SectionHeaders[i].ElementSize );
                Assert.AreEqual( binaryIn.SectionHeaders[i].ElementCount, binaryOut.SectionHeaders[i].ElementCount );
                Assert.AreEqual( binaryIn.SectionHeaders[i].FirstElementAddress, binaryOut.SectionHeaders[i].FirstElementAddress );
            }

            // Compare labels
            for ( int i = 0; i < binaryIn.ProcedureLabelSection.Count; i++ )
            {
                Assert.AreEqual( binaryIn.ProcedureLabelSection[i].Name, binaryOut.ProcedureLabelSection[i].Name );
                Assert.AreEqual( binaryIn.ProcedureLabelSection[i].InstructionIndex, binaryOut.ProcedureLabelSection[i].InstructionIndex );
                Assert.AreEqual( binaryIn.ProcedureLabelSection[i].Reserved, binaryOut.ProcedureLabelSection[i].Reserved );
            }

            for ( int i = 0; i < binaryIn.JumpLabelSection.Count; i++ )
            {
                Assert.AreEqual( binaryIn.JumpLabelSection[i].Name, binaryOut.JumpLabelSection[i].Name );
                Assert.AreEqual( binaryIn.JumpLabelSection[i].InstructionIndex, binaryOut.JumpLabelSection[i].InstructionIndex );
                Assert.AreEqual( binaryIn.JumpLabelSection[i].Reserved, binaryOut.JumpLabelSection[i].Reserved );
            }

            // Compare instructions
            for ( int i = 0; i < binaryIn.TextSection.Count; i++ )
            {
                var inInstruction = binaryIn.TextSection[i];
                var outInstruction = binaryOut.TextSection[i];

                Assert.AreEqual( inInstruction.Opcode, outInstruction.Opcode );

                if ( inInstruction.Opcode == FlowScriptOpcode.PUSHI || inInstruction.Opcode == FlowScriptOpcode.PUSHF )
                {
                    ++i;
                    continue;
                }

                if ( inInstruction.Opcode == FlowScriptOpcode.IF || inInstruction.Opcode == FlowScriptOpcode.GOTO )
                {
                    Assert.AreEqual( binaryIn.JumpLabelSection[inInstruction.OperandShort].Name, binaryOut.JumpLabelSection[outInstruction.OperandShort].Name );
                }
                else
                {
                    Assert.AreEqual( inInstruction.OperandShort, outInstruction.OperandShort );
                }         
            }

            // Compare message script
            //Assert.IsTrue(binaryIn.MessageScriptSection.SequenceEqual(binaryOut.MessageScriptSection));

            // Compare strings
            Assert.IsTrue( binaryIn.StringSection.SequenceEqual( binaryOut.StringSection ) );
        }
    }
}