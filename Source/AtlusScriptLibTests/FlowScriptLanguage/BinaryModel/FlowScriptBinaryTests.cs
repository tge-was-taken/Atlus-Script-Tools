using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace AtlusScriptLib.FlowScriptLanguage.BinaryModel.Tests
{
    [TestClass()]
    public class FlowScriptBinaryTests
    {
        private void FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion version, FlowScriptBinaryFormatVersion actualVersion )
        {
            var script = FlowScriptBinary.FromFile( $"TestResources\\{actualVersion}.bf", version );

            Assert.IsNotNull( script, "Script object should not be null" );
            Assert.AreEqual( actualVersion, script.FormatVersion );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithVersion1Parameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version1, FlowScriptBinaryFormatVersion.Version1 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.Version1 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithVersion3BigEndianParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version3BigEndian, FlowScriptBinaryFormatVersion.Version1 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithVersion2Parameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version2, FlowScriptBinaryFormatVersion.Version2 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.Version2 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithVersion3BigEndianVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version3BigEndian, FlowScriptBinaryFormatVersion.Version2 );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3BigEndianWithVersion3BigEndianVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version3BigEndian, FlowScriptBinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3BigEndianWithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod()]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3BigEndianWithVersion1Parameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( FlowScriptBinaryFormatVersion.Version1, FlowScriptBinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod()]
        public void FromFileTest_InvalidFileFormat_Small()
        {
            Assert.ThrowsException<InvalidDataException>( () => FlowScriptBinary.FromFile( "TestResources\\dummy_small.bin", FlowScriptBinaryFormatVersion.Unknown ) );
        }

        [TestMethod()]
        public void FromFileTest_InvalidFileFormat_Big()
        {
            Assert.ThrowsException<InvalidDataException>( () => FlowScriptBinary.FromFile( "TestResources\\dummy_big.bin", FlowScriptBinaryFormatVersion.Unknown ) );
        }

        [TestMethod()]
        [Ignore]
        public void FromFileTest_Batch()
        {
            foreach ( var path in Directory.EnumerateFiles( "TestResources\\Batch\\", "*.bf" ) )
            {
                var script = FlowScriptBinary.FromFile( path, FlowScriptBinaryFormatVersion.Version3BigEndian );

                Assert.IsNotNull( script );
            }
        }

        [TestMethod()]
        public void FromStreamTest()
        {
            using ( var fileStream = File.OpenRead( "TestResources\\Version3BigEndian.bf" ) )
            {
                var script = FlowScriptBinary.FromStream( fileStream, FlowScriptBinaryFormatVersion.Version3BigEndian );

                Assert.IsNotNull( script );
                Assert.AreEqual( FlowScriptBinaryFormatVersion.Version3BigEndian, script.FormatVersion );
            }
        }
    }
}