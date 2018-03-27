using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLibrary.FlowScriptLanguage.BinaryModel.Tests
{
    [TestClass]
    public class FlowScriptBinaryTests
    {
        private void FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion version, BinaryFormatVersion actualVersion )
        {
            var script = FlowScriptBinary.FromFile( $"TestResources\\{actualVersion}.bf", version );

            Assert.IsNotNull( script, "Script object should not be null" );
            Assert.AreEqual( actualVersion, script.FormatVersion );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithVersion1Parameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Version1, BinaryFormatVersion.Version1 );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Unknown, BinaryFormatVersion.Version1 );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version1WithVersion3BigEndianParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Version3BigEndian, BinaryFormatVersion.Version1 );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithVersion2Parameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Version2, BinaryFormatVersion.Version2 );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Unknown, BinaryFormatVersion.Version2 );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version2WithVersion3BigEndianVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Version3BigEndian, BinaryFormatVersion.Version2 );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3BigEndianWithVersion3BigEndianVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Version3BigEndian, BinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3BigEndianWithUnknownVersionParameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Unknown, BinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod]
        public void FromFile_ResultNotNullAndFormatIsEqualToParameter_Version3BigEndianWithVersion1Parameter()
        {
            FromFile_ResultNotNullAndFormatIsEqualToParameter( BinaryFormatVersion.Version1, BinaryFormatVersion.Version3BigEndian );
        }

        [TestMethod]
        public void FromFileTest_InvalidFileFormat_Small()
        {
            Assert.ThrowsException<InvalidDataException>( () => FlowScriptBinary.FromFile( "TestResources\\dummy_small.bin", BinaryFormatVersion.Unknown ) );
        }

        [TestMethod]
        public void FromFileTest_InvalidFileFormat_Big()
        {
            Assert.ThrowsException<InvalidDataException>( () => FlowScriptBinary.FromFile( "TestResources\\dummy_big.bin", BinaryFormatVersion.Unknown ) );
        }

        [TestMethod]
        [Ignore]
        public void FromFileTest_Batch()
        {
            foreach ( var path in Directory.EnumerateFiles( "TestResources\\Batch\\", "*.bf" ) )
            {
                var script = FlowScriptBinary.FromFile( path, BinaryFormatVersion.Version3BigEndian );

                Assert.IsNotNull( script );
            }
        }

        [TestMethod]
        public void FromStreamTest()
        {
            using ( var fileStream = File.OpenRead( "TestResources\\Version3BigEndian.bf" ) )
            {
                var script = FlowScriptBinary.FromStream( fileStream, BinaryFormatVersion.Version3BigEndian );

                Assert.IsNotNull( script );
                Assert.AreEqual( BinaryFormatVersion.Version3BigEndian, script.FormatVersion );
            }
        }
    }
}