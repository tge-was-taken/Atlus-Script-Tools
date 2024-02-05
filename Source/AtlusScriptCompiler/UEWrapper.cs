using AtlusScriptLibrary.Common.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptCompiler
{
    public class UEWrapper
    {
        public static uint GraphDataOffset;
        public static uint GraphDataSize;
        public static uint ExportMapOffset;
        public static ulong CookedSerialSize;

        public static string[] constantCommonImports =
        {
            "/Script/CoreUObject", "ArrayProperty", "Class", "mBuf", "None", "Package"
        };
        public static string[] constantBfImoprts = 
        {
            "/Script/BfAssetPlugin", "ByteProperty", "BfAsset", "Default__BfAsset"
        };
        public static string[] constantBmdImoprts = 
        {
            "/Script/BmdAssetPlugin", "Int8Property", "BmdAsset", "Default__BmdAsset"
        };

        public static uint AlgorithmHash = 0xC1640000;

        public static byte[] UexpFormattingAfter = { 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };


        public static int FORMATTING_SIZE = 0x25; // from beginning of "uexp" portion to start of bf block
        public static bool UnwrapAsset( string dir, string name, string ext, Stream stream, out string outName )
        {
            var endianReader = new EndianBinaryReader(stream, Endianness.LittleEndian); // UE stuff is in little endian
            ReadIoStorePackageSummaryHeader(endianReader);
            // Get out of there
            //endianReader.SeekBegin(GraphDataOffset + GraphDataSize + 0x25);
            endianReader.SeekBegin(ExportMapOffset);
            ReadExportMapEntry(endianReader);
            CookedSerialSize -= (ulong)FORMATTING_SIZE; // length of data preceeding BF
            endianReader.SeekBegin(GraphDataOffset + GraphDataSize + FORMATTING_SIZE);
            var startPos = endianReader.Position;
            byte[] buffer = new byte[CookedSerialSize];
            stream.Position = startPos;
            stream.Read(buffer, 0, (int)CookedSerialSize);
            outName = Path.Combine(dir, $"{name}_unwrapped{ext}");
            using (var fileOut = File.Create(outName)) { fileOut.Write(buffer, 0, buffer.Length); }
            return false;
        }

        public static void ReadIoStorePackageSummaryHeader(EndianBinaryReader reader) // Accurate for UE 4.27
        {
            reader.ReadUInt64(); // Name
            reader.ReadUInt64(); // SourceName
            reader.ReadUInt32(); // PackageFlags
            reader.ReadUInt32(); // CookedHeaderSize
            reader.ReadUInt32(); // NameMapNamesOffset
            reader.ReadUInt32(); // NameMapNamesSize
            reader.ReadUInt32(); // NameMapHashesOffset
            reader.ReadUInt32(); // NameMapHashesSIze
            reader.ReadUInt32(); // ImportMapOffset
            ExportMapOffset = reader.ReadUInt32(); // ExportMapOffset
            reader.ReadUInt32(); // ExportBudlesOffset
            GraphDataOffset = reader.ReadUInt32(); // GraphDataOffset
            GraphDataSize = reader.ReadUInt32(); // GraphDataSize
            reader.ReadUInt32(); // Padding
        }

        public static void ReadExportMapEntry(EndianBinaryReader reader)
        {
            reader.ReadUInt64(); // CookedSerialOffset
            CookedSerialSize = reader.ReadUInt64(); // CookedSerialSize
        }

        public static void WriteFString16(EndianBinaryWriter writer, string text)
        {
            writer.Write((byte)0);
            if (text.Length > 0xff) throw new Exception($"Name \"{text}\" is too long to converted into FString");
            writer.Write((byte)text.Length);
            writer.Write(Encoding.ASCII.GetBytes(text));
        }
    }
}
