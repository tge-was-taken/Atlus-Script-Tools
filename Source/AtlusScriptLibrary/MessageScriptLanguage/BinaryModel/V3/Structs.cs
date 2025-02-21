using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3;

public class Bm2Header
{
    public static readonly byte[] MAGIC = [0x32, 0x47, 0x53, 0x4D];
    public static readonly byte[] MAGIC_BE = [0x4D, 0x53, 0x47, 0x32];
    public static readonly uint VERSION = 0x10000;

    public uint Field00 { get; set; }
    public byte[] Magic { get; set; }
    public uint Version { get; set; }
    public uint FileSize { get; set; }
    public uint Header2Offset { get; set; }
}

public class Bm2Header2
{
    public uint SpeakerCount { get; set; }
    public uint SpeakerArrayOffset { get; set; }
    public uint MessageCount { get; set; }
    public uint MessageArrayOffset { get; set; }
}

public class Bm2Speaker
{
    public uint Field00 { get; set; }
    public uint DataSize { get; set; }
    public uint DataOffset { get; set; }
    public uint Field0C { get; set; }
    public byte[] Data { get; set; }
}

public class Bm2Message
{
    public string Name { get; set; }
    public uint Field30 { get; set; }
    public uint DataSize { get; set; }
    public uint DataOffset { get; set; }
    public ushort SpeakerId { get; set; }
    public ushort Field3E { get; set; }
    public uint Field40 { get; set; }
    public uint Field44 { get; set; }
    public uint Field48 { get; set; }
    public uint Field4C { get; set; }
    public Bm2MessageData Data { get; set; }
}

public class Bm2MessageData
{
    public uint PageCount { get; set; }
    public List<int> PageOffsets { get; set; }
    public byte[] TextBuffer { get; set; }
}
