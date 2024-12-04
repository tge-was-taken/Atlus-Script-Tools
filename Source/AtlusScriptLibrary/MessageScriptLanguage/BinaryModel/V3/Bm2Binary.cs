using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3.IO;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3;

public class Bm2Binary : IMessageScriptBinary
{
    public static bool IsValidStream(Stream stream)
    {
        var magic = new byte[4];
        stream.Position = 4;
        stream.Read(magic, 0, magic.Length);
        stream.Position = 0;
        return magic.SequenceEqual(Bm2Header.MAGIC_BE) || magic.SequenceEqual(Bm2Header.MAGIC);
    }

    public static Bm2Binary FromFile(string path)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("Value cannot be null or empty.", nameof(path));

        return FromFile(path, BinaryFormatVersion.Unknown);
    }

    public static Bm2Binary FromFile(string path, BinaryFormatVersion version)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("Value cannot be null or empty.", nameof(path));

        if (!Enum.IsDefined(typeof(BinaryFormatVersion), version))
            throw new InvalidEnumArgumentException(nameof(version), (int)version,
                typeof(BinaryFormatVersion));

        using (var fileStream = File.OpenRead(path))
            return FromStream(fileStream, version);
    }

    public static Bm2Binary FromStream(Stream stream, bool leaveOpen = false)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        return FromStream(stream, BinaryFormatVersion.Unknown, leaveOpen);
    }

    public static Bm2Binary FromStream(Stream stream, BinaryFormatVersion version, bool leaveOpen = false)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        if (!Enum.IsDefined(typeof(BinaryFormatVersion), version))
            throw new InvalidEnumArgumentException(nameof(version), (int)version,
                typeof(BinaryFormatVersion));

        using (var reader = new Bm2BinaryReader(stream, version, leaveOpen))
        {
            return reader.ReadBinary();
        }
    }


    public Bm2Header Header { get; set; }
    public Bm2Header2 Header2 { get; set; }
    public List<Bm2Speaker> Speakers { get; set; }
    public List<Bm2Message> Messages { get; set; }
    public BinaryFormatVersion FormatVersion { get; set; }

    public int FileSize => (int)Header.FileSize;

    // Internal constructor for use by builder, reader, and writer
    internal Bm2Binary()
    {
    }

    public void ToFile(string path)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("Value cannot be null or empty.", nameof(path));

        using (var stream = File.Open(path, FileMode.Create, FileAccess.Write))
            ToStream(stream);
    }

    public Stream ToStream()
    {
        var stream = new MemoryStream();
        ToStream(stream, true);
        return stream;
    }

    public void ToStream(Stream stream, bool leaveOpen = false)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        using (var writer = new Bm2BinaryWriter(stream, FormatVersion, leaveOpen))
        {
            writer.WriteBinary(this);
        }
    }
}
