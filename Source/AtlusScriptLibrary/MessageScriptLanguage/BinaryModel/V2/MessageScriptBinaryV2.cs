using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2.IO;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2;

public class MessageScriptBinaryV2 : IMessageScriptBinary
{
    public static bool IsValidStream(Stream stream)
    {
        var magic = new byte[4];
        stream.Read(magic, 0, magic.Length);
        stream.Position = 0;
        return magic.SequenceEqual(BinaryHeaderV2.MAGIC_BE) || magic.SequenceEqual(BinaryHeaderV2.MAGIC);
    }

    public static MessageScriptBinaryV2 FromFile(string path)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("Value cannot be null or empty.", nameof(path));

        return FromFile(path, BinaryFormatVersion.Unknown);
    }

    public static MessageScriptBinaryV2 FromFile(string path, BinaryFormatVersion version)
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

    public static MessageScriptBinaryV2 FromStream(Stream stream, bool leaveOpen = false)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        return FromStream(stream, BinaryFormatVersion.Version2, leaveOpen);
    }

    public static MessageScriptBinaryV2 FromStream(Stream stream, BinaryFormatVersion version, bool leaveOpen = false)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        if (!Enum.IsDefined(typeof(BinaryFormatVersion), version))
            throw new InvalidEnumArgumentException(nameof(version), (int)version,
                typeof(BinaryFormatVersion));

        using (var reader = new MessageScriptBinaryV2Reader(stream, version, leaveOpen))
        {
            return reader.ReadBinary();
        }
    }

    // internal fields for use by builder, reader, and writer
    internal BinaryHeaderV2 mHeader;
    internal BinaryHeader2 mHeader2;
    internal BinaryFormatVersion mFormatVersion;

    public BinaryHeaderV2 Header => mHeader;

    public BinaryHeader2 Header2 => mHeader2;

    public BinaryFormatVersion FormatVersion => mFormatVersion;

    public int FileSize => (int)Header.FileSize;

    // internal constructor for use by builder, reader, and writer
    internal MessageScriptBinaryV2()
    {
    }

    public void ToFile(string path)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("Value cannot be null or empty.", nameof(path));

        using (var stream = FileUtils.Create(path))
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
        using (var writer = new MessageScriptBinaryV2Writer(stream, mFormatVersion, leaveOpen))
        {
            writer.WriteBinary(this);
        }
    }
}
