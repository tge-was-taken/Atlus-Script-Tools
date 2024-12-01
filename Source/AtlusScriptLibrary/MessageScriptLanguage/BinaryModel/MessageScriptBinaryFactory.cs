using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

public static class MessageScriptBinaryFactory
{
    public static IMessageScriptBinary FromStream(Stream stream)
    {
        var sample = new byte[4];
        stream.Read(sample, 0, sample.Length);
        stream.Position = 0;
        if (sample.SequenceEqual(BinaryHeaderV2.MAGIC_BE) || sample.SequenceEqual(BinaryHeaderV2.MAGIC))
            return MessageScriptBinaryV2.FromStream(stream);
        else
            return MessageScriptBinary.FromStream(stream);
    }

    public static IMessageScriptBinary FromFile(string path)
    {
        using var stream = File.OpenRead(path);
        return FromStream(stream);
    }
}
