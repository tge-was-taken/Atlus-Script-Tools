using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V1;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V2;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.V3;
using System.IO;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

public static class MessageScriptBinaryFactory
{
    public static IMessageScriptBinary FromStream(Stream stream)
    {
        if (Bm2Binary.IsValidStream(stream))
            return Bm2Binary.FromStream(stream);
        if (MessageScriptBinaryV2.IsValidStream(stream))
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
