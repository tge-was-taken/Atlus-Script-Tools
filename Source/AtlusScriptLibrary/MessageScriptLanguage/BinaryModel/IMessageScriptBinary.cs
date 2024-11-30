using System.IO;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel
{
    public interface IMessageScriptBinary
    {
        BinaryFormatVersion FormatVersion { get; }

        int FileSize { get; }

        void ToFile(string path);
        Stream ToStream();
        void ToStream(Stream stream, bool leaveOpen = false);
    }
}