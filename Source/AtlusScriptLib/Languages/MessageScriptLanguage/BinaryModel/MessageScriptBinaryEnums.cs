namespace AtlusScriptLib.MessageScriptLanguage.BinaryModel
{
    public enum MessageScriptBinaryWindowType : int
    {
        Dialogue,
        Selection
    }

    public enum MessageScriptBinaryFormatVersion : uint
    {
        Unknown = 1 << 0,
        Version1 = 1 << 1,
        BigEndian = 1 << 15,
        Version1BigEndian = Version1 | BigEndian,
    }
}
