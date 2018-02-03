namespace AtlusScriptLib.MessageScriptLanguage.BinaryModel
{
    public enum BinaryWindowType
    {
        Dialogue,
        Selection
    }

    public enum BinaryFormatVersion : uint
    {
        Unknown = 1 << 0,
        Version1 = 1 << 1,
        BigEndian = 1 << 15,
        Version1BigEndian = Version1 | BigEndian
    }
}
