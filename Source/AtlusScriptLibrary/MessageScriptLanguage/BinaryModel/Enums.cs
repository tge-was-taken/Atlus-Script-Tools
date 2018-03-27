namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel
{
    public enum BinaryDialogKind
    {
        Message,
        Selection
    }

    public enum BinaryFormatVersion : uint
    {
        Unknown = 1 << 0,
        Version1 = 1 << 1,
        Version1DDS = 1 << 2,
        BigEndian = 1 << 15,
        Version1BigEndian = Version1 | BigEndian
    }
}
