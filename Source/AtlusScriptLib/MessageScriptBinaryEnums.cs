namespace AtlusScriptLib
{
    public enum MessageScriptBinaryMessageType : int
    {
        Dialogue,
        Selection
    }

    public enum MessageScriptBinaryFormatVersion
    {
        Unknown = 1 << 0,
        V1      = 1 << 1,
        BE      = 1 << 15,
        V1_BE   = V1 | BE,
    }
}
