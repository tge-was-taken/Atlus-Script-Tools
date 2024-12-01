using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.Text.Encodings;

public abstract class CatherineEncodingBase : CustomUnicodeEncoding
{
    protected readonly static Dictionary<ushort, char> _codeToChar = new()
    {
        { 0xFFE3, ' ' }
    };

    protected CatherineEncodingBase(bool isBigEndian)
        : base(isBigEndian, _codeToChar) { }

    public override CustomUnicodeEncoding GetEncodingForEndianness(bool isBigEndian)
        => isBigEndian ? CatherineBigEndianEncoding.Instance : CatherineEncoding.Instance;
}

public class CatherineBigEndianEncoding : CatherineEncodingBase
{
    public static CatherineBigEndianEncoding Instance { get; } = new();
    private CatherineBigEndianEncoding() : base(true) { }
}

public class CatherineEncoding : CatherineEncodingBase
{
    public static CatherineEncoding Instance { get; } = new();
    private CatherineEncoding() : base(false) { }
}

public abstract class CatherineFullBodyEncodingBase : CustomUnicodeEncoding
{
    protected readonly static Dictionary<ushort, char> _codeToChar = new()
    {
    };

    protected CatherineFullBodyEncodingBase(bool isBigEndian)
        : base(isBigEndian, _codeToChar) { }

    public override CustomUnicodeEncoding GetEncodingForEndianness(bool isBigEndian)
        => isBigEndian ? CatherineFullBodyBigEndianEncoding.Instance : CatherineFullBodyEncoding.Instance;
}

public class CatherineFullBodyEncoding : CatherineFullBodyEncodingBase
{
    public static CatherineFullBodyEncoding Instance { get; } = new();
    private CatherineFullBodyEncoding() : base(false) { }
}

public class CatherineFullBodyBigEndianEncoding : CatherineFullBodyEncodingBase
{
    public static CatherineFullBodyBigEndianEncoding Instance { get; } = new();
    private CatherineFullBodyBigEndianEncoding() : base(true) { }
}
