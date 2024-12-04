using System;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

public enum BinaryDialogKind
{
    Message,
    Selection
}

public enum BinaryFormatVersion : uint
{
    Unknown = 1 << 0,
    Version1 = 1 << 1,
    Version1DDS = Version1 | 1 << 2,
    Version2 = 1 << 3,
    Version3 = 1 << 4,
    BigEndian = 1 << 30,
    UnknownBigEndian = Unknown | BigEndian,
    Version1BigEndian = Version1 | BigEndian,
    Version2BigEndian = Version2 | BigEndian,
    Version3BigEndian = Version3 | BigEndian,
}

public enum BinarySelectionDialogPattern : short
{
    Top = 0,
    Bottom = 1,
}
