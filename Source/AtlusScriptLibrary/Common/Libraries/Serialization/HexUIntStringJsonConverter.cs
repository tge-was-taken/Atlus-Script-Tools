using System;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries.Serialization;

internal class HexUIntStringJsonConverter : JsonConverter<uint>
{
    public override uint Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var stringValue = reader.GetString();
        return uint.Parse(stringValue.Substring(2), NumberStyles.HexNumber);
    }

    public override void Write(Utf8JsonWriter writer, uint value, JsonSerializerOptions options)
    {
        writer.WriteStringValue($"0x{value:X}");
    }
}

internal class HexULongStringJsonConverter : JsonConverter<ulong>
{
    public override ulong Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var stringValue = reader.GetString();
        return ulong.Parse(stringValue.Substring(2), NumberStyles.HexNumber);
    }

    public override void Write(Utf8JsonWriter writer, ulong value, JsonSerializerOptions options)
    {
        writer.WriteStringValue($"0x{value:X}");
    }
}