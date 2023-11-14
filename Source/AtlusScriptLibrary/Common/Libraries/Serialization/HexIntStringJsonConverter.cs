using System;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries.Serialization;

internal class HexIntStringJsonConverter : JsonConverter<int>
{
    public override int Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var stringValue = reader.GetString();
        return int.Parse(stringValue.Substring(2), NumberStyles.HexNumber);
    }

    public override void Write(Utf8JsonWriter writer, int value, JsonSerializerOptions options)
    {
        writer.WriteStringValue($"0x{value:X}");
    }
}