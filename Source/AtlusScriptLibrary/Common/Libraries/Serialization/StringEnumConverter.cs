using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries.Serialization;

/// <summary>
/// Reads an enum from its case-insensitive name, treating a missing or empty value as 0.
/// Closed over the enum type at the use site so no runtime type construction is needed.
/// </summary>
internal class StringEnumConverter<T> : JsonConverter<T> where T : struct, Enum
{
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (string.IsNullOrEmpty(value))
            return default;

#if NETSTANDARD2_0
        return (T)Enum.Parse(typeof(T), value, ignoreCase: true);
#else
        return Enum.Parse<T>(value, ignoreCase: true);
#endif
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToString());
}
