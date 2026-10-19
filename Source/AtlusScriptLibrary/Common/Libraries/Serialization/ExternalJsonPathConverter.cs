using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace AtlusScriptLibrary.Common.Libraries.Serialization;

/// <summary>
/// Reads a list whose JSON value is a path to the file actually holding it, resolved
/// relative to the library directory. Closed over the element type at the use site so
/// the list's metadata can come from the source generator.
/// </summary>
internal class ExternalJsonPathConverter<T> : JsonConverter<List<T>>
{
    public override List<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var path = reader.GetString();
        if (string.IsNullOrEmpty(path))
            return new List<T>();

        var fullPath = Path.Combine(LibraryLookup.LibraryBaseDirectoryPath, path);
        var jsonString = File.ReadAllText(fullPath);
        var typeInfo = (JsonTypeInfo<List<T>>)LibraryJsonContext.Default.GetTypeInfo(typeof(List<T>));
        return JsonSerializer.Deserialize(jsonString, typeInfo);
    }

    public override void Write(Utf8JsonWriter writer, List<T> value, JsonSerializerOptions options)
        => throw new NotImplementedException();
}
