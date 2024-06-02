using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AtlusScriptLibrary.Common.Libraries.Serialization;

internal class ExternalJsonPathConverter : JsonConverterFactory
{
    private static JsonSerializerOptions _options = new JsonSerializerOptions { AllowTrailingCommas = true };

    public override bool CanConvert(Type typeToConvert)
    {
        if (!typeToConvert.IsGenericType) return false;

        return typeToConvert.GetGenericTypeDefinition() == typeof(List<>);
    }

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        Type elementType = typeToConvert.GetGenericArguments()[0];

        JsonConverter converter = (JsonConverter)Activator.CreateInstance(
            typeof(ListConverter<>).MakeGenericType(elementType),
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            new object[] {  },
            culture: null);

        return converter;
    }

    private class ListConverter<T> : JsonConverter<List<T>>
    {
        public override List<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var path = reader.GetString();
            if (string.IsNullOrEmpty(path))
                return null;

            var fullPath = Path.Combine(LibraryLookup.LibraryBaseDirectoryPath, path);
            var jsonString = File.ReadAllText(fullPath);
            var obj = JsonSerializer.Deserialize<List<T>>(jsonString, _options);

            return obj;

        }

        public override void Write(Utf8JsonWriter writer, List<T> value, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }
    }
}