using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace AtlusScriptLibrary.Common.Libraries.Serialization
{
    internal class CustomStringEnumConverter : StringEnumConverter
    {
        public override object ReadJson( JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer )
        {
            if ( string.IsNullOrEmpty( reader.Value.ToString() ) )
                return Enum.ToObject( objectType, 0 );

            return base.ReadJson( reader, objectType, existingValue, serializer );
        }
    }
}