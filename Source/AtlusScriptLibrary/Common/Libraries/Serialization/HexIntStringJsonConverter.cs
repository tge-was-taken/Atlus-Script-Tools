using System;
using System.Globalization;
using Newtonsoft.Json;

namespace AtlusScriptLibrary.Common.Libraries.Serialization
{
    internal class HexIntStringJsonConverter : JsonConverter
    {
        public override bool CanConvert( Type objectType ) => false;

        public override bool CanWrite => false;

        public override object ReadJson( JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer )
        {
            var stringValue = ( string ) reader.Value;
            return int.Parse( stringValue.Substring( 2 ), NumberStyles.HexNumber );
        }

        public override void WriteJson( JsonWriter writer, object value, JsonSerializer serializer )
        {
            throw new NotImplementedException();
        }
    }
}