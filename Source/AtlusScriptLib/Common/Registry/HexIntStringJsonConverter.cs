using System;
using Newtonsoft.Json;

namespace AtlusScriptLib.Common.Registry
{
    internal class HexIntStringJsonConverter : JsonConverter
    {
        public override bool CanConvert( Type objectType ) => false;

        public override bool CanWrite => false;

        public override object ReadJson( JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer )
        {
            var stringValue = ( string ) reader.Value;
            return int.Parse( stringValue.Substring( 2 ), System.Globalization.NumberStyles.HexNumber );
        }

        public override void WriteJson( JsonWriter writer, object value, JsonSerializer serializer )
        {
            throw new NotImplementedException();
        }
    }
}