using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AtlusScriptLib.Common.Registry
{
    public class LibraryRegistry
    {
        public string Name { get; set; }

        public string ShortName { get; set; }

        [JsonProperty( "FlowScriptLibraryRegistryPath")]
        [JsonConverter( typeof( ExternalJsonPathConverter) )]
        public List<FlowScriptLibrary> FlowScriptLibraries { get; set; }

        [JsonProperty( "MessageScriptLibraryPath" )]
        [JsonConverter( typeof(ExternalJsonPathConverter) ) ]
        public List<MessageScriptLibrary> MessageScriptLibraries { get; set; }
    }

    class ExternalJsonPathConverter : JsonConverter
    {
        public override bool CanConvert( Type objectType )
        {
            return false;
        }

        public override object ReadJson( JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer )
        {
            var path = ( string ) reader.Value;
            if ( string.IsNullOrEmpty( path ) )
                return null;

            var fullPath = Path.Combine( LibraryRegistryManager.RegistryDirectoryPath, path );
            var jsonString = File.ReadAllText( fullPath );
            var obj = JsonConvert.DeserializeObject( jsonString, objectType );

            return obj;
        }

        public override void WriteJson( JsonWriter writer, object value, JsonSerializer serializer )
        {
            throw new NotImplementedException();
        }
    }

    class HexIntStringJsonConverter : JsonConverter
    {
        public override bool CanConvert( Type objectType )
        {
            return false;
        }

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