using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace AtlusScriptLib.Common.Registry
{
    public static class LibraryRegistryManager
    {
        public static readonly string RegistryDirectoryPath = Path.Combine( AppDomain.CurrentDomain.BaseDirectory, "Library\\Registry" );

        public static IReadOnlyList< LibraryRegistry > LibraryRegistries;

        public static Dictionary< string, LibraryRegistry > LibraryRegistriesByShortName;

        static LibraryRegistryManager()
        {
            var libraryRegistries = new List< LibraryRegistry >();

            foreach ( var libraryRegistryJsonPath in EnumerateLibraryRegistryJsons() )
            {
                var libraryRegistry = ParseLibraryRegistry( libraryRegistryJsonPath );
                libraryRegistries.Add( libraryRegistry );
            }

            LibraryRegistries = libraryRegistries.AsReadOnly();
            LibraryRegistriesByShortName = LibraryRegistries.ToDictionary( x => x.ShortName );
        }

        private static LibraryRegistry ParseLibraryRegistry( string path )
        {
            string jsonText = File.ReadAllText( path );
            return JsonConvert.DeserializeObject< LibraryRegistry >( jsonText );
        }

        private static IEnumerable< string > EnumerateLibraryRegistryJsons()
        {
            foreach ( var file in Directory.EnumerateFiles( RegistryDirectoryPath, "*.json" ) )
            {
                yield return file;
            }
        }
    }
}
