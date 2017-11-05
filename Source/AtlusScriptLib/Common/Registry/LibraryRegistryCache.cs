using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace AtlusScriptLib.Common.Registry
{
    public static class LibraryRegistryCache
    {
        internal static readonly string RegistryDirectoryPath = Path.Combine( AppDomain.CurrentDomain.BaseDirectory, "Library\\Registry" );
        private static readonly List<LibraryRegistry> sLibraryRegistries;
        private static readonly Dictionary< string, LibraryRegistry > sLibraryRegistriesByShortName;
        private static readonly Dictionary<string, LibraryRegistry> sLibraryRegistriesByFullName;

        public static IEnumerable<LibraryRegistry> LibraryRegistries
            => sLibraryRegistries;

        static LibraryRegistryCache()
        {
            sLibraryRegistries = new List< LibraryRegistry >();
            foreach ( var libraryRegistryJsonPath in Directory.EnumerateFiles( RegistryDirectoryPath, "*.json" ) )
            {
                var libraryRegistry = ParseLibraryRegistry( libraryRegistryJsonPath );
                sLibraryRegistries.Add( libraryRegistry );
            }

            sLibraryRegistriesByShortName = LibraryRegistries.ToDictionary( x => x.ShortName.ToLower() );
            sLibraryRegistriesByFullName = LibraryRegistries.ToDictionary( x => x.Name.ToLower() );
        }

        public static LibraryRegistry GetLibraryRegistry( string name )
        {
            var lowerName = name.ToLower();

            if ( sLibraryRegistriesByShortName.TryGetValue( lowerName, out var value ) )
                return value;

            if ( sLibraryRegistriesByFullName.TryGetValue( lowerName, out value ) )
                return value;

            return null;
        }

        private static LibraryRegistry ParseLibraryRegistry( string path )
        {
            string jsonText = File.ReadAllText( path );
            return JsonConvert.DeserializeObject< LibraryRegistry >( jsonText );
        }
    }
}
