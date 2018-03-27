using System.IO;

namespace AtlusScriptLibrary.Common.IO
{
    public static class FileUtils
    {
        public static FileStream Create( string path )
        {
            CreateDirectoryIfNecessary( path );
            return File.Create( path );
        }

        public static StreamWriter CreateText( string path )
        {
            CreateDirectoryIfNecessary( path );
            return File.CreateText( path );
        }

        public static void WriteAllBytes( string path, byte[] bytes )
        {
            CreateDirectoryIfNecessary( path );
            File.WriteAllBytes( path, bytes );
        }    

        private static void CreateDirectoryIfNecessary( string path )
        {
            var directory = Path.GetDirectoryName( path );
            if ( !string.IsNullOrWhiteSpace( directory ) )
                Directory.CreateDirectory( directory );
        }
    }
}
