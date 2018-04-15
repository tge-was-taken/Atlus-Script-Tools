using System;
using System.Reflection;
using AtlusScriptDocGen.Exceptions;
using AtlusScriptDocGen.Generators;
using AtlusScriptLibrary.Common.CLI;
using AtlusScriptLibrary.Common.Libraries;


namespace AtlusScriptDocGen
{
    internal static class Program
    {
        public static string Name { get; } = Assembly.GetExecutingAssembly().FullName;

        public static Version Version { get; } = Assembly.GetExecutingAssembly().GetName().Version;

        public static Library Library { get; set; }

        public static DocumentationFormat DocFormat { get; set; }

        public static string OutPath { get; set; }

        public static void Main( string[] args )
        {
#if DEBUG
            var generator = new NppLibraryDocumentationGenerator( LibraryLookup.GetLibrary( "p5" ) );
            generator.Generate( "FlowScript.xml" );
#else

            if ( !TryParseArgs( args ) )
                return;

            var generator = LibraryDocumentationGeneratorFactory.Create( Library, DocFormat );
            generator.Generate( OutPath );
#endif
        }

        /// <summary>
        /// Returns whether or not any exceptions occured while parsing args.
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        public static bool TryParseArgs( string[] args )
        {
            try
            {
                ParseArgs( args );
            }
            catch ( MissingArgumentValueException e )
            {
                Console.WriteLine( $"Specified argument -{e.ArgumentName} is missing a value for {e.MissingValueDescription}." );
                return false;
            }
            catch ( InvalidLibraryException e )
            {
                Console.WriteLine( $"Specified library '{e.LibraryName}' does not exist." );
                return false;
            }
            catch ( InvalidDocumentationFormatException e )
            {
                Console.WriteLine( $"Specified documentation format '{e.DocumentFormat}' is invalid or not yet implemented." );
                return false;
            }
#if !DEBUG
            catch ( Exception e )
            {
                Console.WriteLine( $"Unhandled exception occured:\n{e}" );
                return false;
            }
#endif

            return true;
        }

        public static void ParseArgs( string[] args )
        {
            var iterator = new ArgumentIterator( args );
            while ( iterator.HasNext )
            {
                var arg = iterator.Current;

                switch ( arg )
                {
                    case "-Library":
                        {
                            if ( !iterator.TryGetNextArg( out var libraryName ) )
                                throw new MissingArgumentValueException( "Library", "library name" );

                            Library = LibraryLookup.GetLibrary( libraryName );
                            if ( Library == null )
                                throw new InvalidLibraryException( libraryName );
                        }
                        break;

                    case "-DocFormat":
                        {
                            if ( !iterator.TryGetNextArg( out var docFormatStr ) )
                                throw new MissingArgumentValueException( "DocFormat", "documentation format name" );

                            if ( !Enum.TryParse< DocumentationFormat >( docFormatStr, out var docFormat ) )
                                throw new InvalidDocumentationFormatException( docFormatStr );

                            DocFormat = docFormat;
                        }
                        break;

                    case "-Out":
                        {
                            if ( !iterator.TryGetNextArg( out var outPath ) )
                                throw new MissingArgumentValueException( "Out", "out path" );

                            OutPath = outPath;
                        }
                        break;
                }
            }
        }
    }
}
