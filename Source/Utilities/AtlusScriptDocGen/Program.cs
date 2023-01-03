using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using AtlusScriptDocGen.Exceptions;
using AtlusScriptDocGen.Generators;
using AtlusScriptLibrary.Common.CLI;
using AtlusScriptLibrary.Common.Libraries;

namespace AtlusScriptDocGen
{
    internal static class Program
    {
        private static Library sLibrary;
        private static DocumentationFormat sDocFormat;
        private static string sOutPath;

        private static readonly Dictionary<string, DocumentationFormat> sDocFormatLookup = new Dictionary<string, DocumentationFormat>()
        {
            { "npp", DocumentationFormat.Npp },
            { "010", DocumentationFormat.SweetScape010Editor }
        };

        public static string Name { get; } = Assembly.GetExecutingAssembly().GetName().Name;

        public static Version Version { get; } = Assembly.GetExecutingAssembly().GetName().Version;

        public static string FullName { get; } = $"{Name} {Version.Major}.{Version.Minor}";

        private static readonly string sUsage = $@"
{FullName} by TGE
Usage:
{Name}.exe <-Library library_name> <-DocFormat doc_format> [-Out out_path]

Supported libraries:
    - See documentation AtlusScriptCompiler

Supported documentation formats:
    - npp       Notepad++ auto complete information
    - 010       SweetScape 010 hex editor binary template enum definitions";

        public static void Main( string[] args )
        {
#if DEBUG
            var generator = new SweetScape010EditorEnumGenerator( LibraryLookup.GetLibrary( "p5" ) );
            generator.Generate( "P5_Enums.bt" );
#else

            if ( !TryParseArgs( args ) )
            {
                Console.WriteLine( sUsage );
                return;
            }

            var generator = LibraryDocumentationGeneratorFactory.Create( sLibrary, sDocFormat );
            generator.Generate( sOutPath );
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
                            if ( !iterator.TryGetNextArgument( out var libraryName ) )
                                throw new MissingArgumentValueException( "Library", "library name" );

                            sLibrary = LibraryLookup.GetLibrary( libraryName );
                            if ( sLibrary == null )
                                throw new InvalidLibraryException( libraryName );
                        }
                        break;

                    case "-DocFormat":
                        {
                            if ( !iterator.TryGetNextArgument( out var docFormatStr ) )
                                throw new MissingArgumentValueException( "DocFormat", "documentation format name" );

                            if ( !Enum.TryParse< DocumentationFormat >( docFormatStr, out var docFormat ) && !sDocFormatLookup.TryGetValue( docFormatStr, out docFormat ) )
                                throw new InvalidDocumentationFormatException( docFormatStr );

                            sDocFormat = docFormat;
                        }
                        break;

                    case "-Out":
                        {
                            if ( !iterator.TryGetNextArgument( out var outPath ) )
                                throw new MissingArgumentValueException( "Out", "out path" );

                            sOutPath = outPath;
                        }
                        break;
                }
                iterator.MoveNext();
            }

            if ( sLibrary == null )
                throw new MissingMandatoryArgumentException( "Library" );

            if ( sDocFormat == DocumentationFormat.Unknown )
                throw new MissingMandatoryArgumentException( "DocFormat" );

            if (sOutPath == null)
                sOutPath = Path.Combine(Environment.CurrentDirectory, sLibrary.ShortName + (sDocFormat == DocumentationFormat.SweetScape010Editor ? ".bt" : ".xml"));
        }
    }
}
