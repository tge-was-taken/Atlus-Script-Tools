using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AtlusScriptLibrary.Common;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.FlowScriptLanguage.BinaryModel;
using AtlusScriptLibrary.MessageScriptLanguage;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;
using AtlusScriptLibrary.MessageScriptLanguage.Decompiler;
using BinaryHeader = AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.BinaryHeader;

namespace AtlusMessageScriptExtractor
{
    class Program
    {
        // version
        public static Version Version = Assembly.GetExecutingAssembly().GetName().Version;

        // parameters
        public static string DirectoryPath;

        public static string EncodingName;

        public static bool OutputFunctions;

        public static bool EnableBruteforceScanning;

        public static bool DisableScanAlignment;

        public static List<string> BruteforceExclusionList;

        public static List<string> BruteforceInclusionList;

        public static bool UseDecompiler;

        // other
        public static IndentedTextWriter Writer;

        public static Encoding Encoding;

        public static MessageScriptDecompiler Decompiler;

        static void DisplayUsage()
        {
            Console.WriteLine( $"AtlusMessageScriptExtractor {Version.Major}.{Version.Minor} by TGE (2017)" );
            Console.WriteLine();
            Console.WriteLine( "Usage info:" );
            Console.WriteLine( "Press S during brute force scanning to cancel. This will also allow you to add the file extension to the exclusion list." );
            Console.WriteLine();
            Console.WriteLine( "Argument info:");
            Console.WriteLine( "-path <path to directory>   If no path directive is provided, first parameter will be considered the directory path" );
            Console.WriteLine( "-enc <encoder string>       Determines which text encoding is used. If no enc directive is provided, non-ASCII code points will be output as hex values" );
            Console.WriteLine( "-func                       Enables the output of function codes. Disabled by default" );
            Console.WriteLine( "-scan                       Enables bruteforce scanning for message script data if file type is not detected (CAN BE VERY SLOW)");
            Console.WriteLine( "-noalign                    Disables 4 byte alignment for scanning. Not recommend unless you're sure the file contains text that doesn't get detected (ULTRA SLOW)" );
            Console.WriteLine( "-exclude [ext ext2..]       Excludes specified file extensions from brute force scanning.");
            Console.WriteLine( "-include [ext ext2..]       Includes specified file extensions from brute force scanning." );
            Console.WriteLine( "-dec                        Uses decompiler output instead of the regular output." );
            Console.WriteLine( "-usage                      Displays this message" );
            Console.WriteLine();
            Console.WriteLine( "Valid encodings:");
            Console.WriteLine( "sj                          Shift-JIS encoding. Used by Persona Q and others.");
            Console.WriteLine( "p3                          Persona 3's custom encoding");
            Console.WriteLine( "p4                          Persona 4's custom encoding");
            Console.WriteLine( "p5                          Persona 5's custom encoding");
            Console.WriteLine();
            Console.WriteLine( "Press any key to exit" );
            Console.ReadKey();
        }

        static void Main( string[] args )
        {
            if ( args.Length != 0 )
            {
                if ( ParseArguments( args ) )
                {
                    ExtractMessageScripts();
                }
                else
                {
                    DisplayUsage();
                }
            }
            else
            {
                Console.WriteLine("Error: No arguments specified.\n");
                DisplayUsage();
            }
        }

        static bool ParseArguments( string[] args )
        {
            for ( int i = 0; i < args.Length; i++ )
            {
                switch ( args[i] )
                {
                    case "-usage":
                        return false;

                    case "-path":
                        if ( i + 1 == args.Length )
                        {
                            Console.WriteLine( "Error: Missing argument for -path" );
                            return false;
                        }

                        DirectoryPath = args[++i];
                        break;

                    case "-enc":
                        if ( i + 1 == args.Length )
                        {
                            Console.WriteLine( "Error: Missing argument for -enc" );
                            return false;
                        }

                        EncodingName = args[++i].ToLowerInvariant();
                        if ( !Encodings.EncodingByName.TryGetValue( EncodingName, out Encoding ) )
                        {
                            Console.WriteLine("Error: Invalid encoding specified");
                            return false;
                        }
                        break;

                    case "-func":
                        OutputFunctions = true;
                        break;

                    case "-scan":
                        EnableBruteforceScanning = true;
                        break;

                    case "-noalign":
                        DisableScanAlignment = true;
                        break;

                    case "-exclude":
                        BruteforceExclusionList = new List<string>();
                        while ( true )
                        {
                            if ( i + 1 == args.Length )
                                break;

                            var ext = args[++i];
                            if ( ext[0] == '-' )
                            {
                                i--;
                                break;
                            }
                            if ( ext[0] != '.' )
                            {
                                ext = "." + ext;
                            }
                            else if ( ext[0] == '*' )
                            {
                                ext = ext.Substring( 1 );
                            }

                            BruteforceExclusionList.Add( ext );
                        }
                        break;

                    case "-include":
                        BruteforceInclusionList = new List<string>();
                        while ( true )
                        {
                            if ( i + 1 == args.Length )
                                break;

                            var ext = args[++i];
                            if ( ext[0] == '-' )
                            {
                                i--;
                                break;
                            }
                            if ( ext[0] != '.' )
                            {
                                ext = "." + ext;
                            }
                            else if ( ext[0] == '*' )
                            {
                                ext = ext.Substring( 1 );
                            }

                            BruteforceInclusionList.Add( ext );
                        }
                        break;

                    case "-dec":
                        UseDecompiler = true;
                        break;
                }
            }

            if ( DirectoryPath == null )
            {
                DirectoryPath = args[0];
            }

            if ( !Directory.Exists(DirectoryPath) )
            {
                Console.WriteLine("Error: Specified directory doesn't exist");
                return false;
            }

            return true;
        }

        static void ExtractMessageScripts()
        {
            using ( Writer = new IndentedTextWriter( FileUtils.CreateText( $".\\MessageScriptDump.txt" ) ) )
            {
                if ( UseDecompiler )
                {
                    Decompiler = new MessageScriptDecompiler( Writer );
                }

                foreach ( var file in Directory.EnumerateFiles( DirectoryPath, "*.*", SearchOption.AllDirectories ) )
                {
#if !DEBUG
                    try
#endif
                    {
                        ExtractMessageScript( file, File.OpenRead( file ), null );
                    }
#if !DEBUG
                    catch ( Exception e )
                    {
                        Console.WriteLine( $"File \"{file}\" threw exception: {e.Message}" );
                    }
#endif
                }

                Writer.Flush();
            }

            Console.WriteLine( "Done." );
            //Console.ReadKey();
        }

        static void ExtractMessageScript( string file, Stream stream, string parentArchiveFile )
        {
            string prettyFileName;
            if ( parentArchiveFile == null )
                prettyFileName = file.Remove( 0, DirectoryPath.Length );
            else
                prettyFileName = Path.Combine( parentArchiveFile, file );

            // print some useful info
            if ( parentArchiveFile == null )
                Console.WriteLine( $"Processing file: {prettyFileName}" );
            else
                Console.WriteLine( $"Processing archive file: {prettyFileName}" );

            // extract script
            MessageScript script = null;
            string fileExtension = Path.GetExtension( file );

            // Check if it is a plain message script file
            if ( fileExtension.Equals( ".bmd", StringComparison.InvariantCultureIgnoreCase ) )
            {
                script = MessageScript.FromStream( stream, FormatVersion.Detect, Encoding, true );
            }
            // Check if it is a flow script file that can maybe contain a message script
            else if ( fileExtension.Equals( ".bf", StringComparison.InvariantCultureIgnoreCase ) )
            {
                var flowScriptBinary = FlowScriptBinary.FromStream( stream, true );
                if ( flowScriptBinary.MessageScriptSection != null )
                {
                    script = MessageScript.FromBinary( flowScriptBinary.MessageScriptSection, FormatVersion.Detect, Encoding );
                }
                else
                {
                    return;
                }
            }

            if ( script != null )
            {
                // We have found a script, yay!
                Console.WriteLine("Writing message script to file...");
                if ( UseDecompiler )
                    WriteMessageScriptWithDecompiler( prettyFileName, script );
                else
                    WriteMessageScript( prettyFileName, script );
            }
            else
            {
                // Try to open the file as an archive
                
                if ( !Archive.TryOpenArchive( stream, out var archive ) )
                {
                    // If we can't open the file as an archive, try brute force scanning if it is enabled
                    if ( EnableBruteforceScanning &&
                       ( BruteforceExclusionList == null || BruteforceExclusionList != null && !BruteforceExclusionList.Any( x => x.Equals( fileExtension, StringComparison.InvariantCultureIgnoreCase ) ) ) &&
                       ( BruteforceInclusionList == null || BruteforceInclusionList != null && BruteforceInclusionList.Any( x => x.Equals( fileExtension, StringComparison.InvariantCultureIgnoreCase ) ) ) 
                       )
                    {
                        Console.WriteLine( $"Bruteforce scanning..." );

                        var scanCancel = new CancellationTokenSource();
                        var scanTask = Task.Factory.StartNew( () => ScanForMessageScripts( prettyFileName, stream, scanCancel.Token ) );

                        while ( !scanTask.IsCompleted )
                        {
                            // Don't want to block, so wait for key to be available
                            if ( Console.KeyAvailable )
                            {
                                // Blocking is fine after this point
                                var key = Console.ReadKey( true );
                                
                                if ( key.Key == ConsoleKey.S )
                                {
                                    Console.WriteLine( "Do you want to skip scanning this file? Y/N" );
                                    if ( Console.ReadKey( true ).Key == ConsoleKey.Y )
                                    {
                                        scanCancel.Cancel();

                                        Console.WriteLine( "Do you want to add this file extension to the list of excluded files? Y/N" );
                                        if ( Console.ReadKey( true ).Key == ConsoleKey.Y )
                                        {
                                            if ( BruteforceExclusionList == null )
                                                BruteforceExclusionList = new List<string>();

                                            BruteforceExclusionList.Add( Path.GetExtension( prettyFileName ) );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    foreach ( var entry in archive )
                    {
                        ExtractMessageScript( entry, archive.OpenFile(entry), prettyFileName );
                    }
                }
            }
        }

        static void ScanForMessageScripts( string prettyFileName, Stream stream, CancellationToken cancellationToken )
        {
            byte[] magic = new byte[4];

            while ( stream.Position <= stream.Length )
            {
                if ( cancellationToken.IsCancellationRequested )
                {
                    break;
                }

                if ( stream.Position + BinaryHeader.SIZE < stream.Length )
                {
                    // Read 4 bytes
                    magic[0] = ( byte )stream.ReadByte();
                    magic[1] = ( byte )stream.ReadByte();
                    magic[2] = ( byte )stream.ReadByte();
                    magic[3] = ( byte )stream.ReadByte();

                    if ( magic.SequenceEqual( BinaryHeader.MAGIC_V0 ) ||
                        magic.SequenceEqual( BinaryHeader.MAGIC_V1 ) ||
                        magic.SequenceEqual( BinaryHeader.MAGIC_V1_BE ) )
                    {
                        long scriptStartPosition = stream.Position - 12;
                        var scriptBinary = MessageScriptBinary.FromStream( new StreamView( stream, scriptStartPosition, stream.Length - scriptStartPosition ) );
                        var script = MessageScript.FromBinary( scriptBinary );

                        Console.WriteLine( $"Found message script at 0x{scriptStartPosition:X8}. Writing to file..." );

                        if ( UseDecompiler )
                            WriteMessageScriptWithDecompiler( $"{prettyFileName} @ 0x{scriptStartPosition:X8}", script );
                        else
                            WriteMessageScript( $"{prettyFileName} @ 0x{scriptStartPosition:X8}", script );

                        stream.Position = scriptStartPosition + scriptBinary.Header.FileSize;
                    }
                    else if ( DisableScanAlignment )
                    {
                        // Scan alignment is disabled, so we make sure to retry every byte
                        // 4 steps forward, 3 steps back
                        stream.Position -= 3;
                    }
                }
                else
                {
                    break;
                }
            }
        }

        static void WriteMessageScript( string name, MessageScript script )
        {
            Writer.WriteLine( name );

            for ( var i = 0; i < script.Dialogs.Count; i++ )
            {
                var window = script.Dialogs[ i ];
                Writer.WriteLine( $"Id: {i}" );
                WriteWindow( window );
            }

            Writer.WriteLine();
        }

        static void WriteMessageScriptWithDecompiler( string name, MessageScript script )
        {
            Writer.WriteLine( name );

            Decompiler.Decompile( script );

            Writer.WriteLine();
            Writer.Flush();
        }

        static void WriteWindow( IDialog window )
        {
            Writer.WriteLine( window.Name );

            if ( window.Kind == DialogKind.Message )
            {
                WriteDialogWindowSpeaker( ( MessageDialog )window );
            }

            foreach ( var line in window.Lines )
            {
                WriteLine( line );
            }

            Writer.Indent--;
            Writer.WriteLine();
        }

        static void WriteDialogWindowSpeaker( MessageDialog window )
        {
            if ( window.Speaker != null )
            {
                if ( window.Speaker.Kind == SpeakerKind.Named )
                {
                    WriteLine( ( ( NamedSpeaker )window.Speaker ).Name, false );
                }
                else if ( window.Speaker.Kind == SpeakerKind.Variable )
                {
                    Writer.Write( $"var({( ( VariableSpeaker )window.Speaker ).Index})" );
                }

                Writer.WriteLine( ":" );
                Writer.Indent++;
            }
        }

        static void WriteLine( TokenText line, bool writeNewLine = true )
        {
            if ( line == null )
                return;

            foreach ( var token in line.Tokens )
            {
                WriteToken( token );
            }

            // write newline if the line doesn't contain any
            if ( writeNewLine && ( !line.Tokens.Any( x => x.Kind == TokenKind.NewLine ) || ( OutputFunctions && line.Tokens.Last().Kind == TokenKind.Function ) ) )
            {
                Writer.WriteLine();
            }
        }

        static void WriteToken( IToken token )
        {
            if ( token.Kind == TokenKind.CodePoint )
            {
                WriteCodePointToken( ( CodePointToken )token );
            }
            else if ( token.Kind == TokenKind.NewLine )
            {
                Writer.WriteLine();
            }
            else if ( token.Kind == TokenKind.String )
            {
                WriteTextToken( ( StringToken )token );
            }
            else if ( token.Kind == TokenKind.Function && OutputFunctions )
            {
                WriteFunctionToken( ( FunctionToken )token );
            }
        }

        static void WriteCodePointToken( CodePointToken token )
        {
            string str = null;

            if ( Encoding != null )
            {
                str = Encoding.GetString( new[] { token.HighSurrogate, token.LowSurrogate } );

                // check if it's a glyph with no equivalent
                if ( str == "\0" )
                {
                    str = null;
                }
            }

            if ( str == null )
            {
                str = $"[{token.HighSurrogate:X2} {token.LowSurrogate:X2}]";
            }

            Writer.Write( str );
        }

        static void WriteTextToken( StringToken token )
        {
            Writer.Write( token.Value );
        }

        static void WriteFunctionToken( FunctionToken token )
        {
            Writer.Write( $"[F {token.FunctionTableIndex} {token.FunctionIndex}]" );
        }
    }
}
