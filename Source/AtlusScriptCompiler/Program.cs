using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.Common.Text.Encodings;
using AtlusScriptLib.Common.Text.OutputProviders;
using AtlusScriptLib.FlowScriptLanguage.BinaryModel;
using AtlusScriptLib.FlowScriptLanguage.Disassembler;
using AtlusScriptLib.MessageScriptLanguage;
using AtlusScriptLib.MessageScriptLanguage.Compiler;
using AtlusScriptLib.MessageScriptLanguage.Decompiler;

namespace AtlusScriptCompiler
{
    internal class Program
    {
        public static Version Version = Assembly.GetExecutingAssembly().GetName().Version;

        public static Logger Logger = new Logger(nameof(AtlusScriptCompiler));

        public static LogListener Listener = new ConsoleLogListener( true );

        public static string InputFilePath;

        public static string OutputFilePath;

        public static bool IsActionAssigned;

        public static bool DoCompile;

        public static bool DoDecompile;

        public static bool DoDisassemble;

        public static InputFileFormat InputFileFormat;

        public static OutputFileFormat OutputFileFormat;

        public static OutputTextEncoding OutputTextEncoding;

        private static void DisplayUsage()
        {
            Console.WriteLine( $"AtlusScriptCompiler {Version.Major}.{Version.Minor} by TGE (2017)" );
            Console.WriteLine( "" );
            Console.WriteLine( "Argument info:" );
            Console.WriteLine( "    -i <path to file>       Provides an input file source to the compiler. If no input source is explicitly specified, the first argument will be assumed to be one." );
            Console.WriteLine( "    -o <path to file>       Provides an output file path to the compiler. If no output source is explicitly specified, the file will be output in the same folder as the source file under a different extension." );
            Console.WriteLine( "    -com                    Instructs the compiler to compile the provided input file source." );
            Console.WriteLine( "    -dec                    Instructs the compiler to decompile the provided input file source." );
            Console.WriteLine( "    -dis                    Instructs the compiler to disassemble the provided input file source." );
            Console.WriteLine( "    -infmt <format string>  Specifies the input file source format. By default this is guessed by the file extension." );
            Console.WriteLine( "    -outfmt <format string> Specifies the output file format. See below for further info." );
            Console.WriteLine( "    -outenc <format string> Specifies the output text encoding. See below for further info." );
            Console.WriteLine( "" );
            Console.WriteLine( "Parameter detailed info:" );
            Console.WriteLine( "    -outfmt" );
            Console.WriteLine( "" );
            Console.WriteLine( "        MessageScript formats:" );
            Console.WriteLine( "            v1              Used by Persona 3, 4, 5 PS4" );
            Console.WriteLine( "            v1be            Used by Persona 5 PS3" );
            Console.WriteLine( "" );
            Console.WriteLine( "         FlowScript formats:" );
            Console.WriteLine( "            v1              Used by Persona 3 and 4" );
            Console.WriteLine( "            v1be            " );
            Console.WriteLine( "            v2              Used by Persona 4 Dancing All Night" );
            Console.WriteLine( "            v2be            " );
            Console.WriteLine( "            v3              Used by Persona 5 PS4" );
            Console.WriteLine( "            v3be            Used by Persona 5 PS3" );
            Console.WriteLine();
            Console.WriteLine( "    -outenc" );
            Console.WriteLine( "        Below is a list of different available encodings.");
            Console.WriteLine( "        Note that ASCII characters don't really differ from the standard, so this mostly applies to special characters and japanese characters.");
            Console.WriteLine();
            Console.WriteLine( "        sj                  Shift-Jis encoding (CP932). Used by Persona Q" );
            Console.WriteLine( "        p3                  Persona 3's custom encoding" );
            Console.WriteLine( "        p4                  Persona 4's custom encoding" );
            Console.WriteLine( "        p5                  Persona 5's custom encoding" );
            Console.ReadKey();
        }

        public static void Main( string[] args )
        {
            // set up log listener
            Listener.Subscribe( Logger );

            if ( args.Length == 0 )
            {
                Logger.Error( "No arguments specified!" );
                DisplayUsage();
                return;
            }

            if ( !TryParseArguments( args ) )
            {
                Logger.Error( "Failed to parse arguments!" );
                DisplayUsage();
                return;
            }

            bool success;

            if ( DoCompile )
            {
                success = TryDoCompilation();
            }
            else if ( DoDecompile )
            {
                success = TryDoDecompilation();
            }
            else if ( DoDisassemble )
            {
                success = TryDoDisassembling();
            }
            else
            {
                Logger.Error( "No compilation, decompilation or disassemble instruction given!" );
                DisplayUsage();
                return;
            }

            if ( success )
                Logger.Info( "Task completed successfully!" );
            else
                Logger.Error( "One or more errors occured while executing task!" );

            Logger.Info( "Press any key to continue" );
            Console.ReadKey();
        }

        private static bool TryParseArguments( string[] args )
        {
            for ( int i = 0; i < args.Length; i++ )
            {
                switch ( args[i] )
                {
                    case "-i":
                        if ( i + 1 == args.Length )
                        {
                            Logger.Error( "Missing argument for -i parameter" );
                            return false;
                        }

                        InputFilePath = args[++i];
                        break;

                    case "-o":
                        if ( i + 1 == args.Length )
                        {
                            Logger.Error( "Missing argument for -o parameter" );
                            return false;
                        }

                        OutputFilePath = args[++i];
                        break;

                    case "-com":
                        if ( !IsActionAssigned )
                        {
                            IsActionAssigned = true;
                        }
                        else
                        {
                            Logger.Error( "Attempted to assign compilation action while another action is already assigned." );
                            return false;
                        }

                        DoCompile = true;
                        break;

                    case "-dec":
                        if ( !IsActionAssigned )
                        {
                            IsActionAssigned = true;
                        }
                        else
                        {
                            Logger.Error( "Attempted to assign decompilation action while another action is already assigned." );
                            return false;
                        }

                        DoDecompile = true;
                        break;

                    case "-dis":
                        if ( !IsActionAssigned )
                        {
                            IsActionAssigned = true;
                        }
                        else
                        {
                            Logger.Error( "Attempted to assign disassembly action while another action is already assigned." );
                            return false;
                        }

                        DoDisassemble = true;
                        break;

                    case "-infmt":
                        if ( i + 1 == args.Length )
                        {
                            Logger.Error( "Missing argument for -infmt parameter" );
                            return false;
                        }

                        if ( !Enum.TryParse( args[++i], true, out InputFileFormat ) )
                        {
                            Logger.Error( "Invalid input file format specified" );
                            return false;
                        }

                        break;

                    case "-outfmt":
                        if ( i + 1 == args.Length )
                        {
                            Logger.Error( "Missing argument for -outfmt parameter" );
                            return false;
                        }

                        if ( !Enum.TryParse( args[++i], true, out OutputFileFormat ) )
                        {
                            Logger.Error( "Invalid output file format specified" );
                            return false;
                        }

                        break;

                    case "-outenc":
                        if ( i + 1 == args.Length )
                        {
                            Logger.Error( "Missing argument for -outenc parameter" );
                            return false;
                        }

                        if ( !Enum.TryParse( args[++i], true, out OutputTextEncoding ) )
                        {
                            Logger.Error( "Invalid output file encoding specified" );
                            return false;
                        }

                        Logger.Info( $"Using {OutputTextEncoding} encoding" );

                        break;
                }
            }

            if ( InputFilePath == null )
            {
                InputFilePath = args[0];
            }

            if ( !File.Exists(InputFilePath) )
            {
                Logger.Error( $"Specified input file doesn't exist! ({InputFilePath})" );
                return false;
            }

            if ( InputFileFormat == InputFileFormat.None )
            {
                var extension = Path.GetExtension( InputFilePath );

                switch ( extension.ToLowerInvariant() )
                {
                    case ".bf":
                        InputFileFormat = InputFileFormat.FlowScriptBinary;
                        break;

                    case ".flow":
                        InputFileFormat = InputFileFormat.FlowScriptTextSource;
                        break;

                    case ".flowasm":
                        InputFileFormat = InputFileFormat.FlowScriptAssemblerSource;
                        break;

                    case ".bmd":
                        InputFileFormat = InputFileFormat.MessageScriptBinary;
                        break;

                    case ".msg":
                        InputFileFormat = InputFileFormat.MessageScriptTextSource;
                        break;

                    default:
                        Logger.Error( "Unable to detect input file format" );
                        return false;
                }
            }

            if ( OutputFilePath == null )
            {
                if ( DoCompile )
                {
                    switch ( InputFileFormat )
                    {
                        case InputFileFormat.FlowScriptTextSource:
                        case InputFileFormat.FlowScriptAssemblerSource:
                            OutputFilePath = InputFilePath + ".bf";
                            break;
                        case InputFileFormat.MessageScriptTextSource:
                            OutputFilePath = InputFilePath + ".bmd";
                            break;
                    }
                }
                else if ( DoDecompile )
                {
                    switch ( InputFileFormat )
                    {
                        case InputFileFormat.FlowScriptBinary:
                            OutputFilePath = InputFilePath + ".flow";
                            break;
                        case InputFileFormat.MessageScriptBinary:
                            OutputFilePath = InputFilePath + ".msg";
                            break;
                    }
                }
                else if ( DoDisassemble )
                {
                    switch ( InputFileFormat )
                    {
                        case InputFileFormat.FlowScriptBinary:
                            OutputFilePath = InputFilePath + ".flowasm";
                            break;
                    }
                }
            }

            Logger.Info( $"Output file path is set to {OutputFilePath}" );

            return true;
        }

        private static bool TryDoCompilation()
        {
            switch ( InputFileFormat )
            {
                case InputFileFormat.FlowScriptTextSource:
                case InputFileFormat.FlowScriptAssemblerSource:
                    return TryDoFlowScriptCompilation();

                case InputFileFormat.MessageScriptTextSource:
                    return TryDoMessageScriptCompilation();

                case InputFileFormat.FlowScriptBinary:
                case InputFileFormat.MessageScriptBinary:
                    Logger.Error( "Binary files can't be compiled again!" );
                    return false;

                default:
                    Logger.Error( "Invalid input file format!" );
                    return false;
            }
        }

        private static bool TryDoFlowScriptCompilation()
        {
            Logger.Error( "Compiling flow scripts is not implemented yet!" );
            return false;
        }

        private static bool TryDoMessageScriptCompilation()
        {
            // Compile source
            Logger.Info( "Compiling MessageScript..." );

            MessageScriptFormatVersion version;

            if ( OutputFileFormat == OutputFileFormat.V1 )
            {
                version = MessageScriptFormatVersion.Version1;
            }
            else if ( OutputFileFormat == OutputFileFormat.V1BE )
            {
                version = MessageScriptFormatVersion.Version1BigEndian;
            }
            else
            {
                Logger.Error( "Invalid MessageScript file format" );
                return false;
            }

            var encoding = GetEncoding();
            var compiler = new MessageScriptCompiler( version, encoding );
            compiler.AddListener( Listener );
            if ( !compiler.TryCompile( File.OpenText( InputFilePath ), out var script ) )
            {
                Logger.Error( "One or more errors occured during compilation!" );
                return false;
            }

            // Write binary
            Logger.Info( "Writing binary to file..." );
            if ( !TryPerformAction( "An error occured while saving the file.", () => script.ToFile( OutputFilePath ) ) )
                return false;

            return true;
        }

        private static bool TryDoDecompilation()
        {
            switch ( InputFileFormat )
            {
                case InputFileFormat.FlowScriptTextSource:
                case InputFileFormat.FlowScriptAssemblerSource:
                case InputFileFormat.MessageScriptTextSource:
                    Logger.Error( "Can't decompile a text source!" );
                    return false;

                case InputFileFormat.FlowScriptBinary:
                    return TryDoFlowScriptDecompilation();

                case InputFileFormat.MessageScriptBinary:
                    return TryDoMessageScriptDecompilation();

                default:
                    Logger.Error( "Invalid input file format!" );
                    return false;
            }
        }

        private static bool TryDoFlowScriptDecompilation()
        {
            Logger.Error( "Decompiling flow scripts is not implemented yet!" );
            return false;
        }

        private static bool TryDoMessageScriptDecompilation()
        {
            // load binary file
            Logger.Info( "Loading binary MessageScript file..." );
            MessageScript script = null;
            var encoding = GetEncoding();

            if ( !TryPerformAction( "Failed to load message script from file.", () => script = MessageScript.FromFile( InputFilePath, encoding ) ) )
                return false;

            Logger.Info( "Decompiling MessageScript..." );

            if ( !TryPerformAction( "Failed to decompile message script to file.", () =>
            {
                using ( var decompiler = new MessageScriptDecompiler() )
                {
                    decompiler.TextOutputProvider = new FileTextOutputProvider( OutputFilePath );
                    decompiler.Decompile( script );
                }
            } ) )
            {
                return false;
            }

            return true;
        }

        private static bool TryDoDisassembling()
        {
            switch ( InputFileFormat )
            {
                case InputFileFormat.FlowScriptTextSource:
                case InputFileFormat.FlowScriptAssemblerSource:
                case InputFileFormat.MessageScriptTextSource:
                    Logger.Error( "Can't disassemble a text source!" );
                    return false;

                case InputFileFormat.FlowScriptBinary:
                    return TryDoFlowScriptDisassembly();

                case InputFileFormat.MessageScriptBinary:
                    Logger.Info( "Error. Disassembling message scripts is not supported." );
                    return false;

                default:
                    Logger.Error( "Invalid input file format!" );
                    return false;
            }
        }

        private static bool TryDoFlowScriptDisassembly()
        {
            // load binary file
            Logger.Info( "Loading binary FlowScript file..." );

            FlowScriptBinary script;

            try
            {
                script = FlowScriptBinary.FromFile( InputFilePath );
            }
            catch ( Exception e )
            {
                Logger.Error( "Failed to load flow script from file. Info:" );
                Logger.Debug( $"{e.Message}" );
                Logger.Debug( "Stacktrace:" );
                Logger.Debug( $"{e.StackTrace}" );
                return false;
            }

            Logger.Info( "Disassembling FlowScript..." );
            try
            {
                var disassembler = new FlowScriptBinaryDisassembler( OutputFilePath );
                disassembler.Disassemble( script );
            }
            catch ( Exception e )
            {
                Logger.Error( "Failed to disassemble flow script to file. Info:" );
                Logger.Debug( $"{e.Message}" );
                Logger.Debug( "Stacktrace:" );
                Logger.Debug( $"{e.StackTrace}" );
                return false;
            }

            return true;
        }

        private static bool TryPerformAction( string errorMessage, Action action )
        {
            try
            {
                action();
            }
            catch ( Exception e )
            {
                LogException( errorMessage, e );
                return false;
            }

            return true;
        }

        private static Encoding GetEncoding( )
        {
            Encoding encoding = null;

            if ( OutputTextEncoding == OutputTextEncoding.SJ )
            {
                encoding = Encoding.GetEncoding( 932 );
            }
            else if ( OutputTextEncoding == OutputTextEncoding.P3 )
            {
                encoding = new Persona3Encoding();
            }
            else if ( OutputTextEncoding == OutputTextEncoding.P4 )
            {
                encoding = new Persona4Encoding();
            }
            else if ( OutputTextEncoding == OutputTextEncoding.P5 )
            {
                encoding = new Persona5Encoding();
            }

            return encoding;
        }

        private static void LogException( string message, Exception e )
        {
            Logger.Error( message );
            Logger.Debug( "Exception info:" );
            Logger.Debug( $"{e.Message}" );
            Logger.Debug( "Stacktrace:" );
            Logger.Debug( $"{e.StackTrace}" );
        }
    }

    public enum InputFileFormat
    {
        None,
        FlowScriptBinary,
        FlowScriptTextSource,
        FlowScriptAssemblerSource,
        MessageScriptBinary,
        MessageScriptTextSource,
    }

    public enum OutputFileFormat
    {
        None,
        V1,
        V1BE,
        V2,
        V2BE,
        V3,
        V3BE
    }

    public enum OutputTextEncoding
    {
        None,
        SJ,
        P3,
        P4,
        P5
    }

    public class Argument
    {
        public string Key { get; }

        public string Description { get; }

        public List<ArgumentParameter> Parameters { get; }

        public Argument( string key, string description, params ArgumentParameter[] parameters)
        {
            Key = key;
            Description = description;
            Parameters = parameters.ToList();
        }
    }

    public class ArgumentParameter
    {
        public string Name { get; }

        public Action<string> AssignmentAction { get; }

        public ArgumentParameter( string name, Action<string> assignment)
        {
            Name = name;
            AssignmentAction = assignment;
        }
    }
}
