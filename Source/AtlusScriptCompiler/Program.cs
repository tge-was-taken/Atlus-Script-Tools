using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.Common.Text.OutputProviders;
using AtlusScriptLib.FlowScriptLanguage.BinaryModel;
using AtlusScriptLib.FlowScriptLanguage.Disassembler;
using AtlusScriptLib.MessageScriptLanguage;
using AtlusScriptLib.MessageScriptLanguage.BinaryModel;
using AtlusScriptLib.MessageScriptLanguage.Compiler;
using AtlusScriptLib.MessageScriptLanguage.Decompiler;

namespace AtlusScriptCompiler
{
    public class Program
    {
        private static Version Version = Assembly.GetExecutingAssembly().GetName().Version;

        private static string InputFilePath;

        private static string OutputFilePath;

        private static bool IsActionAssigned;

        private static bool DoCompile;

        private static bool DoDecompile;

        private static bool DoDisassemble;

        private static InputFileFormat InputFileFormat;

        private static OutputFileFormat OutputFileFormat;

        private static void DisplayUsage()
        {
            Console.WriteLine( $"AtlusScriptCompiler {Version.Major}.{Version.Minor} by TGE (2017)" );
            Console.WriteLine();
            Console.WriteLine( "Parameter info:" );
            Console.WriteLine( "    -i <path to file>       Provides an input file source to the compiler. If no input source is explicitly specified, the first argument will be assumed to be one." );
            Console.WriteLine( "    -o <path to file>       Provides an output file path to the compiler. If no output source is explicitly specified, the file will be output in the same folder as the source file under a different extension." );
            Console.WriteLine( "    -com                    Instructs the compiler to compile the provided input file source." );
            Console.WriteLine( "    -dec                    Instructs the compiler to decompile the provided input file source." );
            Console.WriteLine( "    -dis                    Instructs the compiler to disassemble the provided input file source." );
            Console.WriteLine( "    -infmt <format string>  Specifies the input file source format. By default this is guessed by the file extension." );
            Console.WriteLine( "    -outfmt <format string> Specifies the output file format. See below for further info." );
            Console.WriteLine();
            Console.WriteLine( "Parameter detailed info:" );
            Console.WriteLine( "    -outfmt" );
            Console.WriteLine();
            Console.WriteLine( "        MessageScript formats:" );
            Console.WriteLine( "            v1              Used by Persona 3, 4, 5 PS4" );
            Console.WriteLine( "            v1be            Used by Persona 5 PS3" );
            Console.WriteLine();
            Console.WriteLine( "         FlowScript formats:" );
            Console.WriteLine( "            v1             Used by Persona 3 and 4" );
            Console.WriteLine( "            v1be           " );
            Console.WriteLine( "            v2             Used by Persona 4 Dancing All Night" );
            Console.WriteLine( "            v2be           " );
            Console.WriteLine( "            v3             Used by Persona 5 PS4" );
            Console.WriteLine( "            v3be           Used by Persona 5 PS3" );
            Console.ReadKey();
        }

        public static void Main( string[] args )
        {
            if ( args.Length == 0 )
            {
                Console.WriteLine( "Error: No arguments specified!" );
                DisplayUsage();
                return;
            }

            if ( !TryParseArguments( args ) )
            {
                Console.WriteLine( "Error: Failed to parse arguments!" );
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
                Console.WriteLine( "Error: No compilation, decompilation or disassemble instruction given!" );
                DisplayUsage();
                return;
            }

            if ( success )
                Console.WriteLine( "Task completed successfully!" );
            else
                Console.WriteLine( "One or more errors occured while executing task!" );

            Console.WriteLine( "Press any key to continue" );
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
                            Console.WriteLine( "Error: Missing argument for -i parameter" );
                            return false;
                        }

                        InputFilePath = args[++i];
                        break;

                    case "-o":
                        if ( i + 1 == args.Length )
                        {
                            Console.WriteLine( "Error: Missing argument for -o parameter" );
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
                            Console.WriteLine( "Error: Attempted to assign compilation action while another action is already assigned." );
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
                            Console.WriteLine( "Error: Attempted to assign decompilation action while another action is already assigned." );
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
                            Console.WriteLine( "Error: Attempted to assign disassembly action while another action is already assigned." );
                            return false;
                        }

                        DoDisassemble = true;
                        break;

                    case "-infmt":
                        if ( i + 1 == args.Length )
                        {
                            Console.WriteLine( "Error: Missing argument for -infmt parameter" );
                            return false;
                        }

                        if ( !Enum.TryParse( args[++i], true, out InputFileFormat ) )
                        {
                            Console.WriteLine( "Error: Invalid input file format specified" );
                            return false;
                        }

                        break;

                    case "-outfmt":
                        if ( i + 1 == args.Length )
                        {
                            Console.WriteLine( "Error: Missing argument for -outfmt parameter" );
                            return false;
                        }

                        if ( !Enum.TryParse( args[++i], true, out OutputFileFormat ) )
                        {
                            Console.WriteLine( "Error: Invalid output file format specified" );
                            return false;
                        }

                        break;
                }
            }

            if ( InputFilePath == null )
            {
                InputFilePath = args[0];
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
                        Console.WriteLine( "Error: Unable to detect input file format" );
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
                    Console.WriteLine( "Error: Binary files can't be compiled again!" );
                    return false;

                default:
                    Console.WriteLine( "Error: Invalid input file format!" );
                    return false;
            }
        }

        private static bool TryDoFlowScriptCompilation()
        {
            Console.WriteLine( "Error: Compiling flow scripts is not implemented yet!" );
            return false;
        }

        private static bool TryDoMessageScriptCompilation()
        {
            MessageScriptBinaryFormatVersion version;

            if ( OutputFileFormat == OutputFileFormat.V1 )
            {
                version = MessageScriptBinaryFormatVersion.Version1;
            }
            else if ( OutputFileFormat == OutputFileFormat.V1BE )
            {
                version = MessageScriptBinaryFormatVersion.Version1BigEndian;
            }
            else
            {
                Console.WriteLine( "Error: Invalid MessageScript file format" );
                return false;
            }

            // Compile source
            var compiler = new MessageScriptCompiler( version );
            compiler.AddListener( new ConsoleLogListener( true ) );
            if ( !compiler.TryCompile( File.OpenText( InputFilePath ), out var script ) )
            {
                Console.WriteLine( "Error: One or more errors occured during compilation!" );
                return false;
            }

            // Write binary
            try
            {
                script.ToFile( OutputFilePath );
            }
            catch ( Exception e )
            {
                Console.WriteLine( "Error: An error occured while saving the file. Info:" );
                Console.WriteLine( $"{e.Message}" );
                Console.WriteLine( "Stacktrace:" );
                Console.WriteLine( $"{e.StackTrace}" );
                return false;
            }

            return true;
        }

        private static bool TryDoDecompilation()
        {
            switch ( InputFileFormat )
            {
                case InputFileFormat.FlowScriptTextSource:
                case InputFileFormat.FlowScriptAssemblerSource:
                case InputFileFormat.MessageScriptTextSource:
                    Console.WriteLine( "Error: Can't decompile a text source!" );
                    return false;

                case InputFileFormat.FlowScriptBinary:
                    return TryDoFlowScriptDecompilation();

                case InputFileFormat.MessageScriptBinary:
                    return TryDoMessageScriptDecompilation();

                default:
                    Console.WriteLine( "Error: Invalid input file format!" );
                    return false;
            }
        }

        private static bool TryDoFlowScriptDecompilation()
        {
            Console.WriteLine( "Error: Decompiling flow scripts is not implemented yet!" );
            return false;
        }

        private static bool TryDoMessageScriptDecompilation()
        {
            // load binary file
            MessageScript script;

            try
            {
                script = MessageScript.FromFile( InputFilePath );
            }
            catch ( Exception e )
            {
                Console.WriteLine( "Error: Failed to load message script from file. Info:" );
                Console.WriteLine( $"{e.Message}" );
                Console.WriteLine( "Stacktrace:" );
                Console.WriteLine( $"{e.StackTrace}" );
                return false;
            }

            try
            {
                using ( var decompiler = new MessageScriptDecompiler() )
                {
                    decompiler.TextOutputProvider = new FileTextOutputProvider( OutputFilePath );
                    decompiler.Decompile( script );
                }
            }
            catch ( Exception e )
            {
                Console.WriteLine( "Error: Failed to decompile message script to file. Info:" );
                Console.WriteLine( $"{e.Message}" );
                Console.WriteLine( "Stacktrace:" );
                Console.WriteLine( $"{e.StackTrace}" );
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
                    Console.WriteLine( "Error: Can't disassemble a text source!" );
                    return false;

                case InputFileFormat.FlowScriptBinary:
                    return TryDoFlowScriptDisassembly();

                case InputFileFormat.MessageScriptBinary:
                    Console.WriteLine( "Error. Disassembling message scripts is not supported." );
                    return false;

                default:
                    Console.WriteLine( "Error: Invalid input file format!" );
                    return false;
            }
        }

        private static bool TryDoFlowScriptDisassembly()
        {
            // load binary file
            FlowScriptBinary script;

            try
            {
                script = FlowScriptBinary.FromFile( InputFilePath );
            }
            catch ( Exception e )
            {
                Console.WriteLine( "Error: Failed to load flow script from file. Info:" );
                Console.WriteLine( $"{e.Message}" );
                Console.WriteLine( "Stacktrace:" );
                Console.WriteLine( $"{e.StackTrace}" );
                return false;
            }

            try
            {
                var disassembler = new FlowScriptBinaryDisassembler( OutputFilePath );
                disassembler.Disassemble( script );
            }
            catch ( Exception e )
            {
                Console.WriteLine( "Error: Failed to disassemble flow script to file. Info:" );
                Console.WriteLine( $"{e.Message}" );
                Console.WriteLine( "Stacktrace:" );
                Console.WriteLine( $"{e.StackTrace}" );
                return false;
            }

            return true;
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
}
