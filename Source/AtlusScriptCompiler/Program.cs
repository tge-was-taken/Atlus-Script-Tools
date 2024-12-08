using System.Reflection;
using System.Text;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Text;
using AtlusScriptLibrary.Common.Text.Encodings;
using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.FlowScriptLanguage.BinaryModel;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using AtlusScriptLibrary.FlowScriptLanguage.Decompiler;
using AtlusScriptLibrary.FlowScriptLanguage.Disassembler;
using AtlusScriptLibrary.MessageScriptLanguage;
using AtlusScriptLibrary.MessageScriptLanguage.Compiler;
using AtlusScriptLibrary.MessageScriptLanguage.Decompiler;
using FormatVersion = AtlusScriptLibrary.FlowScriptLanguage.FormatVersion;

namespace AtlusScriptCompiler;

internal class Program
{
    class MessageScriptOptions
    {
        public MessageScriptBinaryVariant BinaryVariant { get; set; }
        public string? EncodingName { get; set; }
        public Encoding? Encoding { get; set; }
        public bool? OmitUnusedFunctions { get; set; }
    }

    class FlowScriptOptions
    {
        // Flow Script Tracing Options
        public bool EnableProcedureTracing { get; set; }
        public bool EnableProcedureCallTracing { get; set; }
        public bool EnableFunctionCallTracing { get; set; } 
        public bool EnableStackCookie { get; set; } 
        public bool EnableProcedureHook { get; set; } 

        // Flow Script Advanced Options
        public bool SumBits { get; set; }
        public bool OverwriteMessages { get; set; }
        public bool KeepLocalVariableIndices { get; set; }
        public bool GotoOnly { get; set; }
    }

    class UnrealEngineOptions
    {
        public bool Wrapped { get; set; } 
        public string? PatchFile { get; set; }
    }

    class ProgramOptions
    {
        // File Paths
        public string? InputFilePath { get; set; }
        public InputFileFormat InputFileFormat { get; set; }
        public string? OutputFilePath { get; set; }
        public OutputFileFormat OutputFileFormat { get; set; }

        public string? LibraryName { get; set; }
        public bool LogTrace { get; set; }
        public bool Matching { get; set; }

        // Actions
        public bool DoCompile { get; set; }
        public bool DoDecompile { get; set; } 
        public bool DoDisassemble { get; set; } 
        public bool DoDiff { get; set; }
        public bool IsActionAssigned
            => DoCompile || DoDecompile || DoDisassemble || DoDiff;

        // Message Script Configuration
        public MessageScriptOptions MessageScript { get; set; } = new();

        // Flow Script Configuration
        public FlowScriptOptions FlowScript { get; set; } = new();

        // UE-Specific Options
        public UnrealEngineOptions UnrealEngine { get; set; } = new();
    }

    static class ExitCode
    {
        public static readonly int Success = 0;
        public static readonly int Error = 1;
        public static readonly int InvalidArguments = 2;
    }

    public static AssemblyName AssemblyName = Assembly.GetExecutingAssembly().GetName();
    static Version Version = AssemblyName.Version;
    static Logger Logger = new Logger(nameof(AtlusScriptCompiler));
    static LogListener Listener = new FileAndConsoleLogListener(true, LogLevel.Info | LogLevel.Warning | LogLevel.Error | LogLevel.Fatal);
    static ProgramOptions Options = new();

    private static void DisplayUsage()
    {
        Console.WriteLine($"AtlusScriptCompiler {Version.Major}.{Version.Minor}-{ThisAssembly.Git.Commit} ({ThisAssembly.Git.CommitDate})");
        Console.WriteLine();
        Console.WriteLine("Note: If you encounter any issues, please report it & include the AtlusScriptCompiler.log file. Thank you.");
        Console.WriteLine();
        Console.WriteLine("Parameter overview:");
        Console.WriteLine("    General:");
        Console.WriteLine("        -In                     <path to file>      Provides an input file source to the compiler. If no input source is explicitly specified, ");
        Console.WriteLine("                                                    the first argument will be assumed to be one.");
        Console.WriteLine("        -InFormat               <format>            Specifies the input file source format. By default this is guessed by the file extension.");
        Console.WriteLine("        -Out                    <path to file>      Provides an output file path to the compiler. If no output source is explicitly specified, ");
        Console.WriteLine("                                                    the file will be output in the same folder as the source file under a different extension depending on the format used.");
        Console.WriteLine("        -OutFormat              <format>            Specifies the binary output file format. See below for further info.");
        Console.WriteLine("        -Compile                                    Instructs the compiler to compile the provided input file source.");
        Console.WriteLine("        -Decompile                                  Instructs the compiler to decompile the provided input file source.");
        Console.WriteLine("        -Disassemble                                Instructs the compiler to disassemble the provided input file source.");
        Console.WriteLine("        -Library                <name>              Specifies the name of the library that should be used.");
        Console.WriteLine("        -LogTrace                                   Outputs trace log messages to the console");
        Console.WriteLine("        -UPatch                 <path to file>      Patches an existing BF/BMD uasset to insert the newly compiled file into, including fixing file lengths. For Persona 3 Reload");
        Console.WriteLine("        -Diff                                       For testing purposes only. Disassembles & decompiles the given file, and afterwards the decompiled file is recompiled, disassembled, and decompiled again for diffing purposes.");
        Console.WriteLine("        -Matching                                   For testing purposes only. Disables any optimisations that would cause the output to not match with the original binaries.");
        Console.WriteLine();
        Console.WriteLine("    MessageScript:");
        Console.WriteLine("        -Encoding               <format>            Specifies the MessageScript binary output text encoding. See below for further info.");
        Console.WriteLine();
        Console.WriteLine("    FlowScript:");
        Console.WriteLine("        -TraceProcedure                            Enables procedure tracing. Only applies to compiler.");
        Console.WriteLine("        -TraceProcedureCalls                       Enables procedure call tracing. Only applies to compiler.");
        Console.WriteLine("        -TraceFunctionCalls                        Enables function call tracing. Only applies to compiler.");
        Console.WriteLine("        -StackCookie                               Enables stack cookie. Used for debugging stack corruptions.");
        Console.WriteLine("        -Hook                                      Enables hooking of procedures. Used to modify scripts without recompiling them entirely.");
        Console.WriteLine("        -SumBits                                   Sums the bit id values passed to BIT_* functions");
        Console.WriteLine("        -OverwriteMessages                         Causes messages with duplicate names to overwrite existing messages.");
        Console.WriteLine("        -GotoOnly                                  For testing purposes only. Don't try to reconstruct control flow while decompiling.");
        Console.WriteLine();
        Console.WriteLine("Parameter detailed info:");
        Console.WriteLine("    MessageScript:");
        Console.WriteLine("        -OutFormat");
        Console.WriteLine("            V1              Used by Persona 3, 4, 5 PS4");
        Console.WriteLine("            V1DDS           Used by Digital Devil Saga 1 & 2");
        Console.WriteLine("            V1BE            Used by Persona 5 PS3");
        Console.WriteLine("            V1RE            Used by Persona 3 Reload");
        Console.WriteLine("            V2              Used by Catherine: Full Body");
        Console.WriteLine("            V2BE            Used by Catherine");
        Console.WriteLine();
        Console.WriteLine("        -Encoding");
        Console.WriteLine("            Below is a list of different available standard encodings.");
        Console.WriteLine("            Note that ASCII characters don't really differ from the standard, so this mostly applies to special characters and japanese characters.");
        Console.WriteLine();
        Console.WriteLine("            ASCII                             Standard ASCII encoding.");
        Console.WriteLine("            SJ (shift-jis)                    Shift-JIS encoding (CP932). Used by Persona Q(2)");
        Console.WriteLine("            P3                                Persona 3's custom encoding");
        Console.WriteLine("            P4                                Persona 4's custom encoding");
        Console.WriteLine("            P5                                Persona 5's custom encoding");
        Console.WriteLine("            CAT                               Catherine's custom encoding");
        Console.WriteLine("            CFB                               Catherine: Full Body's custom encoding");
        Console.WriteLine("            UT (utf-8)                        UTF-8 Encoding. Used by Persona 3 Reload");
        Console.WriteLine("            Unicode (utf-16)                  UTF-16 Encoding.");
        Console.WriteLine("            Unicode Big Endian (utf-16-be)    Big Endian UTF-16 Encoding.");
        Console.WriteLine("            <charset file name>               Custom encodings can be used by placing them in the charset folder. The TSV files are tab separated.");
        Console.WriteLine("            See below for all available charsets.");
        Console.WriteLine();
        Console.WriteLine("        -Library");
        Console.WriteLine("            For MessageScripts the libraries used for the compiler and decompiler to emit the proper [f] tags for each aliased function.");
        Console.WriteLine("            If you don't use any aliased functions, you don't need to specify this, but if you do without specifying it, you'll get a compiler error.");
        Console.WriteLine("            Not specifying a library definition registry means that the decompiler will not try to look up aliases for functions.");
        Console.WriteLine("            Libraries can be found in the Libraries directory");
        Console.WriteLine("            Either the full name enclosed with quotes, or the shorthand name can be used.");
        Console.WriteLine("            See below for all available libraries.");
        Console.WriteLine();
        Console.WriteLine("    FlowScript:");
        Console.WriteLine("        -OutFormat");
        Console.WriteLine("            V1              Used by Persona 3 and 4");
        Console.WriteLine("            V1DDS           Used by Digital Devil Saga 1 & 2");
        Console.WriteLine("            V1BE            ");
        Console.WriteLine("            V2              Used by Persona 4 Dancing All Night");
        Console.WriteLine("            V2BE            ");
        Console.WriteLine("            V3              Used by Persona 5 PS4");
        Console.WriteLine("            V3BE            Used by Persona 5 PS3 & PS4");
        Console.WriteLine("            V4              Used by Persona 3 Reload");
        Console.WriteLine("            V4BE            Used by Persona 3 Reload");
        Console.WriteLine();
        Console.WriteLine("        -Library");
        Console.WriteLine("            For FlowScripts the libraries is used for the decompiler to decompile binary scripts, but it is also used to generate documentation.");
        Console.WriteLine("            Without a specified registry you cannot decompile scripts.");
        Console.WriteLine("            Libraries can be found in the Libraries directory");
        Console.WriteLine("            Either the full name enclosed with quotes, or the shorthand name can be used.");
        Console.WriteLine("            See below for all available libraries.");
        Console.WriteLine();
        Console.WriteLine("Available libraries:");
        foreach (var lib in LibraryLookup.Libraries)
            Console.WriteLine($"    {lib.Name} ({lib.ShortName})");
        Console.WriteLine();
        Console.WriteLine("Available charsets:");
        foreach (var item in AtlusEncoding.AvailableCharsets)
        {
            if (AtlusEncoding.CharsetAliases.TryGetValue(item, out var aliases))
            {
                Console.WriteLine($"    {item} ({string.Join(", ", aliases)})");
            }
            else
            {
                Console.WriteLine($"    {item}");
            }
        }
        Console.WriteLine();
    }

    public static int Main(string[] args)
    {
        try
        {
            LibraryLookup.EnsureInitialized();
        }
        catch (Exception ex)
        {
            LogException($"Failed to load libraries", ex);
            return ExitCode.Error;
        }

        if (args.Length == 0)
        {
            Logger.Error("No arguments specified!");
            DisplayUsage();
            return ExitCode.InvalidArguments;
        }

        // Set up log listener
        Listener.Subscribe(Logger);

        // Log arguments
        Logger.Trace($"Arguments: {string.Join(" ", args)}");

        if (!TryParseArguments(args))
        {
            Logger.Error("Failed to parse arguments!");
            DisplayUsage();
            return ExitCode.InvalidArguments;
        }

        if (Options.LogTrace)
            Listener.Filter |= LogLevel.Trace;

        bool success;

#if !DEBUG
        try
#endif
        {
            if (Options.UnrealEngine.Wrapped)
            {
                success = UEWrapperHandler();
            }
            if (Options.DoCompile)
            {
                success = TryDoCompilation();
            }
            else if (Options.DoDecompile)
            {
                success = TryDoDecompilation();
            }
            else if (Options.DoDisassemble)
            {
                success = TryDoDisassembling();
            }
            else if (Options.DoDiff)
            {
                success = TryDoDiff();
            }
            else
            {
                Logger.Error("No compilation, decompilation or disassemble instruction given!");
                DisplayUsage();
                return ExitCode.InvalidArguments;
            }
            if (success && Options.UnrealEngine.PatchFile != null)
            {
                if (Options.DoCompile)
                {
                    success = UEWrapper.WrapAsset(Options.OutputFilePath, Options.UnrealEngine.PatchFile);
                }
                else
                {
                    Logger.Error("Patch file can only be used on compilation");
                    DisplayUsage();
                    return ExitCode.InvalidArguments;
                }
            }
        }
#if !DEBUG
        catch ( Exception e )
        {
            LogException( "Unhandled exception thrown", e );
            success = false;

            if ( System.Diagnostics.Debugger.IsAttached )
                throw;
        }
#endif

        if (success)
            Logger.Info("Task completed successfully!");
        else
            Logger.Error("One or more errors occured while executing task!");

        Console.ForegroundColor = ConsoleColor.Gray;
        return success ? ExitCode.Success : ExitCode.Error;
    }

    private static bool TryParseArguments(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            bool isLast = i + 1 == args.Length;

            switch (args[i])
            {
                // General
                case "-In":
                    if (isLast)
                    {
                        Logger.Error("Missing argument for -In parameter");
                        return false;
                    }

                    Options.InputFilePath = args[++i];
                    break;

                case "-InFormat":
                    if (isLast)
                    {
                        Logger.Error("Missing argument for -InFormat parameter");
                        return false;
                    }

                    if (!Enum.TryParse(args[++i], true, out InputFileFormat inputFileFormat))
                    {
                        Logger.Error("Invalid input file format specified");
                        return false;
                    }
                    Options.InputFileFormat = inputFileFormat;

                    break;

                case "-Out":
                    if (isLast)
                    {
                        Logger.Error("Missing argument for -Out parameter");
                        return false;
                    }

                    Options.OutputFilePath = args[++i];
                    break;

                case "-OutFormat":
                    if (isLast)
                    {
                        Logger.Error("Missing argument for -OutFormat parameter");
                        return false;
                    }

                    if (!Enum.TryParse(args[++i], true, out OutputFileFormat outputFileFormat))
                    {
                        Logger.Error("Invalid output file format specified");
                        return false;
                    }
                    Options.OutputFileFormat = outputFileFormat;

                    break;

                case "-Compile":
                    if (Options.IsActionAssigned)
                    {
                        Logger.Error("Attempted to assign compilation action while another action is already assigned.");
                        return false;
                    }

                    Options.DoCompile = true;
                    break;

                case "-Decompile":
                    if (Options.IsActionAssigned)
                    {
                        Logger.Error("Attempted to assign decompilation action while another action is already assigned.");
                        return false;
                    }

                    Options.DoDecompile = true;
                    break;

                case "-Disassemble":
                    if (Options.IsActionAssigned)
                    {
                        Logger.Error("Attempted to assign disassembly action while another action is already assigned.");
                        return false;
                    }

                    Options.DoDisassemble = true;
                    break;

                case "-Diff":
                    if (Options.IsActionAssigned)
                    {
                        Logger.Error("Attempted to assign diff action while another action is already assigned.");
                        return false;
                    }
                    Options.DoDiff = true;
                    break;

                case "-Library":
                    if (isLast)
                    {
                        Logger.Error("Missing argument for -Library parameter");
                        return false;
                    }

                    Options.LibraryName = args[++i];
                    break;

                case "-LogTrace":
                    Options.LogTrace = true;
                    break;

                case "-Matching":
                    Options.Matching = true;
                    break;

                // MessageScript
                case "-Encoding":
                    if (isLast)
                    {
                        Logger.Error("Missing argument for -Encoding parameter");
                        return false;
                    }

                    Options.MessageScript.EncodingName = args[++i];

                    switch (Options.MessageScript.EncodingName.ToLower())
                    {
                        case "ascii":
                            Options.MessageScript.Encoding = Encoding.ASCII;
                            break;
                        case "sj":
                        case "shiftjis":
                        case "shift-jis":
                            Options.MessageScript.Encoding = ShiftJISEncoding.Instance;
                            break;
                        case "ut":
                        case "utf-8":
                            Options.MessageScript.Encoding = Encoding.UTF8;
                            break;
                        case "unicode":
                        case "utf-16":
                            Options.MessageScript.Encoding = Encoding.Unicode;
                            break;
                        case "utf-16-be":
                            Options.MessageScript.Encoding = Encoding.BigEndianUnicode;
                            break;
                        case "cat":
                            Options.MessageScript.Encoding = CatherineEncoding.Instance;
                            break;
                        case "cfb":
                            Options.MessageScript.Encoding = CatherineFullBodyEncoding.Instance;
                            break;
                        default:
                            try
                            {
                                Options.MessageScript.Encoding = AtlusEncoding.Create(Options.MessageScript.EncodingName);
                            }
                            catch (ArgumentException)
                            {
                                Logger.Error($"Unknown encoding: {Options.MessageScript.EncodingName}");
                                return false;
                            }
                            break;
                    }

                    Logger.Info($"Using {Options.MessageScript.EncodingName} encoding");
                    break;

                case "-TraceProcedure":
                    Options.FlowScript.EnableProcedureTracing = true;
                    break;

                case "-TraceProcedureCalls":
                    Options.FlowScript.EnableProcedureCallTracing = true;
                    break;

                case "-TraceFunctionCalls":
                    Options.FlowScript.EnableFunctionCallTracing = true;
                    break;

                case "-StackCookie":
                    Options.FlowScript.EnableStackCookie = true;
                    break;

                case "-Hook":
                    Options.FlowScript.EnableProcedureHook = true;
                    break;

                case "-SumBits":
                    Options.FlowScript.SumBits = true;
                    break;

                case "-UPatch":
                    if (isLast)
                    {
                        Logger.Error("Missing argument for -UPatch parameter");
                        return false;
                    }

                    Options.UnrealEngine.PatchFile = args[++i];
                    break;

                case "-OverwriteMessages":
                    Options.FlowScript.OverwriteMessages = true;
                    break;

                case "-GotoOnly":
                    Options.FlowScript.GotoOnly = true;
                    break;
            }
        }

        if (Options.InputFilePath == null)
        {
            Options.InputFilePath = args[0];
        }

        if (!File.Exists(Options.InputFilePath))
        {
            Logger.Error($"Specified input file doesn't exist! ({Options.InputFilePath})");
            return false;
        }

        if (Options.InputFileFormat == InputFileFormat.None)
        {
            var extension = Path.GetExtension(Options.InputFilePath);

            switch (extension.ToLowerInvariant())
            {
                case ".bf":
                    Options.InputFileFormat = InputFileFormat.FlowScriptBinary;
                    break;

                case ".flow":
                    Options.InputFileFormat = InputFileFormat.FlowScriptTextSource;
                    break;

                case ".flowasm":
                    Options.InputFileFormat = InputFileFormat.FlowScriptAssemblerSource;
                    break;

                case ".bmd":
                    Options.InputFileFormat = InputFileFormat.MessageScriptBinary;
                    Options.MessageScript.BinaryVariant = MessageScriptBinaryVariant.BMD;
                    break;

                case ".bm2":
                    Options.InputFileFormat = InputFileFormat.MessageScriptBinary;
                    Options.MessageScript.BinaryVariant = MessageScriptBinaryVariant.BM2;
                    break;

                case ".msg":
                    Options.InputFileFormat = InputFileFormat.MessageScriptTextSource;
                    break;

                case ".uasset":
                    Logger.Error("-InFormat parameter required when working with Unreal Engine wrapped scripts");
                    return false;

                default:
                    Logger.Error("Unable to detect input file format");
                    return false;
            }
        }

        if (Options.InputFileFormat == InputFileFormat.MessageScriptTextSource &&
            (Options.OutputFileFormat == OutputFileFormat.V3 || Options.OutputFileFormat == OutputFileFormat.V3BE))
        {
            Options.MessageScript.BinaryVariant = MessageScriptBinaryVariant.BM2;
        }

        if (Path.GetExtension(Options.InputFilePath).ToLowerInvariant().Equals(".uasset"))
        {
            Options.UnrealEngine.Wrapped = true;
        }
        else
        {
            Options.UnrealEngine.Wrapped = false;
        }

        if (!Options.IsActionAssigned)
        {
            // Decide on default action based on input file format
            switch (Options.InputFileFormat)
            {
                case InputFileFormat.FlowScriptBinary:
                case InputFileFormat.MessageScriptBinary:
                    Options.DoDecompile = true;
                    break;
                case InputFileFormat.FlowScriptTextSource:
                case InputFileFormat.MessageScriptTextSource:
                    Options.DoCompile = true;
                    break;
                default:
                    Logger.Error("No compilation, decompilation or disassemble instruction given!");
                    return false;
            }
        }

        if (Options.OutputFilePath == null)
        {
            if (Options.DoCompile)
            {
                switch (Options.InputFileFormat)
                {
                    case InputFileFormat.FlowScriptTextSource:
                    case InputFileFormat.FlowScriptAssemblerSource:
                        Options.OutputFilePath = Options.InputFilePath + ".bf";
                        break;
                    case InputFileFormat.MessageScriptTextSource:
                        if (Options.MessageScript.BinaryVariant == MessageScriptBinaryVariant.BMD)
                            Options.OutputFilePath = Options.InputFilePath + ".bmd";
                        else if (Options.MessageScript.BinaryVariant == MessageScriptBinaryVariant.BM2)
                            Options.OutputFilePath = Options.InputFilePath + ".bm2";
                        break;
                }
            }
            else if (Options.DoDecompile)
            {
                switch (Options.InputFileFormat)
                {
                    case InputFileFormat.FlowScriptBinary:
                        Options.OutputFilePath = Options.InputFilePath + ".flow";
                        break;
                    case InputFileFormat.MessageScriptBinary:
                        Options.OutputFilePath = Options.InputFilePath + ".msg";
                        break;
                }
            }
            else if (Options.DoDisassemble)
            {
                switch (Options.InputFileFormat)
                {
                    case InputFileFormat.FlowScriptBinary:
                        Options.OutputFilePath = Options.InputFilePath + ".flowasm";
                        break;
                }
            }
        }

        if (!Options.UnrealEngine.Wrapped) 
            Logger.Info($"Output file path is set to {Options.OutputFilePath}");

        if (Options.DoDiff)
        {
            Options.Matching = true;
        }

        if (Options.Matching)
        {
            Options.MessageScript.OmitUnusedFunctions = false;
            Options.FlowScript.KeepLocalVariableIndices = true;
        }

        return true;
    }

    private static bool TryDoCompilation()
    {
        switch (Options.InputFileFormat)
        {
            case InputFileFormat.FlowScriptTextSource:
            case InputFileFormat.FlowScriptAssemblerSource:
                return TryDoFlowScriptCompilation(
                    Options.InputFilePath,
                    Options.OutputFilePath,
                    Options.OutputFileFormat,
                    Options.LibraryName,
                    Options.FlowScript,
                    Options.MessageScript);

            case InputFileFormat.MessageScriptTextSource:
                return TryDoMessageScriptCompilation(
                    Options.InputFilePath,
                    Options.OutputFilePath,
                    Options.OutputFileFormat,
                    Options.LibraryName,
                    Options.MessageScript);

            case InputFileFormat.FlowScriptBinary:
            case InputFileFormat.MessageScriptBinary:
                Logger.Error("Binary files can't be compiled again!");
                return false;

            default:
                Logger.Error("Invalid input file format!");
                return false;
        }
    }

    private static bool TryDoFlowScriptCompilation(
        string inputFilePath,
        string outputFilePath,
        OutputFileFormat outputFileFormat,
        string? libraryName,
        FlowScriptOptions flowScriptOptions,
        MessageScriptOptions messageScriptOptions)
    {
        Logger.Info("Compiling FlowScript...");

        // Get format verson
        var version = GetFlowScriptFormatVersion(outputFileFormat);
        if (version == FormatVersion.Unknown)
        {
            Logger.Error("Invalid FlowScript file format specified");
            return false;
        }

        // Compile source
        var compiler = new FlowScriptCompiler(version);
        compiler.AddListener(Listener);
        compiler.Encoding = messageScriptOptions.Encoding;
        compiler.EnableProcedureTracing = flowScriptOptions.EnableProcedureTracing;
        compiler.EnableProcedureCallTracing = flowScriptOptions.EnableProcedureCallTracing;
        compiler.EnableFunctionCallTracing = flowScriptOptions.EnableFunctionCallTracing;
        compiler.EnableStackCookie = flowScriptOptions.EnableStackCookie;
        compiler.ProcedureHookMode = flowScriptOptions.EnableProcedureHook ? ProcedureHookMode.ImportedOnly : ProcedureHookMode.None;
        compiler.OverwriteExistingMsgs = flowScriptOptions.OverwriteMessages;

        if (libraryName != null)
        {
            var library = LibraryLookup.GetLibrary(libraryName);

            if (library == null)
            {
                Logger.Error("Invalid library name specified");
                return false;
            }

            compiler.Library = library;
        }

        FlowScript flowScript = null;
        var success = false;
        using (var file = File.Open(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            try
            {
                success = compiler.TryCompile(file, out flowScript);
            }
            catch (UnsupportedCharacterException e)
            {
                Logger.Error($"Character '{e.Character}' not supported by encoding '{e.EncodingName}'");
            }

            if (!success)
            {
                Logger.Error("One or more errors occured during compilation!");
                return false;
            }
        }

        // Write binary
        Logger.Info("Writing binary to file...");
        return TryPerformAction("An error occured while saving the file.", () => flowScript.ToFile(outputFilePath));
    }

    private static FormatVersion GetFlowScriptFormatVersion(OutputFileFormat outputFileFormat)
    {
        FormatVersion version;
        switch (outputFileFormat)
        {
            case OutputFileFormat.V1:
                version = FormatVersion.Version1;
                break;
            case OutputFileFormat.V1BE:
                version = FormatVersion.Version1BigEndian;
                break;
            case OutputFileFormat.V1DDS:
                version = FormatVersion.Version1; // TODO: relay proper MessageScript version to FlowScript loader
                break;
            case OutputFileFormat.V2:
                version = FormatVersion.Version2;
                break;
            case OutputFileFormat.V2BE:
                version = FormatVersion.Version2BigEndian;
                break;
            case OutputFileFormat.V3:
                version = FormatVersion.Version3;
                break;
            case OutputFileFormat.V3BE:
                version = FormatVersion.Version3BigEndian;
                break;
            case OutputFileFormat.V4:
                version = FormatVersion.Version4;
                break;
            case OutputFileFormat.V4BE:
                version = FormatVersion.Version4BigEndian;
                break;
            default:
                version = FormatVersion.Unknown;
                break;
        }

        return version;
    }

    private static OutputFileFormat GetOutputFileFormat(FormatVersion version)
    {
        OutputFileFormat outputFileFormat;
        switch (version)
        {
            case FormatVersion.Version1:
                outputFileFormat = OutputFileFormat.V1;
                break;
            case FormatVersion.Version1BigEndian:
                outputFileFormat = OutputFileFormat.V1BE;
                break;
            case FormatVersion.Version2:
                outputFileFormat = OutputFileFormat.V2;
                break;
            case FormatVersion.Version2BigEndian:
                outputFileFormat = OutputFileFormat.V2BE;
                break;
            case FormatVersion.Version3:
                outputFileFormat = OutputFileFormat.V3;
                break;
            case FormatVersion.Version3BigEndian:
                outputFileFormat = OutputFileFormat.V3BE;
                break;
            case FormatVersion.Version4:
                outputFileFormat = OutputFileFormat.V4;
                break;
            case FormatVersion.Version4BigEndian:
                outputFileFormat = OutputFileFormat.V4BE;
                break;
            default:
                outputFileFormat = OutputFileFormat.None;
                break;
        }

        return outputFileFormat;
    }

    private static bool TryDoMessageScriptCompilation(
        string inputFilePath,
        string outputFilePath,
        OutputFileFormat outputFileFormat,
        string? libraryName,
        MessageScriptOptions messageScriptOptions)
    {
        // Compile source
        Logger.Info("Compiling MessageScript...");

        var version = GetMessageScriptFormatVersion(outputFileFormat);
        if (version == AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Detect)
        {
            Logger.Error("Invalid MessageScript file format");
            return false;
        }

        var compiler = new MessageScriptCompiler(version, messageScriptOptions.Encoding);
        compiler.AddListener(Listener);

        if (libraryName != null)
        {
            var library = LibraryLookup.GetLibrary(libraryName);

            if (library == null)
            {
                Logger.Error("Invalid library name specified");
                return false;
            }

            compiler.Library = library;
        }

        bool success = false;
        MessageScript script = null;

        try
        {
            success = compiler.TryCompile(File.OpenText(inputFilePath), out script);
        }
        catch (UnsupportedCharacterException e)
        {
            Logger.Error($"Character '{e.Character}' not supported by encoding '{e.EncodingName}'");
        }

        if (!success)
        {
            Logger.Error("One or more errors occured during compilation!");
            return false;
        }

        // Write binary
        Logger.Info("Writing binary to file...");
        if (!TryPerformAction("An error occured while saving the file.", () => script.ToFile(outputFilePath)))
            return false;

        return true;
    }

    private static AtlusScriptLibrary.MessageScriptLanguage.FormatVersion GetMessageScriptFormatVersion(OutputFileFormat outputFileFormat)
    {
        AtlusScriptLibrary.MessageScriptLanguage.FormatVersion version;

        switch (outputFileFormat)
        {
            case OutputFileFormat.V1:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1;
                break;
            case OutputFileFormat.V1DDS:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1DDS;
                break;
            case OutputFileFormat.V1BE:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1BigEndian;
                break;
            case OutputFileFormat.V1RE:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1Reload;
                break;
            case OutputFileFormat.V2:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version2;
                break;
            case OutputFileFormat.V2BE:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version2BigEndian;
                break;
            case OutputFileFormat.V3:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version3;
                break;
            case OutputFileFormat.V3BE:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version3BigEndian;
                break;
            default:
                version = AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Detect;
                break;
        }

        return version;
    }

    private static OutputFileFormat GetOutputFileFormatFromMessageScriptVersion(AtlusScriptLibrary.MessageScriptLanguage.FormatVersion version)
    {
        OutputFileFormat outputFileFormat;

        switch (version)
        {
            case AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1:
                outputFileFormat = OutputFileFormat.V1;
                break;
            case AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1DDS:
                outputFileFormat = OutputFileFormat.V1DDS;
                break;
            case AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1BigEndian:
                outputFileFormat = OutputFileFormat.V1BE;
                break;
            case AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version1Reload:
                outputFileFormat = OutputFileFormat.V1RE;
                break;
            case AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version2:
                outputFileFormat = OutputFileFormat.V2;
                break;
            case AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version2BigEndian:
                outputFileFormat = OutputFileFormat.V2BE;
                break;
            case AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version3:
                outputFileFormat = OutputFileFormat.V3;
                break;
            case AtlusScriptLibrary.MessageScriptLanguage.FormatVersion.Version3BigEndian:
                outputFileFormat = OutputFileFormat.V3BE;
                break;
            default:
                outputFileFormat = OutputFileFormat.None;
                break;
        }

        return outputFileFormat;
    }

    private static bool TryDoDecompilation()
    {
        switch (Options.InputFileFormat)
        {
            case InputFileFormat.FlowScriptTextSource:
            case InputFileFormat.FlowScriptAssemblerSource:
            case InputFileFormat.MessageScriptTextSource:
                Logger.Error("Can't decompile a text source!");
                return false;

            case InputFileFormat.FlowScriptBinary:
                return TryDoFlowScriptDecompilation(
                    Options.InputFilePath,
                    Options.OutputFilePath,
                    Options.LibraryName,
                    Options.FlowScript,
                    Options.MessageScript,
                    out _);

            case InputFileFormat.MessageScriptBinary:
                return TryDoMessageScriptDecompilation(
                    Options.InputFilePath,
                    Options.OutputFilePath,
                    Options.OutputFileFormat,
                    Options.LibraryName,
                    Options.MessageScript);

            default:
                Logger.Error("Invalid input file format!");
                return false;
        }
    }

    private static bool TryDoFlowScriptDecompilation(
        string inputFilePath, 
        string outputFilePath,
        string? libraryName, 
        FlowScriptOptions flowScriptOptions,
        MessageScriptOptions messageScriptOptions,
        out OutputFileFormat outputFileFormat)
    {
        // Load binary file
        outputFileFormat = OutputFileFormat.None;
        Logger.Info("Loading binary FlowScript file...");
        FlowScript flowScript = null;
        if (!TryPerformAction("Failed to load flow script from file", () => flowScript = FlowScript.FromFile(inputFilePath, messageScriptOptions.Encoding)))
            return false;

        Logger.Info("Decompiling FlowScript...");

        var decompiler = new FlowScriptDecompiler();
        decompiler.SumBits = flowScriptOptions.SumBits;
        decompiler.KeepLocalVariableIndices = flowScriptOptions.KeepLocalVariableIndices;
        decompiler.GotoOnly = flowScriptOptions.GotoOnly;
        decompiler.MessageScriptOmitUnusedFunctions = messageScriptOptions.OmitUnusedFunctions;
        decompiler.AddListener(Listener);

        if (libraryName != null)
        {
            var library = LibraryLookup.GetLibrary(libraryName);

            if (library == null)
            {
                Logger.Error("Invalid library name specified");
                return false;
            }

            decompiler.Library = library;
        }

        if (!decompiler.TryDecompile(flowScript, outputFilePath))
        {
            Logger.Error("Failed to decompile FlowScript");
            return false;
        }

        outputFileFormat = GetOutputFileFormat(flowScript!.FormatVersion);
        if (outputFileFormat != OutputFileFormat.None)
            Logger.Info($"FlowScript version {outputFileFormat} decompiled.");

        return true;
    }

    private static bool TryDoMessageScriptDecompilation(
        string inputFilePath,
        string outputFilePath,
        OutputFileFormat outputFileFormat,
        string? libraryName, 
        MessageScriptOptions messageScriptOptions)
    {
        // load binary file
        Logger.Info("Loading binary MessageScript file...");
        MessageScript script = null;
        var format = GetMessageScriptFormatVersion(outputFileFormat);

        if (!TryPerformAction("Failed to load message script from file.", () => script = MessageScript.FromFile(inputFilePath, format, messageScriptOptions.Encoding)))
            return false;

        Logger.Info("Decompiling MessageScript...");

        if (!TryPerformAction("Failed to decompile message script to file.", () =>
        {
            using (var decompiler = new MessageScriptDecompiler(new FileTextWriter(outputFilePath)))
            {
                if (libraryName != null)
                {
                    var library = LibraryLookup.GetLibrary(libraryName);

                    if (library == null)
                    {
                        Logger.Error("Invalid library name specified");
                    }

                    decompiler.Library = library;
                }

                decompiler.OmitUnusedFunctions = messageScriptOptions.OmitUnusedFunctions.GetValueOrDefault(decompiler.OmitUnusedFunctions);
                decompiler.Decompile(script);
            }
        }))
        {
            return false;
        }


        var outFormat = GetOutputFileFormatFromMessageScriptVersion(script.FormatVersion);
        if (outFormat != OutputFileFormat.None)
            Logger.Info($"MessageScript version {outFormat} decompiled.");

        return true;
    }

    private static bool TryDoDiff()
    {
        switch (Options.InputFileFormat)
        {
            case InputFileFormat.FlowScriptTextSource:
            case InputFileFormat.FlowScriptAssemblerSource:
            case InputFileFormat.MessageScriptTextSource:
                Logger.Error("Can't diff a text source!");
                return false;
            case InputFileFormat.FlowScriptBinary:
                return TryDoFlowScriptDiff(
                    Options.InputFilePath,
                    Options.LibraryName,
                    Options.FlowScript,
                    Options.MessageScript);
            case InputFileFormat.MessageScriptBinary:
                return TryDoMessageScriptDiff();
            default:
                Logger.Error("Invalid input file format!");
                return false;
        }
    }

    private static bool TryDoFlowScriptDiff(string inputFilePath, string libraryName, FlowScriptOptions flowScriptOptions, MessageScriptOptions messageScriptOptions)
    {
        var bfFilePath = inputFilePath;
        var flowAsmFilePath = inputFilePath + ".flowasm";
        var flowFilePath = inputFilePath + ".flow";
        var newBfFilePath = flowFilePath + ".bf";
        var newFlowAsmFilePath = newBfFilePath + ".flowasm";
        var newFlowFilePath = newBfFilePath + ".flow";

        if (!TryDoFlowScriptDisassembly(bfFilePath, flowAsmFilePath, outputInstructionIndices: false))
            return false;
        if (!TryDoFlowScriptDecompilation(bfFilePath, flowFilePath, libraryName, flowScriptOptions, messageScriptOptions, out var outputFileFormat))
            return false;
        if (!TryDoFlowScriptCompilation(flowFilePath, newBfFilePath, outputFileFormat, libraryName, flowScriptOptions, messageScriptOptions))
            return false;
        if (!TryDoFlowScriptDisassembly(newBfFilePath, newFlowAsmFilePath, outputInstructionIndices: false))
            return false;
        if (!TryDoFlowScriptDecompilation(newBfFilePath, newFlowFilePath, libraryName, flowScriptOptions, messageScriptOptions, out _))
            return false;

        return true;
    }

    private static bool TryDoMessageScriptDiff()
    {
        Logger.Error("Diffing message scripts not implemented.");
        return false;
    }

    private static bool TryDoDisassembling()
    {
        switch (Options.InputFileFormat)
        {
            case InputFileFormat.FlowScriptTextSource:
            case InputFileFormat.FlowScriptAssemblerSource:
            case InputFileFormat.MessageScriptTextSource:
                Logger.Error("Can't disassemble a text source!");
                return false;

            case InputFileFormat.FlowScriptBinary:
                return TryDoFlowScriptDisassembly(Options.InputFilePath, Options.OutputFilePath);

            case InputFileFormat.MessageScriptBinary:
                Logger.Info("Error. Disassembling message scripts is not supported.");
                return false;

            default:
                Logger.Error("Invalid input file format!");
                return false;
        }
    }

    private static bool TryDoFlowScriptDisassembly(string inputFilePath, string outputFilePath, 
        bool? outputInstructionIndices = default)
    {
        // load binary file
        Logger.Info("Loading binary FlowScript file...");

        FlowScriptBinary script = null;
        if (!TryPerformAction("Failed to load flow script from file.", () =>
        {
            script = FlowScriptBinary.FromFile(inputFilePath);
        }))
        {
            return false;
        }

        Logger.Info("Disassembling FlowScript...");
        if (!TryPerformAction("Failed to disassemble flow script to file.", () =>
        {
            var disassembler = new FlowScriptBinaryDisassembler(outputFilePath);
            if (outputInstructionIndices.HasValue)
                disassembler.OutputInstructionIndices = outputInstructionIndices.Value;
            disassembler.Disassemble(script);
            disassembler.Dispose();
        }))
        {
            return false;
        }

        return true;
    }

    private static bool TryPerformAction(string errorMessage, Action action)
    {
#if !DEBUG
        try
        {
#endif
        action();
#if !DEBUG
        }
        catch ( Exception e )
        {
            LogException( errorMessage, e );
            return false;
        }
#endif

        return true;
    }

    private static void LogException(string message, Exception e)
    {
        Logger.Error(message);
        Logger.Error("Exception info:");
        Logger.Error($"{e.Message}");
        Logger.Error("Stacktrace:");
        Logger.Error($"{e.StackTrace}");
        Logger.Error($"Version info:");
        Logger.Error($"AtlusScriptCompiler {Version.Major}.{Version.Minor}-{ThisAssembly.Git.Commit} ({ThisAssembly.Git.CommitDate})");
    }

    private static bool UEWrapperHandler()
    {
        bool success = false;
        using (var unwrapper = File.Open(Options.InputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            UEWrapper.UnwrapAsset(
                Path.GetDirectoryName(Options.InputFilePath), 
                Path.GetFileNameWithoutExtension(Options.InputFilePath), 
                GetInputFileExtensionByFileFormat(Options.InputFileFormat, Options.MessageScript.BinaryVariant), 
                unwrapper, 
                out var outName);
            Options.InputFilePath = outName;
            Options.OutputFilePath = Options.InputFilePath + GetOutputFileExtensionByFileFormat(Options.InputFileFormat, Options.MessageScript.BinaryVariant, Options.DoDecompile);
            Logger.Info($"Input file path is set to {Options.InputFilePath}");
            Logger.Info($"Output file path is set to {Options.OutputFilePath}");
}
        return success;
    }

    private static string GetInputFileExtensionByFileFormat(InputFileFormat inputFileFormat, MessageScriptBinaryVariant messageScriptBinaryVariant)
    {
        switch (inputFileFormat)
        {
            case InputFileFormat.FlowScriptBinary:
                return ".bf";
            case InputFileFormat.MessageScriptBinary:
                if (messageScriptBinaryVariant == MessageScriptBinaryVariant.BMD)
                    return ".bmd";
                else if (messageScriptBinaryVariant == MessageScriptBinaryVariant.BM2)
                    return ".bm2";
                else goto default;
            default:
                throw new Exception("Couldn't determine an input file extension");
        }
    }

    private static string GetOutputFileExtensionByFileFormat(InputFileFormat inputFileFormat, MessageScriptBinaryVariant messageScriptBinaryVariant, bool doDecompile)
    {
        switch (inputFileFormat)
        {
            case InputFileFormat.FlowScriptTextSource:
            case InputFileFormat.FlowScriptAssemblerSource:
                return ".bf";
            case InputFileFormat.MessageScriptTextSource:
                if (messageScriptBinaryVariant == MessageScriptBinaryVariant.BMD)
                    return ".bmd";
                else if (messageScriptBinaryVariant == MessageScriptBinaryVariant.BM2)
                    return ".bm2";
                else goto default;
            case InputFileFormat.FlowScriptBinary:
                if (doDecompile) return ".flow";
                return ".flowasm";
            case InputFileFormat.MessageScriptBinary:
                return ".msg";

            default:
                throw new Exception("Couldn't determine an output file extension");
        }
    }
}

public enum MessageScriptBinaryVariant
{
    BMD,
    BM2
}

public enum InputFileFormat
{
    None,
    FlowScriptBinary,
    FlowScriptTextSource,
    FlowScriptAssemblerSource,
    MessageScriptBinary,
    MessageScriptTextSource
}

public enum OutputFileFormat
{
    None,
    V1,
    V1DDS,
    V1BE,
    V1RE,
    V2,
    V2BE,
    V3,
    V3BE,
    V4,
    V4BE,
}