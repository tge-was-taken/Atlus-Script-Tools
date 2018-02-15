using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.Common.Registry;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Processing;
using AtlusScriptLib.FlowScriptLanguage.Syntax;
using AtlusScriptLib.MessageScriptLanguage;
using AtlusScriptLib.MessageScriptLanguage.Compiler;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler
{
    /// <summary>
    /// Represents the compiler for FlowScripts. Responsible for transforming FlowScript sources into code.
    /// </summary>
    public class FlowScriptCompiler
    {
        private static readonly Dictionary<ValueKind, ValueKind> sTypeToBaseTypeMap = new Dictionary<ValueKind, ValueKind>
        {
            { ValueKind.Bool, ValueKind.Int },
            { ValueKind.Int, ValueKind.Int },
            { ValueKind.Float, ValueKind.Float },
            { ValueKind.String, ValueKind.Int }
        };

        //
        // compiler state state
        //
        private readonly Logger mLogger;
        private readonly FormatVersion mFormatVersion;
        private readonly HashSet<int> mImportedFileHashSet;
        private bool mReresolveImports;
        private string mFilePath;
        private string mCurrentBaseDirectory;
        private FlowScript mScript;
        private int mNextLabelIndex;
        private Stack<ScopeContext> mScopeStack;
        private ScopeContext mRootScope;
        private Variable mIntReturnValueVariable;
        private Variable mFloatReturnValueVariable;

        // variable indices
        private short mNextIntVariableIndex;
        private short mNextFloatVariableIndex;
        private short mNextStaticIntVariableIndex = 255;   // We count the indices for the static variables *down* to
        private short mNextStaticFloatVariableIndex = 255; // reduce the chance of conflict with the game's original scripts
        private short mNextIntParameterVariableIndex;
        private short mNextFloatParameterVariableIndex;
        private short mNextAiLocalVariableIndex;
        private short mNextAiGlobalVariableIndex;

        //
        // procedure state
        //
        private ProcedureDeclaration mProcedureDeclaration;
        private List<Instruction> mInstructions;
        private Dictionary<string, Label> mLabels;

        private int mStackValueCount; // for debugging
        private IntrinsicSupport mInstrinsic;

        private ScopeContext Scope => mScopeStack.Peek();

        /// <summary>
        /// Gets or sets the encoding to use for any imported MessageScripts.
        /// </summary>
        public Encoding Encoding { get; set; }

        /// <summary>
        /// Gets or sets the library registry to use for any imported MessageScripts.
        /// </summary>
        public Library Library { get; set; }

        /// <summary>
        /// Gets or sets whether the compiler should output procedure tracing code.
        /// </summary>
        public bool EnableProcedureTracing { get; set; } = true;

        /// <summary>
        /// Gets or sets whether the compiler should output procedure call tracing code.
        /// </summary>
        public bool EnableProcedureCallTracing { get; set; }

        /// <summary>
        /// Gets or sets whether the compiler should output function call tracing code.
        /// </summary>
        public bool EnableFunctionCallTracing { get; set; }

        /// <summary>
        /// Gets or sets whether the compiler should use stack cookies
        /// </summary>
        public bool EnableStackCookie { get; set; }

        /// <summary>
        /// Initializes a FlowScript compiler with the given format version.
        /// </summary>
        /// <param name="version"></param>
        public FlowScriptCompiler( FormatVersion version )
        {
            mLogger = new Logger( nameof( FlowScriptCompiler ) );
            mFormatVersion = version;
            mImportedFileHashSet = new HashSet<int>();
        }

        /// <summary>
        /// Adds a compiler log listener. Use this if you want to see what went wrong during compilation.
        /// </summary>
        /// <param name="listener">The listener to add.</param>
        public void AddListener( LogListener listener )
        {
            listener.Subscribe( mLogger );
        }

        /// <summary>
        /// Tries to compile the provided FlowScript source. Returns a boolean indicating if the operation succeeded.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="flowScript"></param>
        /// <returns></returns>
        public bool TryCompile( string source, out FlowScript flowScript )
        {
            Info( "Start compiling FlowScript from source" );

            // Add source to prevent recursion
            mImportedFileHashSet.Add( source.GetHashCode() );

            // Parse compilation unit
            var parser = new CompilationUnitParser();
            parser.AddListener( new LoggerPassthroughListener( mLogger ) );
            if ( !parser.TryParse( source, out var compilationUnit ) )
            {
                Error( "Failed to parse compilation unit" );
                flowScript = null;
                return false;
            }

            return TryCompile( compilationUnit, out flowScript );
        }

        /// <summary>
        /// Tries to compile the provided FlowScript source. Returns a boolean indicating if the operation succeeded.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="flowScript"></param>
        /// <returns></returns>
        public bool TryCompile( Stream stream, out FlowScript flowScript )
        {
            if ( stream is FileStream fileStream )
            {
                mFilePath = Path.GetFullPath( fileStream.Name );
                mCurrentBaseDirectory = Path.GetDirectoryName( mFilePath );
                Info( $"Start compiling FlowScript from file '{mFilePath}'" );
                Info( $"Base directory set to '{mCurrentBaseDirectory}'" );
            }
            else
            {
                Info( "Start compiling FlowScript from stream" );
                Warning( "Because the input is not a file, this means imports will not work!" );
            }

            // Add hash for current file
            var hashAlgo = new MD5CryptoServiceProvider();
            var hashBytes = hashAlgo.ComputeHash( stream );
            int hashInt = BitConverter.ToInt32( hashBytes, 0 );
            mImportedFileHashSet.Add( hashInt );
            stream.Position = 0;

            // Parse compilation unit
            var parser = new CompilationUnitParser();
            parser.AddListener( new LoggerPassthroughListener( mLogger ) );
            if ( !parser.TryParse( stream, out var compilationUnit ) )
            {
                Error( "Failed to parse compilation unit" );
                flowScript = null;
                return false;
            }

            return TryCompile( compilationUnit, out flowScript );
        }

        /// <summary>
        /// Tries to compile the provided FlowScript source. Returns a boolean indicating if the operation succeeded.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="flowScript"></param>
        /// <returns></returns>
        public bool TryCompile( CompilationUnit compilationUnit, out FlowScript flowScript )
        {
            // Resolve types that are unresolved at parse time
            var resolver = new TypeResolver();
            resolver.AddListener( new LoggerPassthroughListener( mLogger ) );
            if ( !resolver.TryResolveTypes( compilationUnit ) )
            {
                Error( "Failed to resolve types in compilation unit" );
                flowScript = null;
                return false;
            }

            // Syntax checker?

            // Compile compilation unit
            if ( !TryCompileCompilationUnit( compilationUnit ) )
            {
                flowScript = null;
                return false;
            }

            flowScript = mScript;

            return true;
        }

        //
        // Compiling compilation units
        //
        private void InitializeCompilationState()
        {
            // todo: imports?
            mScript = new FlowScript( mFormatVersion );
            mNextLabelIndex = 0;

            // Set up scope stack
            mScopeStack = new Stack<ScopeContext>();

            // Create & push root scope
            // This is where all script-level declarations are stored
            mRootScope = new ScopeContext( null );
            mScopeStack.Push( mRootScope );

            mInstrinsic = new IntrinsicSupport( Library );
            if ( !mInstrinsic.SupportsTrace )
            {
                Warning( "Tracing is not supported by the specified library; it will be disabled for the current compilation" );
                EnableFunctionCallTracing = EnableProcedureCallTracing = EnableProcedureTracing = EnableStackCookie = false;
            }
        }

        private bool TryCompileCompilationUnit( CompilationUnit compilationUnit )
        {
            Info( $"Start compiling FlowScript compilation unit with version {mFormatVersion}" );

            // Initialize
            InitializeCompilationState();

            // Resolve imports
            if ( compilationUnit.Imports.Count > 0 )
            {
                do
                {
                    if ( !TryResolveImports( compilationUnit ) )
                    {
                        Error( compilationUnit, "Failed to resolve imports" );
                        return false;
                    }
                } while ( mReresolveImports );
            }

            // Evaluate declarations, return values, parameters etc
            if ( !TryEvaluateCompilationUnitBeforeCompilation( compilationUnit ) )
                return false;

            // Compile compilation unit body
            foreach ( var statement in compilationUnit.Declarations )
            {
                if ( statement is ProcedureDeclaration procedureDeclaration )
                {
                    if ( procedureDeclaration.Body != null )
                    {
                        if ( !TryCompileProcedure( procedureDeclaration, out var procedure ) )
                            return false;

                        mScript.Procedures.Add( procedure );
                    }
                }
                else if ( statement is VariableDeclaration variableDeclaration )
                {
                    if ( variableDeclaration.Initializer != null && ( variableDeclaration.Modifier != null && variableDeclaration.Modifier.Kind != VariableModifierKind.Constant ) )
                    {
                        Error( variableDeclaration.Initializer, "Non-constant variables declared outside of a procedure can't be initialized with a value" );
                        return false;
                    }
                }
                else if ( !( statement is FunctionDeclaration ) && !( statement is EnumDeclaration ) )
                {
                    Error( statement, $"Unexpected top-level statement type: {statement}" );
                    return false;
                }
            }

            Info( "Done compiling compilation unit" );

            return true;
        }

        private void ExpandImportStatementsPaths( CompilationUnit compilationUnit, string baseDirectory )
        {
            foreach ( var import in compilationUnit.Imports )
            {
                import.CompilationUnitFileName = Path.Combine( baseDirectory, import.CompilationUnitFileName );
            }
        }

        //
        // Resolving imports
        //
        private bool TryResolveImports( CompilationUnit compilationUnit )
        {
            Info( compilationUnit, "Resolving imports" );

            ExpandImportStatementsPaths( compilationUnit, Path.GetDirectoryName( mFilePath ) );

            var importedMessageScripts = new List<MessageScript>();
            var importedFlowScripts = new List<CompilationUnit>();

            foreach ( var import in compilationUnit.Imports )
            {
                if ( import.CompilationUnitFileName.EndsWith( ".msg" ) )
                {
                    // MessageScript
                    if ( !TryResolveMessageScriptImport( import, out var messageScript ) )
                    {
                        Error( import, $"Failed to resolve MessageScript import: { import.CompilationUnitFileName }" );
                        return false;
                    }

                    // Will be null if it was already imported before
                    if ( messageScript != null )
                        importedMessageScripts.Add( messageScript );
                }
                else if ( import.CompilationUnitFileName.EndsWith( ".flow" ) )
                {
                    // FlowScript
                    if ( !TryResolveFlowScriptImport( import, out var importedCompilationUnit ) )
                    {
                        Error( import, $"Failed to resolve FlowScript import: { import.CompilationUnitFileName }" );
                        return false;
                    }

                    // Will be null if it was already imported before
                    if ( importedCompilationUnit != null )
                        importedFlowScripts.Add( importedCompilationUnit );
                }
                else
                {
                    // Unknown
                    Error( import, $"Unknown import file type: {import.CompilationUnitFileName}" );
                    return false;
                }
            }

            // Resolve MessageScripts imports
            if ( importedMessageScripts.Count > 0 )
            {
                int startIndex = 0;
                if ( mScript.MessageScript == null )
                {
                    mScript.MessageScript = importedMessageScripts[ 0 ];
                    startIndex = 1;
                }

                // Merge message scripts
                for ( int i = startIndex; i < importedMessageScripts.Count; i++ )
                {
                    mScript.MessageScript.Dialogs.AddRange( importedMessageScripts[i].Dialogs );
                }
            }

            // Resolve FlowScript imports
            bool shouldReresolveImports = false;
            if ( importedFlowScripts.Count > 0 )
            {
                // Merge compilation units
                foreach ( var importedFlowScript in importedFlowScripts )
                {
                    if ( importedFlowScript.Imports.Count > 0 )
                    {
                        // If any of the imported FlowScripts have import, we have to re-resolve the imports again
                        shouldReresolveImports = true;
                        compilationUnit.Imports.AddRange( importedFlowScript.Imports );
                    }

                    compilationUnit.Declarations.AddRange( importedFlowScript.Declarations );
                }
            }

            mReresolveImports = shouldReresolveImports;

            if ( !mReresolveImports )
                Info( compilationUnit, "Done resolving imports" );

            return true;
        }

        private bool TryResolveMessageScriptImport( Import import, out MessageScript messageScript )
        {
            Info( $"Resolving MessageScript import '{import.CompilationUnitFileName}'" );

            var messageScriptCompiler = new MessageScriptCompiler( GetMessageScriptFormatVersion(), Encoding );
            messageScriptCompiler.AddListener( new LoggerPassthroughListener( mLogger ) );
            messageScriptCompiler.Library = Library;

            string compilationUnitFilePath = import.CompilationUnitFileName;

            if ( !File.Exists( compilationUnitFilePath ) )
            {
                // Retry as relative path if we have a filename
                if ( mFilePath != null )
                {
                    compilationUnitFilePath = Path.Combine( mCurrentBaseDirectory, compilationUnitFilePath );

                    if ( !File.Exists( compilationUnitFilePath ) )
                    {
                        Error( import, $"MessageScript file to import does not exist: {import.CompilationUnitFileName}" );
                        messageScript = null;
                        return false;
                    }
                }
                else
                {
                    Error( import, $"MessageScript file to import does not exist: {import.CompilationUnitFileName}" );
                    messageScript = null;
                    return false;
                }
            }

            Info( $"Importing MessageScript from file '{compilationUnitFilePath}'" );

            string messageScriptSource;

            try
            {
                messageScriptSource = File.ReadAllText( compilationUnitFilePath );
            }
            catch ( Exception )
            {
                Error( import, $"Can't open MessageScript file to import: {import.CompilationUnitFileName}" );
                messageScript = null;
                return false;
            }

            int messageScriptSourceHash = messageScriptSource.GetHashCode();

            if ( !mImportedFileHashSet.Contains( messageScriptSourceHash ) )
            {
                if ( !messageScriptCompiler.TryCompile( messageScriptSource, out messageScript ) )
                {
                    Error( import, $"Import MessageScript failed to compile: {import.CompilationUnitFileName}" );
                    return false;
                }

                mImportedFileHashSet.Add( messageScriptSourceHash );
            }
            else
            {
                Warning( $"MessageScript file '{compilationUnitFilePath}' was already included once! Skipping!" );
                messageScript = null;
            }

            return true;
        }

        private bool TryResolveFlowScriptImport( Import import, out CompilationUnit importedCompilationUnit )
        {
            string compilationUnitFilePath = import.CompilationUnitFileName;
            Info( $"Resolving FlowScript import '{compilationUnitFilePath}'" );

            if ( !File.Exists( compilationUnitFilePath ) )
            {
                // Retry as relative path if we have a filename
                if ( mFilePath != null )
                {
                    compilationUnitFilePath = Path.Combine( Path.GetDirectoryName(mFilePath), compilationUnitFilePath );

                    if ( !File.Exists( compilationUnitFilePath ) )
                    {
                        Error( import, $"FlowScript file to import does not exist: {import.CompilationUnitFileName}" );
                        importedCompilationUnit = null;
                        return false;
                    }
                }
                else
                {
                    Error( import, $"FlowScript file to import does not exist: {import.CompilationUnitFileName}" );
                    importedCompilationUnit = null;
                    return false;
                }
            }

            Info( $"Importing FlowScript from file '{compilationUnitFilePath}'" );
            FileStream flowScriptFileStream;
            try
            {
                flowScriptFileStream = File.Open( compilationUnitFilePath, FileMode.Open, FileAccess.Read, FileShare.Read );
            }
            catch ( Exception )
            {
                Error( import, $"Can't open FlowScript file to import: {import.CompilationUnitFileName}" );
                importedCompilationUnit = null;
                return false;
            }

            var hashAlgo = new MD5CryptoServiceProvider();
            var hashBytes = hashAlgo.ComputeHash( flowScriptFileStream );
            int flowScriptSourceHash = BitConverter.ToInt32( hashBytes, 0 );
            flowScriptFileStream.Position = 0;

            if ( !mImportedFileHashSet.Contains( flowScriptSourceHash ) )
            {
                var parser = new CompilationUnitParser();
                parser.AddListener( new LoggerPassthroughListener( mLogger ) );
                if ( !parser.TryParse( flowScriptFileStream, out importedCompilationUnit ) )
                {
                    Error( import, "Failed to parse imported FlowScript" );
                    return false;
                }

                flowScriptFileStream.Dispose();

                ExpandImportStatementsPaths( importedCompilationUnit, Path.GetDirectoryName( compilationUnitFilePath ) );

                mImportedFileHashSet.Add( flowScriptSourceHash );
            }
            else
            {
                Warning( $"FlowScript file '{compilationUnitFilePath}' was already included once! Skipping!" );
                importedCompilationUnit = null;
            }

            return true;
        }

        private MessageScriptLanguage.FormatVersion GetMessageScriptFormatVersion()
        {
            switch ( mFormatVersion )
            {
                case FormatVersion.Version1:
                case FormatVersion.Version2:
                case FormatVersion.Version3:
                    return MessageScriptLanguage.FormatVersion.Version1;
                case FormatVersion.Version1BigEndian:
                case FormatVersion.Version2BigEndian:
                case FormatVersion.Version3BigEndian:
                    return MessageScriptLanguage.FormatVersion.Version1BigEndian;
            }

            return MessageScriptLanguage.FormatVersion.Version1;
        }

        private bool TryEvaluateCompilationUnitBeforeCompilation( CompilationUnit compilationUnit )
        {
            // Declare constants for the message script window names
            if ( mScript.MessageScript != null )
            {
                Info( "Inserting MessageScript window identifier constants" );
                for ( int i = 0; i < mScript.MessageScript.Dialogs.Count; i++ )
                {
                    var dialog = mScript.MessageScript.Dialogs[i];

                    var declaration = new VariableDeclaration
                    (
                        new VariableModifier( VariableModifierKind.Constant ),
                        new TypeIdentifier( ValueKind.Int ),
                        new Identifier( ValueKind.Int, dialog.Name ),
                        new IntLiteral( i )
                    );

                    if ( !Scope.TryDeclareVariable( declaration ) )
                    {
                        Error( declaration, $"Compiler generated constant for MessageScript dialog {dialog.Name} conflicts with another variable" );
                    }
                    else
                    {
                        Info( $"Declared compile time constant: {declaration}" );
                    }
                }
            }

            bool hasIntReturnValue = false;
            bool hasFloatReturnValue = false;
            short maxIntParameterCount = 0;
            short maxFloatParameterCount = 0;

            // top-level only
            Trace( "Registering script declarations" );
            foreach ( var statement in compilationUnit.Declarations )
            {
                switch ( statement )
                {
                    case FunctionDeclaration functionDeclaration:
                        {
                            if ( !Scope.TryDeclareFunction( functionDeclaration ) )
                            {
                                Warning( functionDeclaration, $"Ignoring duplicate function declaration: {functionDeclaration}" );
                            }
                            else
                            {
                                Trace( $"Registered function declaration '{functionDeclaration}'" );
                            }
                        }
                        break;
                    case ProcedureDeclaration procedureDeclaration:
                        {
                            if ( !Scope.TryDeclareProcedure( procedureDeclaration ) )
                            {
                                Error( procedureDeclaration, $"Duplicate procedure declaration: {procedureDeclaration}" );
                                return false;
                            }
                            Trace( $"Registered procedure declaration '{procedureDeclaration}'" );

                            if ( procedureDeclaration.ReturnType.ValueKind != ValueKind.Void )
                            {
                                if ( sTypeToBaseTypeMap[procedureDeclaration.ReturnType.ValueKind] == ValueKind.Int )
                                {
                                    hasIntReturnValue = true;
                                }
                                else if ( procedureDeclaration.ReturnType.ValueKind == ValueKind.Float )
                                {
                                    hasFloatReturnValue = true;
                                }
                            }

                            short intParameterCount = ( short )procedureDeclaration.Parameters.Count( x => sTypeToBaseTypeMap[x.Type.ValueKind] == ValueKind.Int );
                            short floatParameterCount = ( short )procedureDeclaration.Parameters.Count( x => sTypeToBaseTypeMap[x.Type.ValueKind] == ValueKind.Float );
                            maxIntParameterCount = Math.Max( intParameterCount, maxIntParameterCount );
                            maxFloatParameterCount = Math.Max( floatParameterCount, maxFloatParameterCount );
                        }
                        break;

                    case VariableDeclaration variableDeclaration:
                        {
                            if ( !TryRegisterVariableDeclaration( variableDeclaration ) )
                            {
                                Error( variableDeclaration, $"Duplicate variable declaration: {variableDeclaration}" );
                                return false;
                            }
                            Trace( $"Registered variable declaration '{variableDeclaration}'" );
                        }
                        break;

                    case EnumDeclaration enumDeclaration:
                        {
                            if ( !Scope.TryDeclareEnum( enumDeclaration ) )
                            {
                                Error( enumDeclaration, $"Failed to declare enum: {enumDeclaration}" );
                                return false;
                            }
                        }
                        break;
                }
            }

            // Add stuff from registry
            if ( Library != null )
            {
                // Functions
                foreach ( var libraryFunction in Library.FlowScriptModules.SelectMany( x => x.Functions ) )
                {
                    Scope.TryDeclareFunction( FunctionDeclaration.FromLibraryFunction( libraryFunction ) );
                }

                // Enums
                foreach ( var libraryEnum in Library.FlowScriptModules
                                                            .Where( x => x.Enums != null )
                                                            .SelectMany( x => x.Enums ) )
                {
                    Scope.TryDeclareEnum( EnumDeclaration.FromLibraryEnum( libraryEnum ) );
                }

                // Constants
                foreach ( var libraryConstant in Library.FlowScriptModules
                                                            .Where( x => x.Constants != null )
                                                            .SelectMany( x => x.Constants ) )
                {
                    Scope.TryDeclareVariable( VariableDeclaration.FromLibraryConstant( libraryConstant ) );
                }
            }

            // Declare return value variable
            if ( hasIntReturnValue )
            {
                mIntReturnValueVariable = Scope.GenerateVariable( ValueKind.Int, mNextIntVariableIndex++ );
            }

            if ( hasFloatReturnValue )
            {
                mFloatReturnValueVariable = Scope.GenerateVariable( ValueKind.Float, mNextFloatVariableIndex++ );
            }


            // Set up indices
            mNextIntParameterVariableIndex = mNextIntVariableIndex;
            mNextIntVariableIndex += maxIntParameterCount;

            mNextFloatParameterVariableIndex = mNextFloatVariableIndex;
            mNextFloatVariableIndex += maxFloatParameterCount;

            return true;
        }

        //
        // Procedure code generation
        //
        private void InitializeProcedureCompilationState( ProcedureDeclaration declaration )
        {
            mProcedureDeclaration = declaration;
            mInstructions = new List<Instruction>();
            mLabels = new Dictionary<string, Label>();
            mStackValueCount = 1;
        }

        private bool TryCompileProcedure( ProcedureDeclaration declaration, out FlowScriptLanguage.Procedure procedure )
        {
            Info( declaration, $"Compiling procedure: {declaration.Identifier.Text}" );

            // Initialize procedure to null so we can return without having to set it explicitly
            procedure = null;

            // Compile procedure body
            if ( !TryEmitProcedureBody( declaration ) )
                return false;

            // Create labels
            if ( !TryResolveProcedureLabels( out var labels ) )
                return false;

            // Create the procedure object
            procedure = new FlowScriptLanguage.Procedure( declaration.Identifier.Text, mInstructions, labels );

            return true;
        }

        private bool TryEmitProcedureBody( ProcedureDeclaration declaration )
        {
            Trace( declaration.Body, $"Emitting procedure body for {declaration}" );

            var startIntParameterVariableIndex = mNextIntParameterVariableIndex;
            var startFloatParameterVariableIndex = mNextFloatParameterVariableIndex;

            // Initialize some state
            InitializeProcedureCompilationState( declaration );

            // Emit procedure start  
            PushScope();
            Emit( Instruction.PROC( mRootScope.Procedures[declaration.Identifier.Text].Index ) );

            if ( EnableProcedureTracing )
                TraceProcedureStart();

            if ( EnableStackCookie )
            {
                // Emit stack cookie
                Emit( Instruction.PUSHI( declaration.Identifier.Text.GetHashCode() ) );
            }

            // Register / forward declare labels in procedure body before codegen
            Trace( declaration.Body, "Forward declaring labels in procedure body" );
            if ( !TryRegisterLabels( declaration.Body ) )
            {
                Error( declaration.Body, "Failed to forward declare labels in procedure body" );
                return false;
            }

            // Emit procedure parameters
            if ( declaration.Parameters.Count > 0 )
            {
                Trace( declaration, "Emitting code for procedure parameters" );
                if ( !TryEmitProcedureParameters( declaration.Parameters ) )
                {
                    Error( declaration, "Failed to emit procedure parameters" );
                    return false;
                }
            }

            ReturnStatement returnStatement = new ReturnStatement();

            // Remove last return statement
            if ( declaration.Body.Statements.Count != 0 && declaration.Body.Statements.Last() is ReturnStatement )
            {
                returnStatement = ( ReturnStatement ) declaration.Body.Last();
                declaration.Body.Statements.Remove( returnStatement );
            }

            // Emit procedure body
            Trace( declaration.Body, "Emitting code for procedure body" );
            if ( !TryEmitCompoundStatement( declaration.Body ) )
            {
                Error( declaration.Body, "Failed to emit procedure body" );
                return false;
            }

            // Assign out parameters
            if ( declaration.Parameters.Count > 0 )
            {
                var intVariableCount = 0;
                var floatVariableCount = 0;

                foreach ( var parameter in declaration.Parameters )
                {
                    Scope.TryGetVariable( parameter.Identifier.Text, out var variable );

                    if ( sTypeToBaseTypeMap[ parameter.Type.ValueKind ] == ValueKind.Int )
                    {
                        if ( parameter.Modifier == ParameterModifier.Out )
                        {
                            Emit( Instruction.PUSHLIX( variable.Index ) );
                            Emit( Instruction.POPLIX( ( short )( startIntParameterVariableIndex + intVariableCount ) ) );
                        }

                        ++intVariableCount;
                    }
                    else
                    {
                        if ( parameter.Modifier == ParameterModifier.Out )
                        {
                            Emit( Instruction.PUSHLFX( variable.Index ) );
                            Emit( Instruction.POPLFX( ( short )( startFloatParameterVariableIndex + floatVariableCount ) ) );
                        }

                        ++floatVariableCount;
                    }   
                }
            }

            if ( !TryEmitReturnStatement( returnStatement ) )
            {
                return false;
            }

            PopScope();

            return true;
        }

        private bool TryEmitProcedureParameters( List<Parameter> parameters )
        {
            int intParameterCount = 0;
            int floatParameterCount = 0;

            foreach ( var parameter in parameters )
            {
                Trace( parameter, $"Emitting parameter: {parameter}" );

                // Create declaration
                var declaration = new VariableDeclaration(
                    new VariableModifier( VariableModifierKind.Local ),
                    parameter.Type,
                    parameter.Identifier,
                    null );

                // Declare variable
                if ( !TryEmitVariableDeclaration( declaration ) )
                    return false;

                // Push parameter value
                if ( sTypeToBaseTypeMap[declaration.Type.ValueKind] == ValueKind.Int )
                {
                    if ( parameter.Modifier != ParameterModifier.Out )
                        Emit( Instruction.PUSHLIX( mNextIntParameterVariableIndex ) );

                    ++mNextIntParameterVariableIndex;
                    ++intParameterCount;
                }
                else
                {
                    if ( parameter.Modifier != ParameterModifier.Out )
                        Emit( Instruction.PUSHLFX( mNextFloatParameterVariableIndex ) );

                    ++mNextFloatParameterVariableIndex;
                    ++floatParameterCount;
                }

                if ( parameter.Modifier != ParameterModifier.Out )
                {
                    // Assign it with parameter value
                    if ( !TryEmitVariableAssignment( declaration.Identifier ) )
                        return false;
                }
            }

            // Reset parameter indices
            mNextIntParameterVariableIndex -= ( short )intParameterCount;
            mNextFloatParameterVariableIndex -= ( short )floatParameterCount;

            return true;
        }

        private bool TryRegisterLabels( CompoundStatement body )
        {
            foreach ( var declaration in body.Select( x => x as Declaration ).Where( x => x != null ) )
            {
                if ( declaration.DeclarationType == DeclarationType.Label )
                {
                    mLabels[declaration.Identifier.Text] = CreateLabel( declaration.Identifier.Text );
                }
            }

            foreach ( var statement in body )
            {
                switch ( statement )
                {
                    case IfStatement ifStatement:
                        if ( !TryRegisterLabels( ifStatement.Body ) )
                            return false;

                        if ( ifStatement.ElseBody != null )
                        {
                            if ( !TryRegisterLabels( ifStatement.ElseBody ) )
                                return false;
                        }
                        break;

                    default:
                        break;
                }
            }

            return true;
        }

        private bool TryResolveProcedureLabels( out List<FlowScriptLanguage.Label> labels )
        {
            Trace( "Resolving labels in procedure" );
            if ( mLabels.Values.Any( x => !x.IsResolved ) )
            {
                foreach ( var item in mLabels.Values.Where( x => !x.IsResolved ) )
                    mLogger.Error( $"Label '{item.Name}' is referenced but not declared" );

                mLogger.Error( "Failed to compile procedure because one or more undeclared labels are referenced" );
                labels = null;
                return false;
            }

            labels = mLabels.Values
                .Select( x => new FlowScriptLanguage.Label( x.Name, x.InstructionIndex ) )
                .ToList();

            mLabels.Clear();
            return true;
        }

        //
        // Statements
        //
        private bool TryEmitStatements( IEnumerable<Statement> statements )
        {
            foreach ( var statement in statements )
            {
                if ( !TryEmitStatement( statement ) )
                    return false;
            }

            return true;
        }

        private bool TryEmitCompoundStatement( CompoundStatement compoundStatement )
        {
            PushScope();

            if ( !TryEmitStatements( compoundStatement ) )
                return false;

            PopScope();

            return true;
        }

        private bool TryEmitStatement( Statement statement )
        {
            switch ( statement )
            {
                case CompoundStatement compoundStatement:
                    if ( !TryEmitCompoundStatement( compoundStatement ) )
                        return false;
                    break;
                case Declaration _:
                    {
                        if ( statement is VariableDeclaration variableDeclaration )
                        {
                            if ( !TryEmitVariableDeclaration( variableDeclaration ) )
                                return false;
                        }
                        else if ( statement is LabelDeclaration labelDeclaration )
                        {
                            if ( !TryRegisterLabelDeclaration( labelDeclaration ) )
                                return false;
                        }
                        else
                        {
                            Error( statement, "Expected variable or label declaration" );
                            return false;
                        }

                        break;
                    }

                case Expression expression:
                    if ( !TryEmitExpression( expression, true ) )
                        return false;
                    break;
                case IfStatement ifStatement:
                    if ( !TryEmitIfStatement( ifStatement ) )
                        return false;
                    break;
                case ForStatement forStatement:
                    if ( !TryEmitForStatement( forStatement ) )
                        return false;
                    break;
                case WhileStatement whileStatement:
                    if ( !TryEmitWhileStatement( whileStatement ) )
                        return false;
                    break;
                case BreakStatement breakStatement:
                    if ( !TryEmitBreakStatement( breakStatement ) )
                        return false;
                    break;
                case ContinueStatement continueStatement:
                    if ( !TryEmitContinueStatement( continueStatement ) )
                        return false;
                    break;
                case ReturnStatement returnStatement:
                    if ( !TryEmitReturnStatement( returnStatement ) )
                    {
                        Error( returnStatement, $"Failed to compile return statement: {returnStatement}" );
                        return false;
                    }

                    break;
                case GotoStatement gotoStatement:
                    if ( !TryEmitGotoStatement( gotoStatement ) )
                    {
                        Error( gotoStatement, $"Failed to compile goto statement: {gotoStatement}" );
                        return false;
                    }

                    break;
                case SwitchStatement switchStatement:
                    if ( !TryEmitSwitchStatement( switchStatement ) )
                    {
                        Error( switchStatement, $"Failed to compile switch statement: {switchStatement}" );
                        return false;
                    }

                    break;
                default:
                    Error( statement, $"Compiling statement '{statement}' not implemented" );
                    return false;
            }

            return true;
        }

        //
        // Variable stuff
        //
        private bool TryGetVariableIndex( VariableDeclaration declaration, out short variableIndex )
        {
            if ( declaration.Modifier == null || declaration.Modifier.Kind == VariableModifierKind.Local )
            {
                // Local variable
                if ( declaration.Type.ValueKind == ValueKind.Float )
                {
                    variableIndex = mNextFloatVariableIndex++;
                }
                else
                {
                    variableIndex = mNextIntVariableIndex++;
                }
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.Global )
            {
                if ( declaration.Modifier.Index == null )
                {
                    // Static variable
                    // We count the indices for the static variables *down* to
                    // to reduce the chance we conflict with the game's original scripts
                    if ( declaration.Type.ValueKind == ValueKind.Float )
                    {
                        variableIndex = mNextStaticFloatVariableIndex--;
                    }
                    else
                    {
                        variableIndex = mNextStaticIntVariableIndex--;
                    }
                }
                else
                {
                    variableIndex = ( short )declaration.Modifier.Index.Value;
                }
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.Constant )
            {
                // Constant
                variableIndex = -1;
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.AiLocal )
            {
                if ( !mInstrinsic.SupportsAiLocal )
                {
                    Error( declaration.Modifier, "ai_local modifier is not supported by the specified library" );
                    variableIndex = -1;
                    return false;
                }

                if ( declaration.Modifier.Index == null )
                    variableIndex = mNextAiLocalVariableIndex++;
                else
                    variableIndex = ( short ) declaration.Modifier.Index.Value;
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.AiGlobal )
            {
                if ( !mInstrinsic.SupportsAiGlobal )
                {
                    Error( declaration.Modifier, "ai_global modifier is not supported by the specified library" );
                    variableIndex = -1;
                    return false;
                }

                if ( declaration.Modifier.Index == null )
                    variableIndex = mNextAiGlobalVariableIndex++;
                else
                    variableIndex = ( short ) declaration.Modifier.Index.Value;
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.Bit )
            {
                if ( !mInstrinsic.SupportsBit )
                {
                    Error( declaration.Modifier, "bit modifier is not supported by the specified library" );
                    variableIndex = -1;
                    return false;
                }

                variableIndex = ( short )declaration.Modifier.Index.Value;
            }
            else
            {
                Error( declaration.Modifier, $"Unexpected variable modifier: {declaration.Modifier}" );
                variableIndex = -1;
                return false;
            }

            return true;
        }

        private bool TryRegisterVariableDeclaration( VariableDeclaration declaration )
        {
            Trace( declaration, $"Registering variable declaration: {declaration}" );

            // Get variable idnex
            if ( !TryGetVariableIndex( declaration, out var variableIndex ) )
            {
                Error( declaration, $"Failed to get index for variable '{declaration}'" );
                return false;
            }

            // Declare variable in scope
            if ( !Scope.TryDeclareVariable( declaration, variableIndex ) )
            {
                Error( declaration, $"Variable '{declaration}' has already been declared" );
                return false;
            }

            return true;
        }

        private bool TryEmitVariableDeclaration( VariableDeclaration declaration )
        {
            Trace( declaration, $"Emitting variable declaration: {declaration}" );

            // Register variable
            if ( !TryRegisterVariableDeclaration( declaration ) )
            {
                Error( declaration, "Failed to register variable declaration" );
                return false;
            }

            // Nothing to emit for constants
            if ( declaration.Modifier.Kind == VariableModifierKind.Constant )
                return true;

            // Emit the variable initializer if it has one         
            if ( declaration.Initializer != null )
            {
                Trace( declaration.Initializer, "Emitting variable initializer" );

                if ( !TryEmitVariableAssignment( declaration.Identifier, declaration.Initializer, true ) )
                {
                    Error( declaration.Initializer, "Failed to emit code for variable initializer" );
                    return false;
                }
            }

            return true;
        }

        private bool TryRegisterLabelDeclaration( LabelDeclaration declaration )
        {
            Trace( declaration, $"Registering label declaration: {declaration}" );

            // register label
            if ( !mLabels.TryGetValue( declaration.Identifier.Text, out var label ) )
            {
                Error( declaration.Identifier, $"Unexpected declaration of an registered label: '{declaration}'" );
                return false;
            }

            ResolveLabel( label );

            return true;
        }

        //
        // Expressions
        //
        private bool TryEmitExpression( Expression expression, bool isStatement )
        {
            switch ( expression )
            {
                case MemberAccessExpression memberAccessExpression:
                    if ( isStatement )
                    {
                        Error( memberAccessExpression, "An identifier is an invalid statement" );
                        return false;
                    }

                    if ( !TryEmitMemberAccess( memberAccessExpression ) )
                        return false;
                    break;

                case CallOperator callExpression:
                    if ( !TryEmitCall( callExpression, isStatement ) )
                        return false;
                    break;
                case UnaryExpression unaryExpression:
                    if ( !TryEmitUnaryExpression( unaryExpression, isStatement ) )
                        return false;
                    break;
                case BinaryExpression binaryExpression:
                    if ( !TryEmitBinaryExpression( binaryExpression, isStatement ) )
                        return false;
                    break;
                case Identifier identifier:
                    if ( isStatement )
                    {
                        Error( identifier, "An identifier is an invalid statement" );
                        return false;
                    }

                    if ( !TryEmitPushVariableValue( identifier ) )
                        return false;
                    break;
                case BoolLiteral boolLiteral:
                    if ( isStatement )
                    {
                        Error( boolLiteral, "A boolean literal is an invalid statement" );
                        return false;
                    }

                    EmitPushBoolLiteral( boolLiteral );
                    break;
                case IntLiteral intLiteral:
                    if ( isStatement )
                    {
                        Error( intLiteral, "A integer literal is an invalid statement" );
                        return false;
                    }

                    EmitPushIntLiteral( intLiteral );
                    break;
                case FloatLiteral floatLiteral:
                    if ( isStatement )
                    {
                        Error( floatLiteral, "A float literal is an invalid statement" );
                        return false;
                    }

                    EmitPushFloatLiteral( floatLiteral );
                    break;
                case StringLiteral stringLiteral:
                    if ( isStatement )
                    {
                        Error( stringLiteral, "A string literal is an invalid statement" );
                        return false;
                    }

                    EmitPushStringLiteral( stringLiteral );
                    break;
                default:
                    Error( expression, $"Compiling expression '{expression}' not implemented" );
                    return false;
            }

            return true;
        }

        private bool TryEmitMemberAccess( MemberAccessExpression memberAccessExpression )
        {
            Trace( memberAccessExpression, $"Emitting member access '{memberAccessExpression}'" );

            if ( !Scope.TryGetEnum( memberAccessExpression.Operand.Text, out var enumType ) )
            {
                Error( $"Referenced undeclared enum '{memberAccessExpression.Operand.Text}'" );
                return false;
            }

            if ( !enumType.Members.TryGetValue( memberAccessExpression.Member.Text, out var value ) )
            {
                Error( $"Referenced undeclared enum member '{memberAccessExpression.Member.Text}' in enum '{memberAccessExpression.Operand.Text}'" );
                return false;
            }

            if ( !TryEmitExpression( value, false ) )
            {
                Error( $"Failed to emit enum value '{value}'" );
                return false;
            }

            return true;
        }

        private bool TryEmitCall( CallOperator callExpression, bool isStatement )
        {
            Trace( callExpression, $"Emitting call: {callExpression}" );

            if ( mRootScope.TryGetFunction( callExpression.Identifier.Text, out var function ) )
            {
                if ( callExpression.Arguments.Count != function.Declaration.Parameters.Count )
                {
                    // Todo: mark variadic functions
                    if ( function.Declaration.Identifier.Text != "PUTS" || function.Declaration.Parameters.Count == 0 )
                    {
                        Error(
                            $"Function '{function.Declaration}' expects {function.Declaration.Parameters.Count} arguments but {callExpression.Arguments.Count} are given" );
                        return false;
                    }
                }

                // Check MessageScript function call semantics
                if ( mScript.MessageScript != null )
                {
                    // Todo: make this less hardcoded
                    switch ( callExpression.Identifier.Text )
                    {
                        case "MSG":
                        case "SEL":
                            {
                                var firstArgument = callExpression.Arguments[ 0 ];
                                if ( firstArgument.Expression is IntLiteral firstArgumentInt )
                                {
                                    var index = firstArgumentInt.Value;
                                    if ( index < 0 || index >= mScript.MessageScript.Dialogs.Count )
                                    {
                                        Error( $"Function call to {callExpression.Identifier.Text} references dialog that doesn't exist (index: {index})" );
                                        return false;
                                    }

                                    var expectedDialogKind = callExpression.Identifier.Text == "MSG"
                                        ? DialogKind.Message
                                        : DialogKind.Selection;

                                    var dialog = mScript.MessageScript.Dialogs[index];
                                    if ( dialog.Kind != expectedDialogKind )
                                    {
                                        Error( $"Function call to {callExpression.Identifier.Text} doesn't reference a {expectedDialogKind} dialog, got dialog of type: {dialog.Kind} index: {index}" );
                                        return false;
                                    }
                                }
                            }
                            break;
                    }
                }

                if ( EnableFunctionCallTracing )
                {
                    TraceFunctionCall( function.Declaration );
                }

                if ( function.Declaration.Parameters.Count > 0 )
                {
                    if ( !TryEmitFunctionCallArguments( callExpression ) )
                        return false;
                }

                // call function
                Emit( Instruction.COMM( function.Index ) );

                if ( !isStatement && function.Declaration.ReturnType.ValueKind != ValueKind.Void )
                {
                    if ( !EnableFunctionCallTracing )
                    {
                        // push return value of function
                        Trace( callExpression, $"Emitting PUSHREG for {callExpression}" );
                        Emit( Instruction.PUSHREG() );
                    }
                    else
                    {
                        TraceFunctionCallReturnValue( function.Declaration );
                    }
                }
            }
            else if ( mRootScope.TryGetProcedure( callExpression.Identifier.Text, out var procedure ) )
            {
                if ( callExpression.Arguments.Count != procedure.Declaration.Parameters.Count )
                {
                    Error( $"Procedure '{procedure.Declaration}' expects {procedure.Declaration.Parameters.Count} arguments but {callExpression.Arguments.Count} are given" );
                    return false;
                }

                if ( EnableProcedureCallTracing )
                {
                    TraceProcedureCall( procedure.Declaration );
                }

                if ( !TryEmitParameterCallArguments( callExpression, procedure.Declaration, out var parameterIndices ) )
                    return false;

                // call procedure
                Emit( Instruction.CALL( procedure.Index ) );

                // Emit out parameter assignments
                for ( int i = 0; i < procedure.Declaration.Parameters.Count; i++ )
                {
                    var parameter = procedure.Declaration.Parameters[ i ];
                    if ( parameter.Modifier != ParameterModifier.Out )
                        continue;

                    // Copy value of local variable copy of out parameter to actual out parameter
                    var index = parameterIndices[ i ];
                    var identifier = ( Identifier ) callExpression.Arguments[ i ].Expression;
                    if ( !Scope.TryGetVariable( identifier.Text, out var variable ) )
                        return false;

                    if ( sTypeToBaseTypeMap[ variable.Declaration.Type.ValueKind ] == ValueKind.Int )
                    {
                        Emit( Instruction.PUSHLIX( index ) );
                        Emit( Instruction.POPLIX( variable.Index ) );
                    }
                    else
                    {
                        Emit( Instruction.PUSHLFX( index ) );
                        Emit( Instruction.POPLFX( variable.Index ) );
                    }
                       
                }

                // Emit return value
                if ( !isStatement && procedure.Declaration.ReturnType.ValueKind != ValueKind.Void )
                {
                    if ( !EnableProcedureCallTracing )
                    {
                        // Push return value of procedure
                        if ( sTypeToBaseTypeMap[ procedure.Declaration.ReturnType.ValueKind ] == ValueKind.Int )
                            Emit( Instruction.PUSHLIX( mIntReturnValueVariable.Index ) );
                        else
                            Emit( Instruction.PUSHLFX( mFloatReturnValueVariable.Index ) );
                    }
                    else
                    {
                        TraceProcedureCallReturnValue( procedure.Declaration );
                    }
                }
            }
            else
            {
                Error( callExpression, $"Invalid call expression. Expected function or procedure identifier, got: {callExpression.Identifier}" );
                return false;
            }

            return true;
        }

        private bool TryEmitFunctionCallArguments( CallOperator callExpression )
        {
            Trace( "Emitting function call arguments" );

            // Compile expressions backwards so they are pushed to the stack in the right order
            for ( int i = callExpression.Arguments.Count - 1; i >= 0; i-- )
            {
                if ( !TryEmitExpression( callExpression.Arguments[i].Expression, false ) )
                {
                    Error( callExpression.Arguments[i], $"Failed to compile function call argument: {callExpression.Arguments[i]}" );
                    return false;
                }
            }

            return true;
        }

        private bool TryEmitParameterCallArguments( CallOperator callExpression, ProcedureDeclaration declaration, out List<short> parameterIndices )
        {
            Trace( "Emitting parameter call arguments" );

            int intParameterCount = 0;
            int floatParameterCount = 0;
            parameterIndices = new List< short >();

            for ( int i = 0; i < callExpression.Arguments.Count; i++ )
            {
                var argument = callExpression.Arguments[ i ];

                if ( argument.Modifier != ArgumentModifier.Out )
                {
                    if ( !TryEmitExpression( argument.Expression, false ) )
                    {
                        Error( callExpression.Arguments[i], $"Failed to compile function call argument: {argument}" );
                        return false;
                    }
                }

                // Assign each required parameter variable
                if ( sTypeToBaseTypeMap[declaration.Parameters[i].Type.ValueKind] == ValueKind.Int )
                {
                    if ( argument.Modifier != ArgumentModifier.Out )
                        Emit( Instruction.POPLIX( mNextIntParameterVariableIndex ) );

                    parameterIndices.Add( mNextIntParameterVariableIndex );

                    ++mNextIntParameterVariableIndex;
                    ++intParameterCount;
                }
                else
                {
                    if ( argument.Modifier != ArgumentModifier.Out )
                        Emit( Instruction.POPLFX( mNextFloatParameterVariableIndex ) );

                    parameterIndices.Add( mNextFloatParameterVariableIndex );

                    ++mNextFloatParameterVariableIndex;
                    ++floatParameterCount;
                }
            }

            // Reset the parameter variable indices
            mNextIntParameterVariableIndex -= ( short )intParameterCount;
            mNextFloatParameterVariableIndex -= ( short )floatParameterCount;

            return true;
        }

        private bool TryEmitUnaryExpression( UnaryExpression unaryExpression, bool isStatement )
        {
            Trace( unaryExpression, $"Emitting unary expression: {unaryExpression}" );

            switch ( unaryExpression )
            {
                case PostfixOperator postfixOperator:
                    if ( !TryEmitPostfixOperator( postfixOperator, isStatement ) )
                    {
                        Error( postfixOperator, "Failed to emit postfix operator" );
                        return false;
                    }
                    break;

                case PrefixOperator prefixOperator:
                    if ( !TryEmitPrefixOperator( prefixOperator, isStatement ) )
                    {
                        Error( prefixOperator, "Failed to emit prefix operator" );
                        return false;
                    }
                    break;

                default:
                    Error( unaryExpression, $"Emitting unary expression '{unaryExpression}' not implemented" );
                    return false;
            }

            return true;
        }

        private bool TryEmitPostfixOperator( PostfixOperator postfixOperator, bool isStatement )
        {
            var identifier = ( Identifier )postfixOperator.Operand;
            if ( !Scope.TryGetVariable( identifier.Text, out var variable ) )
            {
                Error( identifier, $"Reference to undefined variable: {identifier}" );
                return false;
            }

            short index;
            if ( variable.Declaration.Type.ValueKind != ValueKind.Float )
            {
                index = mNextIntVariableIndex++;
            }
            else
            {
                index = mNextFloatVariableIndex++;
            }

            Variable copy = null;
            if ( !isStatement )
            {
                // Make copy of variable
                copy = Scope.GenerateVariable( variable.Declaration.Type.ValueKind, index );

                // Push value of the variable to save in the copy
                if ( !TryEmitPushVariableValue( identifier ) )
                {
                    Error( identifier, $"Failed to push variable value to copy variable: {identifier}" );
                    return false;
                }

                // Assign the copy with the value of the variable
                if ( !TryEmitVariableAssignment( copy.Declaration.Identifier ) )
                {
                    Error( $"Failed to emit variable assignment to copy variable: {copy}" );
                    return false;
                }
            }

            // In/decrement the actual variable
            {
                // Push 1
                Emit( Instruction.PUSHIS( 1 ) );

                // Push value of the variable
                if ( !TryEmitPushVariableValue( identifier ) )
                {
                    Error( identifier, $"Failed to push variable value to copy variable: {identifier}" );
                    return false;
                }

                // Subtract or add
                if ( postfixOperator is PostfixDecrementOperator )
                {
                    Emit( Instruction.SUB() );
                }
                else if ( postfixOperator is PostfixIncrementOperator )
                {
                    Emit( Instruction.ADD() );
                }
                else
                {
                    return false;
                }

                // Emit assignment with calculated value
                if ( !TryEmitVariableAssignment( identifier ) )
                {
                    Error( identifier, $"Failed to emit variable assignment: {identifier}" );
                    return false;
                }
            }

            if ( !isStatement )
            {
                // Push the value of the copy
                Trace( $"Pushing variable value: {copy.Declaration.Identifier}" );

                if ( !TryEmitPushVariableValue( copy.Declaration.Identifier ) )
                {
                    Error( $"Failed to push value for copy variable { copy }" );
                    return false;
                }
            }

            return true;
        }

        private bool TryEmitPrefixOperator( PrefixOperator prefixOperator, bool isStatement )
        {
            switch ( prefixOperator )
            {
                case LogicalNotOperator _:
                case NegationOperator _:
                    if ( isStatement )
                    {
                        Error( prefixOperator, "A logical not operator is an invalid statement" );
                        return false;
                    }

                    if ( !TryEmitExpression( prefixOperator.Operand, false ) )
                    {
                        Error( prefixOperator.Operand, "Failed to emit operand for unary expression" );
                        return false;
                    }

                    if ( prefixOperator is LogicalNotOperator )
                    {
                        Trace( prefixOperator, "Emitting NOT" );
                        Emit( Instruction.NOT() );
                    }
                    else if ( prefixOperator is NegationOperator )
                    {
                        Trace( prefixOperator, "Emitting MINUS" );
                        Emit( Instruction.MINUS() );
                    }
                    else
                    {
                        goto default;
                    }
                    break;

                case PrefixDecrementOperator _:
                case PrefixIncrementOperator _:
                    {
                        // Push 1
                        Emit( Instruction.PUSHIS( 1 ) );

                        // Push value
                        var identifier = ( Identifier )prefixOperator.Operand;
                        if ( !TryEmitPushVariableValue( identifier ) )
                        {
                            Error( identifier, $"Failed to emit variable value for: { identifier }" );
                            return false;
                        }

                        // Emit operation
                        if ( prefixOperator is PrefixDecrementOperator )
                        {
                            Emit( Instruction.SUB() );
                        }
                        else if ( prefixOperator is PrefixIncrementOperator )
                        {
                            Emit( Instruction.ADD() );
                        }
                        else
                        {
                            goto default;
                        }

                        // Emit assignment
                        if ( !TryEmitVariableAssignment( identifier ) )
                        {
                            Error( prefixOperator, $"Failed to emit variable assignment: {prefixOperator}" );
                            return false;
                        }

                        if ( !isStatement )
                        {
                            Trace( prefixOperator, $"Emitting variable value: {identifier}" );

                            if ( !TryEmitPushVariableValue( identifier ) )
                            {
                                Error( identifier, $"Failed to emit variable value for: { identifier }" );
                                return false;
                            }
                        }
                    }
                    break;

                default:
                    Error( prefixOperator, $"Unknown prefix operator: {prefixOperator}" );
                    return false;
            }

            return true;
        }

        private bool TryEmitBinaryExpression( BinaryExpression binaryExpression, bool isStatement )
        {
            Trace( binaryExpression, $"Emitting binary expression: {binaryExpression}" );

            if ( binaryExpression is AssignmentOperatorBase assignment )
            {
                if ( !TryEmitVariableAssignmentBase( assignment, isStatement ) )
                {
                    Error( assignment, $"Failed to emit variable assignment: { assignment }" );
                    return false;
                }
            }
            else
            {
                if ( isStatement )
                {
                    Error( binaryExpression, "A binary operator is not a valid statement" );
                    return false;
                }

                Trace( "Emitting value for binary expression" );

                if ( binaryExpression is ModulusOperator modulusOperator )
                {
                    // This one is special
                    if ( !TryEmitModulusOperator( modulusOperator ) )
                    {
                        Error( binaryExpression.Right, $"Failed to emit modulus expression: {binaryExpression.Left}" );
                        return false;
                    }
                }
                else
                {
                    if ( !TryEmitExpression( binaryExpression.Right, false ) )
                    {
                        Error( binaryExpression.Right, $"Failed to emit right expression: {binaryExpression.Left}" );
                        return false;
                    }

                    if ( !TryEmitExpression( binaryExpression.Left, false ) )
                    {
                        Error( binaryExpression.Right, $"Failed to emit left expression: {binaryExpression.Right}" );
                        return false;
                    }

                    switch ( binaryExpression )
                    {
                        case AdditionOperator _:
                            Emit( Instruction.ADD() );
                            break;
                        case SubtractionOperator _:
                            Emit( Instruction.SUB() );
                            break;
                        case MultiplicationOperator _:
                            Emit( Instruction.MUL() );
                            break;
                        case DivisionOperator _:
                            Emit( Instruction.DIV() );
                            break;
                        case LogicalOrOperator _:
                            Emit( Instruction.OR() );
                            break;
                        case LogicalAndOperator _:
                            Emit( Instruction.AND() );
                            break;
                        case EqualityOperator _:
                            Emit( Instruction.EQ() );
                            break;
                        case NonEqualityOperator _:
                            Emit( Instruction.NEQ() );
                            break;
                        case LessThanOperator _:
                            Emit( Instruction.S() );
                            break;
                        case GreaterThanOperator _:
                            Emit( Instruction.L() );
                            break;
                        case LessThanOrEqualOperator _:
                            Emit( Instruction.SE() );
                            break;
                        case GreaterThanOrEqualOperator _:
                            Emit( Instruction.LE() );
                            break;
                        default:
                            Error( binaryExpression, $"Emitting binary expression '{binaryExpression}' not implemented" );
                            return false;
                    }
                }
            }

            return true;
        }

        private bool TryEmitModulusOperator( ModulusOperator modulusOperator )
        {
            var value = modulusOperator.Left;
            var number = modulusOperator.Right;

            if ( !TryEmitModulus( value, number ) )
                return false;

            return true;
        }

        private bool TryEmitModulus( Expression value, Expression number )
        {
            // value % number turns into
            // value - ( ( value / number ) * value )

            // push number for multiplication
            if ( !TryEmitExpression( number, false ) )
                return false;

            // value / number
            if ( !TryEmitExpression( number, false ) )
                return false;

            if ( !TryEmitExpression( value, false ) )
                return false;

            Emit( Instruction.DIV() );

            // *= number
            Emit( Instruction.MUL() );

            // value - ( ( value / number ) * number )
            if ( !TryEmitExpression( value, false ) )
                return false;

            Emit( Instruction.SUB() );

            // Result value is on stack
            return true;
        }

        private bool TryEmitPushVariableValue( Identifier identifier )
        {
            Trace( identifier, $"Emitting variable reference: {identifier}" );

            if ( !Scope.TryGetVariable( identifier.Text, out var variable ) )
            {
                Error( identifier, $"Referenced undeclared variable '{identifier}'" );
                return false;
            }

            if ( variable.Declaration.Modifier == null || variable.Declaration.Modifier.Kind == VariableModifierKind.Local )
            {
                if ( variable.Declaration.Type.ValueKind != ValueKind.Float )
                    Emit( Instruction.PUSHLIX( variable.Index ) );
                else
                    Emit( Instruction.PUSHLFX( variable.Index ) );
            }
            else if ( variable.Declaration.Modifier.Kind == VariableModifierKind.Global )
            {
                if ( variable.Declaration.Type.ValueKind != ValueKind.Float )
                    Emit( Instruction.PUSHIX( variable.Index ) );
                else
                    Emit( Instruction.PUSHIF( variable.Index ) );
            }
            else if ( variable.Declaration.Modifier.Kind == VariableModifierKind.Constant )
            {
                if ( !TryEmitExpression( variable.Declaration.Initializer, false ) )
                {
                    Error( variable.Declaration.Initializer, $"Failed to emit value for constant expression: {variable.Declaration}" );
                    return false;
                }
            }
            else if ( variable.Declaration.Modifier.Kind == VariableModifierKind.AiLocal )
            {
                Emit( Instruction.PUSHIS( variable.Index ) );
                Emit( Instruction.COMM( mInstrinsic.AiGetLocalFunctionIndex ) ); // AI_GET_LOCAL_PARAM
                Emit( Instruction.PUSHREG() );
            }
            else if ( variable.Declaration.Modifier.Kind == VariableModifierKind.AiGlobal )
            {
                Emit( Instruction.PUSHIS( variable.Index ) );
                Emit( Instruction.COMM( mInstrinsic.AiGetGlobalFunctionIndex ) ); // AI_GET_GLOBAL
                Emit( Instruction.PUSHREG() );
            }
            else if ( variable.Declaration.Modifier.Kind == VariableModifierKind.Bit )
            {
                Emit( Instruction.PUSHIS( variable.Index ) );
                Emit( Instruction.COMM( mInstrinsic.BitCheckFunctionIndex ) ); // BIT_CHK
                Emit( Instruction.PUSHREG() );
            }
            else
            {
                Error( variable.Declaration, "Unsupported variable modifier type" );
                return false;
            }

            return true;
        }

        private bool TryEmitVariableAssignmentBase( AssignmentOperatorBase assignment, bool isStatement )
        {
            if ( assignment is CompoundAssignmentOperator compoundAssignment )
            {
                if ( !TryEmitVariableCompoundAssignment( compoundAssignment, isStatement ) )
                {
                    Error( compoundAssignment, $"Failed to emit compound assignment: {compoundAssignment}" );
                    return false;
                }
            }
            else
            {
                if ( !TryEmitVariableAssignment( ( Identifier )assignment.Left, assignment.Right, isStatement ) )
                {
                    Error( assignment, $"Failed to emit assignment: {assignment}" );
                    return false;
                }
            }

            return true;
        }

        private bool TryEmitVariableCompoundAssignment( CompoundAssignmentOperator compoundAssignment, bool isStatement )
        {
            Trace( compoundAssignment, $"Emitting compound assignment: {compoundAssignment}" );

            var identifier = ( Identifier )compoundAssignment.Left;

            if ( compoundAssignment is ModulusAssignmentOperator _ )
            {
                // Special treatment because it doesnt have an instruction
                if ( !TryEmitModulus( compoundAssignment.Left, compoundAssignment.Right ) )
                {
                    Error( compoundAssignment, $"Failed to emit modulus assignment operator: {compoundAssignment}" );
                    return false;
                }
            }
            else
            {
                // Push value of right expression
                if ( !TryEmitExpression( compoundAssignment.Right, false ) )
                {
                    Error( compoundAssignment.Right, $"Failed to emit expression: { compoundAssignment.Right }" );
                    return false;
                }

                // Push value of variable
                if ( !TryEmitPushVariableValue( identifier ) )
                {
                    Error( identifier, $"Failed to emit variable value for: { identifier }" );
                    return false;
                }

                // Emit operation
                switch ( compoundAssignment )
                {
                    case AdditionAssignmentOperator _:
                        Emit( Instruction.ADD() );
                        break;

                    case SubtractionAssignmentOperator _:
                        Emit( Instruction.SUB() );
                        break;

                    case MultiplicationAssignmentOperator _:
                        Emit( Instruction.MUL() );
                        break;

                    case DivisionAssignmentOperator _:
                        Emit( Instruction.DIV() );
                        break;

                    default:
                        Error( compoundAssignment, $"Unknown compound assignment type: { compoundAssignment }" );
                        return false;
                }
            }

            // Assign the value to the variable
            if ( !TryEmitVariableAssignment( identifier ) )
            {
                Error( identifier, $"Failed to assign value to variable: { identifier }" );
                return false;
            }

            if ( !isStatement )
            {
                Trace( compoundAssignment, $"Pushing variable value: {identifier}" );

                // Push value of variable
                if ( !TryEmitPushVariableValue( identifier ) )
                {
                    Error( identifier, $"Failed to emit variable value for: { identifier }" );
                    return false;
                }
            }

            return true;
        }


        /// <summary>
        /// Emit variable assignment with an explicit expression.
        /// </summary>
        /// <param name="identifier"></param>
        /// <param name="expression"></param>
        /// <returns></returns>
        private bool TryEmitVariableAssignment( Identifier identifier, Expression expression, bool isStatement )
        {
            Trace( $"Emitting variable assignment: {identifier} = {expression}" );

            if ( !TryEmitExpression( expression, false ) )
            {
                Error( expression, "Failed to emit code for assigment value expression" );
                return false;
            }

            if ( !TryEmitVariableAssignment( identifier ) )
            {
                Error( identifier, "Failed to emit code for value assignment to variable" );
                return false;
            }

            if ( !isStatement )
            {
                // Push value of variable
                Trace( identifier, $"Pushing variable value: {identifier}" );

                if ( !TryEmitPushVariableValue( identifier ) )
                {
                    Error( identifier, $"Failed to emit variable value for: { identifier }" );
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Emit variable assignment without explicit expression.
        /// </summary>
        /// <param name="identifier"></param>
        /// <returns></returns>
        private bool TryEmitVariableAssignment( Identifier identifier )
        {
            if ( !Scope.TryGetVariable( identifier.Text, out var variable ) )
            {
                Error( identifier, $"Assignment to undeclared variable: {identifier}" );
                return false;
            }

            if ( !TryEmitVariableAssignment( variable.Declaration, variable.Index ) )
                return false;

            return true;
        }

        private bool TryEmitVariableAssignment( VariableDeclaration declaration, short index )
        {
            // load the value into the variable
            if ( declaration.Modifier == null || declaration.Modifier.Kind == VariableModifierKind.Local )
            {
                if ( declaration.Type.ValueKind != ValueKind.Float )
                    Emit( Instruction.POPLIX( index ) );
                else
                    Emit( Instruction.POPLFX( index ) );
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.Global )
            {
                if ( declaration.Type.ValueKind != ValueKind.Float )
                    Emit( Instruction.POPIX( index ) );
                else
                    Emit( Instruction.POPFX( index ) );
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.Constant )
            {
                Error( declaration.Identifier, "Illegal assignment to constant" );
                return false;
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.AiLocal )
            {
                // implicit pop of value
                Emit( Instruction.PUSHIS( index ) );
                Emit( Instruction.COMM( mInstrinsic.AiSetLocalFunctionIndex ) ); // AI_SET_LOCAL_PARAM
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.AiGlobal )
            {
                // implicit pop of value
                Emit( Instruction.PUSHIS( index ) );
                Emit( Instruction.COMM( mInstrinsic.AiSetGlobalFunctionIndex ) ); // AI_SET_GLOBAL
            }
            else if ( declaration.Modifier.Kind == VariableModifierKind.Bit )
            {
                var falseLabel = CreateLabel( "BitAssignmentIfFalse" );
                var endLabel = CreateLabel( "BitAssignmentIfEnd" );

                // implicit pop of value
                Emit( Instruction.IF( falseLabel.Index ) );
                {
                    // Value assigned is true
                    Emit( Instruction.PUSHIS( index ));
                    Emit( Instruction.COMM( mInstrinsic.BitOnFunctionIndex ) ); // BIT_ON
                    Emit( Instruction.GOTO( endLabel.Index ) );
                }
                // Else
                {
                    // Value assigned is false
                    ResolveLabel( falseLabel );
                    Emit( Instruction.PUSHIS( index ) );
                    Emit( Instruction.COMM( mInstrinsic.BitOffFunctionIndex ) ); // BIT_OFF
                    Emit( Instruction.GOTO( endLabel.Index ) );
                }
                ResolveLabel( endLabel );
            }
            else
            {
                Error( declaration.Identifier, $"Unsupported variable modifier type: {declaration.Modifier}" );
                return false;
            }

            return true;
        }

        //
        // Literal values
        //
        private void EmitPushBoolLiteral( BoolLiteral boolLiteral )
        {
            Trace( boolLiteral, $"Pushing bool literal: {boolLiteral}" );

            if ( boolLiteral.Value )
                Emit( Instruction.PUSHIS( 1 ) );
            else
                Emit( Instruction.PUSHIS( 0 ) );
        }

        private void EmitPushIntLiteral( IntLiteral intLiteral )
        {
            Trace( intLiteral, $"Pushing int literal: {intLiteral}" );

            if ( IntFitsInShort( intLiteral.Value ) )
                Emit( Instruction.PUSHIS( ( short )intLiteral.Value ) );
            else
                Emit( Instruction.PUSHI( intLiteral.Value ) );
        }

        private void EmitPushFloatLiteral( FloatLiteral floatLiteral )
        {
            Trace( floatLiteral, $"Pushing float literal: {floatLiteral}" );

            Emit( Instruction.PUSHF( floatLiteral.Value ) );
        }

        private void EmitPushStringLiteral( StringLiteral stringLiteral )
        {
            Trace( stringLiteral, $"Pushing string literal: {stringLiteral}" );

            Emit( Instruction.PUSHSTR( stringLiteral.Value ) );
        }

        private bool IntFitsInShort( int value )
        {
            return ( ( ( value & 0xffff8000 ) + 0x8000 ) & 0xffff7fff ) == 0;
        }

        // 
        // If statement
        //
        private bool TryEmitIfStatement( IfStatement ifStatement )
        {
            Trace( ifStatement, $"Emitting if statement: '{ifStatement}'" );

            // emit condition expression, which should push a boolean value to the stack
            if ( !TryEmitExpression( ifStatement.Condition, false ) )
            {
                Error( ifStatement.Condition, "Failed to emit if statement condition" );
                return false;
            }

            // generate label for jump if condition is false
            var endLabel = CreateLabel( "IfEndLabel" );
            Label elseLabel = null;

            // emit if instruction that jumps to the label if the condition is false
            if ( ifStatement.ElseBody == null )
            {
                Emit( Instruction.IF( endLabel.Index ) );
            }
            else
            {
                elseLabel = CreateLabel( "IfElseLabel" );
                Emit( Instruction.IF( elseLabel.Index ) );
            }

            // compile if body
            if ( ifStatement.ElseBody == null )
            {
                // If there's no else, then the end of the body will line up with the end label
                if ( !TryEmitIfStatementBody( ifStatement.Body, null ) )
                    return false;
            }
            else
            {
                // If there's an else body, then the end of the body will line up with the else label, but it should line up with the end label
                if ( !TryEmitIfStatementBody( ifStatement.Body, endLabel ) )
                    return false;
            }

            if ( ifStatement.ElseBody != null )
            {
                ResolveLabel( elseLabel );

                // compile if else body
                // The else body will always line up with the end label
                if ( !TryEmitIfStatementBody( ifStatement.ElseBody, null ) )
                    return false;
            }

            ResolveLabel( endLabel );

            return true;
        }

        private bool TryEmitIfStatementBody( CompoundStatement body, Label endLabel )
        {
            Trace( body, "Compiling if statement body" );
            if ( !TryEmitCompoundStatement( body ) )
            {
                Error( body, "Failed to compile if statement body" );
                return false;
            }

            // ensure that we end up at the right position after the body
            if ( endLabel != null )
                Emit( Instruction.GOTO( endLabel.Index ) );

            return true;
        }

        // 
        // If statement
        //
        private bool TryEmitForStatement( ForStatement forStatement )
        {
            Trace( forStatement, $"Emitting for statement: '{forStatement}'" );

            // Enter for scope
            PushScope();

            // Emit initializer
            if ( !TryEmitStatement( forStatement.Initializer ) )
            {
                Error( forStatement.Condition, "Failed to emit for statement initializer" );
                return false;
            }

            // Create labels
            var conditionLabel = CreateLabel( "ForConditionLabel" );
            var afterLoopLabel = CreateLabel( "ForAfterLoopLabel" );
            var endLabel = CreateLabel( "ForEndLabel" );

            // Emit condition check
            {
                ResolveLabel( conditionLabel );

                // Emit condition
                if ( !TryEmitExpression( forStatement.Condition, false ) )
                {
                    Error( forStatement.Condition, "Failed to emit for statement condition" );
                    return false;
                }

                // Jump to the end of the loop if condition is NOT true
                Emit( Instruction.IF( endLabel.Index ) );
            }

            // Emit body
            {
                // Allow break & continue
                Scope.BreakLabel = endLabel;
                Scope.ContinueLabel = afterLoopLabel;

                // emit body
                Trace( forStatement.Body, "Emitting for statement body" );
                if ( !TryEmitCompoundStatement( forStatement.Body ) )
                {
                    Error( forStatement.Body, "Failed to emit for statement body" );
                    return false;
                }
            }

            // Emit after loop
            {
                ResolveLabel( afterLoopLabel );

                if ( !TryEmitExpression( forStatement.AfterLoop, true ) )
                {
                    Error( forStatement.AfterLoop, "Failed to emit for statement after loop expression" );
                    return false;
                }

                // jump to condition check
                Emit( Instruction.GOTO( conditionLabel.Index ) );
            }

            // We're at the end of the for loop
            ResolveLabel( endLabel );

            // Exit for scope
            PopScope();

            return true;
        }

        // 
        // While statement
        //
        private bool TryEmitWhileStatement( WhileStatement whileStatement )
        {
            Trace( whileStatement, $"Emitting while statement: '{whileStatement}'" );

            // Create labels
            var conditionLabel = CreateLabel( "WhileConditionLabel" );
            var endLabel = CreateLabel( "WhileEndLabel" );

            // Emit condition check
            {
                ResolveLabel( conditionLabel );

                // compile condition expression, which should push a boolean value to the stack
                if ( !TryEmitExpression( whileStatement.Condition, false ) )
                {
                    Error( whileStatement.Condition, "Failed to emit while statement condition" );
                    return false;
                }

                // Jump to the end of the loop if condition is NOT true
                Emit( Instruction.IF( endLabel.Index ) );
            }

            // Emit body
            {
                // Enter while body scope
                PushScope();

                // allow break & continue
                Scope.BreakLabel = endLabel;
                Scope.ContinueLabel = conditionLabel;

                // emit body
                Trace( whileStatement.Body, "Emitting while statement body" );
                if ( !TryEmitCompoundStatement( whileStatement.Body ) )
                {
                    Error( whileStatement.Body, "Failed to emit while statement body" );
                    return false;
                }

                // jump to condition check
                Emit( Instruction.GOTO( conditionLabel.Index ) );

                // Exit while body scope
                PopScope();
            }

            // We're at the end of the while loop
            ResolveLabel( endLabel );

            return true;
        }

        //
        // Switch statement
        //
        private bool TryEmitSwitchStatement( SwitchStatement switchStatement )
        {
            Trace( switchStatement, $"Emitting switch statement: '{switchStatement}'" );
            PushScope();

            var defaultLabel = switchStatement.Labels.SingleOrDefault( x => x is DefaultSwitchLabel );
            if ( switchStatement.Labels.Last() != defaultLabel )
            {
                switchStatement.Labels.Remove( defaultLabel );
                switchStatement.Labels.Add( defaultLabel );
            }

            var switchEndLabel = CreateLabel( "SwitchStatementEndLabel" );
            var labelBodyLabels = new List< Label >();
            foreach ( var label in switchStatement.Labels )
            {
                if ( label is ConditionSwitchLabel conditionLabel )
                {
                    // Emit condition expression, which should push a boolean value to the stack
                    if ( !TryEmitExpression( conditionLabel.Condition, false ) )
                    {
                        Error( conditionLabel.Condition, "Failed to emit switch statement label condition" );
                        return false;
                    }

                    // emit switch on expression
                    if ( !TryEmitExpression( switchStatement.SwitchOn, false ) )
                    {
                        Error( switchStatement.SwitchOn, "Failed to emit switch statement condition" );
                        return false;
                    }

                    // emit equality check, but check if it's not equal to jump to the body if it is
                    Emit( Instruction.NEQ() );

                    // generate label for jump if condition is false
                    var labelBodyLabel = CreateLabel( "SwitchStatementLabelBodyLabel" );

                    // emit if instruction that jumps to the body if the condition is met
                    Emit( Instruction.IF( labelBodyLabel.Index ) );

                    labelBodyLabels.Add( labelBodyLabel );
                }
            }

            if ( defaultLabel != null )
            {
                // Emit body of default case first
                Scope.BreakLabel = switchEndLabel;

                // Emit default case body
                Trace( "Compiling switch statement label body" );
                if ( !TryEmitStatements( defaultLabel.Body ) )
                {
                    Error( "Failed to compile switch statement label body" );
                    return false;
                }
            }

            // Emit other label bodies
            for ( var i = 0; i < switchStatement.Labels.Count; i++ )
            {
                var label = switchStatement.Labels[ i ];

                if ( label is ConditionSwitchLabel )
                {
                    // Resolve body label
                    var labelBodyLabel = labelBodyLabels[ i ];
                    ResolveLabel( labelBodyLabel );

                    // Break jumps to end of switch
                    Scope.BreakLabel = switchEndLabel;

                    // Emit body
                    Trace( "Compiling switch statement label body" );
                    if ( !TryEmitStatements( label.Body ) )
                    {
                        Error( "Failed to compile switch statement label body" );
                        return false;
                    }
                }
            }

            ResolveLabel( switchEndLabel );

            PopScope();
            return true;
        }

        //
        // Control statements
        //
        private bool TryEmitBreakStatement( BreakStatement breakStatement )
        {
            if ( !Scope.TryGetBreakLabel( out var label ) )
            {
                Error( breakStatement, "Break statement is invalid in this context" );
                return false;
            }

            Emit( Instruction.GOTO( label.Index ) );

            return true;
        }

        private bool TryEmitContinueStatement( ContinueStatement continueStatement )
        {
            if ( !Scope.TryGetContinueLabel( out var label ) )
            {
                Error( continueStatement, "Continue statement is invalid in this context" );
                return false;
            }

            Emit( Instruction.GOTO( label.Index ) );

            return true;
        }

        private bool TryEmitReturnStatement( ReturnStatement returnStatement )
        {
            Trace( returnStatement, $"Emitting return statement: '{returnStatement}'" );

            if ( EnableStackCookie )
            {
                // Check stack cookie
                Emit( Instruction.PUSHI( mProcedureDeclaration.Identifier.Text.GetHashCode() ) );
                Emit( Instruction.NEQ() );
                var label = CreateLabel( "IfStackCookieIsValid" );
                Emit( Instruction.IF( label.Index ) );
                EmitTracePrint( "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", false );
                EmitTracePrint( "!!! Error: Stack cookie is invalid !!!!", false );
                EmitTracePrint( "!!! This is likely a compiler bug! !!!!", false );
                EmitTracePrint( "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", false );
                ResolveLabel( label );
            }

            if ( EnableProcedureTracing )
            {
                TraceProcedureReturn();
            }

            // Save return address in a temporary variable
            if ( returnStatement.Value != null )
            {
                if ( mProcedureDeclaration.ReturnType.ValueKind == ValueKind.Void )
                {
                    Error( returnStatement, "Procedure with void return type can't return a value" );
                    return false;
                }

                // Emit return value
                if ( !TryEmitExpression( returnStatement.Value, false ) )
                {
                    Error( returnStatement.Value, $"Failed to emit return value: {returnStatement.Value}" );
                    return false;
                }

                if ( sTypeToBaseTypeMap[mProcedureDeclaration.ReturnType.ValueKind] == ValueKind.Int )
                    Emit( Instruction.POPLIX( mIntReturnValueVariable.Index ) );
                else
                    Emit( Instruction.POPLFX( mFloatReturnValueVariable.Index ) );
            }
            else if ( mProcedureDeclaration.ReturnType.ValueKind != ValueKind.Void )
            {
                Error( returnStatement, "Missing return statement value for procedure with non-void return type" );
                return false;
            }

            // emit end
            Emit( Instruction.END() );
            return true;
        }

        private bool TryEmitGotoStatement( GotoStatement gotoStatement )
        {
            Trace( gotoStatement, $"Emitting goto statement: '{gotoStatement}'" );

            if ( !mLabels.TryGetValue( gotoStatement.LabelIdentifier.Text, out var label ) )
            {
                Error( gotoStatement.LabelIdentifier, $"Goto statement referenced undeclared label: {gotoStatement.LabelIdentifier}" );
                return false;
            }

            // emit goto
            Emit( Instruction.GOTO( label.Index ) );
            return true;
        }

        //
        // Helpers
        //
        private void TraceFunctionCall( FunctionDeclaration declaration )
        {
            EmitTracePrint( $"Call to function '{ declaration.Identifier }'" );
            if ( false && declaration.Parameters.Count > 0 )
            {
                EmitTracePrint( "Arguments:" );
                var saves = new Stack< Variable >();

                foreach ( var parameter in declaration.Parameters )
                {
                    switch ( parameter.Type.ValueKind )
                    {
                        case ValueKind.Int:
                            saves.Push( EmitTracePrintIntegerNoPush() );
                            break;
                        case ValueKind.Float:
                            saves.Push( EmitTracePrintFloatNoPush() );
                            break;
                        case ValueKind.Bool:
                            saves.Push( EmitTracePrintBoolNoPush() );
                            break;
                        case ValueKind.String:
                            //saves.Push( EmitTracePrintStringNoPush() );
                            break;
                    }
                }

                // Push values back onto stack
                while ( saves.Count > 0 )
                {
                    var variable = saves.Pop();
                    switch ( variable.Declaration.Type.ValueKind )
                    {
                        case ValueKind.Bool:
                            EmitUnchecked( Instruction.PUSHLIX( variable.Index ) );
                            break;
                        case ValueKind.Int:
                            EmitUnchecked( Instruction.PUSHLIX( variable.Index ) );
                            break;
                        case ValueKind.Float:
                            EmitUnchecked( Instruction.PUSHLFX( variable.Index ) );
                            break;
                    }
                }
            }
        }

        private Variable EmitTracePrintStringNoPush()
        {
            var save = Scope.GenerateVariable( ValueKind.String, mNextIntVariableIndex++ );

            // Pop integer value off stack and save it in a temporary variable
            EmitUnchecked( Instruction.POPLFX( save.Index ) );

            // Print it to log
            EmitUnchecked( Instruction.PUSHLFX( save.Index ) );
            EmitUnchecked( Instruction.COMM( mInstrinsic.PrintStringFunctionIndex ) );

            return save;
        }

        private void TraceFunctionCallReturnValue( FunctionDeclaration declaration )
        {
            EmitTracePrint( $"Call to function '{ declaration.Identifier }' returned:" );

            // push return value of function
            Emit( Instruction.PUSHREG() );

            EmitTracePrintValue( declaration.ReturnType.ValueKind );
        }

        private void TraceProcedureCall( ProcedureDeclaration declaration )
        {
            EmitTracePrint( $"Call to procedure '{ declaration.Identifier }'" );

            if ( false && declaration.Parameters.Count > 0 )
            {
                EmitTracePrint( "Arguments:" );

                int intParameterCount = 1;
                int floatParameterCount = 1;

                foreach ( var parameter in declaration.Parameters )
                {
                    if ( parameter.Type.ValueKind == ValueKind.Int )
                    {
                        Emit( Instruction.PUSHLIX( ( short )( mNextIntParameterVariableIndex + intParameterCount ) ) );
                    }
                    if ( parameter.Type.ValueKind == ValueKind.Bool)
                    {
                        Emit( Instruction.PUSHLIX( ( short )( mNextIntParameterVariableIndex + intParameterCount ) ) );
                    }
                    Emit( Instruction.PUSHLFX( ( short )( mNextFloatParameterVariableIndex + floatParameterCount ) ) );

                    EmitTracePrintValue( parameter.Type.ValueKind );

                    if ( parameter.Type.ValueKind == ValueKind.Int)
                    {
                        Emit( Instruction.POPLIX( ( short )( mNextIntParameterVariableIndex + intParameterCount ) ) );
                        ++intParameterCount;
                    }
                    if ( parameter.Type.ValueKind == ValueKind.Bool)
                    {
                        Emit( Instruction.POPLIX( ( short )( mNextIntParameterVariableIndex + intParameterCount ) ) );
                        ++intParameterCount;
                    }
                    Emit( Instruction.POPLFX( ( short )( mNextFloatParameterVariableIndex + floatParameterCount ) ) );
                    ++floatParameterCount;
                }
            }
        }

        private void TraceProcedureCallReturnValue( ProcedureDeclaration declaration )
        {
            EmitTracePrint( $"Call to procedure '{ declaration.Identifier }' returned:" );

            // Push return value of procedure
            if ( sTypeToBaseTypeMap[declaration.ReturnType.ValueKind] == ValueKind.Int )
                Emit( Instruction.PUSHLIX( mIntReturnValueVariable.Index ) );
            else
                Emit( Instruction.PUSHLFX( mFloatReturnValueVariable.Index ) );

            EmitTracePrintValue( declaration.ReturnType.ValueKind );
        }

        private void TraceProcedureStart()
        {
            EmitTracePrint( $"Entered procedure: '{ mProcedureDeclaration.Identifier.Text }'" );
        }

        private void TraceProcedureReturn()
        {
            EmitTracePrint( $"Exiting procedure: '{ mProcedureDeclaration.Identifier.Text }'" );
        }

        private void Emit( Instruction instruction )
        {
            // Emit instruction
            mInstructions.Add( instruction );
            TraceInstructionStackBehaviour( instruction );
        }

        private void TraceInstructionStackBehaviour( Instruction instruction )
        {
            switch ( instruction.Opcode )
            {
                case Opcode.PUSHI:
                case Opcode.PUSHF:
                case Opcode.PUSHIX:
                case Opcode.PUSHIF:
                    ++mStackValueCount;
                    break;
                case Opcode.PUSHREG:
                    ++mStackValueCount;
                    break;
                case Opcode.POPIX:
                case Opcode.POPFX:
                    --mStackValueCount;
                    break;
                case Opcode.END:
                {
                    // Log stack value count at procedure end
                    mLogger.Debug( $"{mStackValueCount} values on stack at END" );

                    if ( mStackValueCount < 1 )
                    {
                        mLogger.Error( "Stack underflow!!!" );
                    }
                    else if ( mStackValueCount != 1 )
                    {
                        mLogger.Error( "Return address corruption" );
                    }
                }
                    break;
                case Opcode.ADD:
                case Opcode.SUB:
                case Opcode.MUL:
                case Opcode.DIV:
                    mStackValueCount -= 2;
                    ++mStackValueCount;
                    break;
                case Opcode.EQ:
                case Opcode.NEQ:
                case Opcode.S:
                case Opcode.L:
                case Opcode.SE:
                case Opcode.LE:
                case Opcode.IF:
                    mStackValueCount -= 2;
                    ++mStackValueCount;
                    break;
                case Opcode.PUSHIS:
                case Opcode.PUSHLIX:
                case Opcode.PUSHLFX:
                    ++mStackValueCount;
                    break;
                case Opcode.POPLIX:
                case Opcode.POPLFX:
                    --mStackValueCount;
                    break;
                case Opcode.PUSHSTR:
                    ++mStackValueCount;
                    break;
                case Opcode.CALL:
                    break;
                case Opcode.COMM:
                {
                    var functionCalled = mRootScope.Functions.Values.Single( x => x.Index == instruction.Operand.Int16Value);
                    mStackValueCount -= functionCalled.Declaration.Parameters.Count;
                }
                    break;
                case Opcode.OR:
                    mStackValueCount -= 2;
                    ++mStackValueCount;
                    break;
                case Opcode.PROC:
                    break;
                case Opcode.JUMP:
                    break;
                case Opcode.RUN:
                    break;
                case Opcode.GOTO:
                    break;
                case Opcode.MINUS:
                    --mStackValueCount;
                    ++mStackValueCount;
                    break;
                case Opcode.NOT:
                    --mStackValueCount;
                    ++mStackValueCount;
                    break;
                case Opcode.AND:
                    mStackValueCount -= 2;
                    ++mStackValueCount;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private void EmitTracePrint( string message, bool prefixTrace = true )
        {
            var messageFormatted = message;
            if ( prefixTrace )
                messageFormatted = $"Trace: {message}";

            EmitUnchecked( Instruction.PUSHSTR( messageFormatted ) );
            EmitUnchecked( Instruction.COMM( mInstrinsic.PrintStringFunctionIndex ) );
        }

        private void EmitTracePrintValue( ValueKind kind )
        {
            switch ( kind )
            {
                case ValueKind.Int:
                    EmitTracePrintInteger();
                    break;
                case ValueKind.Float:
                    EmitTracePrintFloat();
                    break;
                case ValueKind.Bool:
                    EmitTracePrintBool();
                    break;
            }
        }

        private void EmitTracePrintInteger()
        {
            var save = EmitTracePrintIntegerNoPush();

            // Push the value back to the stack
            EmitUnchecked( Instruction.PUSHLIX( save.Index ) );
        }

        private Variable EmitTracePrintIntegerNoPush()
        {
            var save = Scope.GenerateVariable( ValueKind.Int, mNextIntVariableIndex++ );

            // Pop integer value off stack and save it in a temporary variable
            EmitUnchecked( Instruction.POPLIX( save.Index ) );

            // Print it to log
            EmitUnchecked( Instruction.PUSHLIX( save.Index ) );
            EmitUnchecked( Instruction.COMM( mInstrinsic.PrintIntFunctionIndex ) );

            return save;
        }

        private void EmitTracePrintFloat()
        {
            var save = EmitTracePrintFloatNoPush();

            // Push the value back to the stack
            EmitUnchecked( Instruction.PUSHLFX( save.Index ) );
        }

        private Variable EmitTracePrintFloatNoPush()
        {
            var save = Scope.GenerateVariable( ValueKind.Float, mNextFloatVariableIndex++ );

            // Pop integer value off stack and save it in a temporary variable
            EmitUnchecked( Instruction.POPLFX( save.Index ) );

            // Print it to log
            EmitUnchecked( Instruction.PUSHLFX( save.Index ) );
            EmitUnchecked( Instruction.COMM( mInstrinsic.PrintFloatFunctionIndex ) );

            return save;
        }

        private void EmitTracePrintBool()
        {
            var save = EmitTracePrintBoolNoPush();

            // Push the value back to the stack
            EmitUnchecked( Instruction.PUSHLIX( save.Index ) );
        }

        private Variable EmitTracePrintBoolNoPush()
        {
            var save = Scope.GenerateVariable( ValueKind.Int, mNextIntVariableIndex++ );

            // Pop integer value off stack and save it in a temporary variable
            EmitUnchecked( Instruction.POPLIX( save.Index ) );

            // Print it to log
            var elseLabel = CreateLabel( "IfElseLabel" );
            var endLabel = CreateLabel( "IfEndLabel" );

            // if ( x == 1 )
            EmitUnchecked( Instruction.PUSHIS( 1 ) );
            EmitUnchecked( Instruction.PUSHLIX( save.Index ) );
            EmitUnchecked( Instruction.EQ() );
            EmitUnchecked( Instruction.IF( elseLabel.Index ) );
            {
                // PUTS( "true" );
                EmitTracePrint( "true" );
                EmitUnchecked( Instruction.GOTO( endLabel.Index ) );
            }
            // else
            ResolveLabel( elseLabel );
            {
                // PUTS( "false" );
                EmitTracePrint( "false" );
            }
            ResolveLabel( endLabel );

            return save;
        }

        private void EmitUnchecked( Instruction instruction )
        {
            mInstructions.Add( instruction );
        }

        private Label CreateLabel( string name )
        {
            var label = new Label();
            label.Index = ( short )mLabels.Count;
            label.Name = name + "_" + mNextLabelIndex++;

            mLabels.Add( label.Name, label );

            return label;
        }

        private void ResolveLabel( Label label )
        {
            label.InstructionIndex = ( short )( mInstructions.Count );
            label.IsResolved = true;

            Trace( $"Resolved label {label.Name} to instruction index {label.InstructionIndex}" );
        }

        private void PushScope()
        {
            mScopeStack.Push( new ScopeContext( mScopeStack.Peek() ) );
            Trace( "Entered scope" );
        }

        private void PopScope()
        {
            //mNextIntVariableIndex -= ( short )Scope.Variables.Count( x => sTypeToBaseTypeMap[x.Value.Declaration.Type.ValueType] == FlowScriptValueType.Int );
            //mNextFloatVariableIndex -= ( short )Scope.Variables.Count( x => sTypeToBaseTypeMap[x.Value.Declaration.Type.ValueType] == FlowScriptValueType.Float );
            mScopeStack.Pop();
            Trace( "Exited scope" );
        }

        //
        // Logging
        //
        private void Trace( SyntaxNode node, string message )
        {
            if ( node.SourceInfo != null )
                Trace( $"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}" );
            else
                Trace( message );
        }

        private void Trace( string message )
        {
            mLogger.Trace( $"{message}" );
        }

        private void Info( SyntaxNode node, string message )
        {
            if ( node.SourceInfo != null )
                Info( $"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}" );
            else
                Info( message );
        }

        private void Info( string message )
        {
            mLogger.Info( $"{message}" );
        }

        private void Error( SyntaxNode node, string message )
        {
            if ( node.SourceInfo != null )
                Error( $"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}" );
            else
                Error( message );

            if ( Debugger.IsAttached )
                Debugger.Break();
        }

        private void Error( string message )
        {
            mLogger.Error( $"{message}" );
        }

        private void Warning( SyntaxNode node, string message )
        {
            if ( node.SourceInfo != null )
                Warning( $"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}" );
            else
                Warning( message );
        }

        private void Warning( string message )
        {
            mLogger.Warning( $"{message}" );
        }
    }
}
