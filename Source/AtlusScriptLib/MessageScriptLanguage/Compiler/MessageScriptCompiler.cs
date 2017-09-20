using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.MessageScriptLanguage.Parser;
using Antlr4.Runtime;
using Antlr4.Runtime.Tree;
using System.Text;

namespace AtlusScriptLib.MessageScriptLanguage.Compiler
{
    // Todo: improve error logging in general
    // Todo: add exception settings?

    /// <summary>
    /// Represents the compiler that compiles MessageScript text sources to their appropriate binary equivalents.
    /// </summary>
    public class MessageScriptCompiler
    {
        private Logger mLogger;
        private MessageScriptFormatVersion mVersion;
        private Encoding mEncoding;


        /// <summary>
        /// Constructs a new instance of <see cref="MessageScriptCompiler"/> which will compile to the specified format.
        /// </summary>
        /// <param name="version">The version of the format to compile the output to.</param>
        /// <param name="encoding">The encoding to use for non-ASCII characters. If not specified, non-ASCII characters will be ignored unless they are stored as [x XX YY] tags.</param>
        public MessageScriptCompiler( MessageScriptFormatVersion version, Encoding encoding = null )
        {
            mVersion = version;
            mEncoding = encoding;
            mLogger = new Logger( nameof( MessageScriptCompiler ) );
            LoggerManager.RegisterLogger( mLogger );
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
        /// Compile the given input source. An exception is thrown on failure.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <returns>The output of the compilation.</returns>
        public MessageScript Compile( string input )
        {
            if ( !TryCompile(input, out var script))
                throw new MessageScriptCompilationFailureException();

            return script;
        }

        /// <summary>
        /// Compile the given input source. An exception is thrown on failure.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <returns>The output of the compilation.</returns>
        public MessageScript Compile( TextReader input )
        {
            if ( !TryCompile( input, out var script ) )
                throw new MessageScriptCompilationFailureException();

            return script;
        }

        /// <summary>
        /// Compile the given input source. An exception is thrown on failure.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <returns>The output of the compilation.</returns>
        public MessageScript Compile( Stream input )
        {
            if ( !TryCompile( input, out var script ) )
                throw new MessageScriptCompilationFailureException();

            return script;
        }

        /// <summary>
        /// Attempts to compile the given input source.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <param name="script">The output of the compilaton. Is only guaranteed to be valid if the operation succeeded.</param>
        /// <returns>A boolean value indicating whether the compilation succeeded or not.</returns>
        public bool TryCompile( string input, out MessageScript script )
        {
            var cst = MessageScriptParserHelper.ParseCompilationUnit( input );
            return TryCompile( cst, out script );
        }

        /// <summary>
        /// Attempts to compile the given input source.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <param name="script">The output of the compilaton. Is only guaranteed to be valid if the operation succeeded.</param>
        /// <returns>A boolean value indicating whether the compilation succeeded or not.</returns>
        public bool TryCompile( TextReader input, out MessageScript script )
        {
            var cst = MessageScriptParserHelper.ParseCompilationUnit( input, new AntlrErrorListener( this ) );
            return TryCompile( cst, out script );
        }

        /// <summary>
        /// Attempts to compile the given input source.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <param name="script">The output of the compilaton. Is only guaranteed to be valid if the operation succeeded.</param>
        /// <returns>A boolean value indicating whether the compilation succeeded or not.</returns>
        public bool TryCompile( Stream input, out MessageScript script )
        {
            var cst = MessageScriptParserHelper.ParseCompilationUnit( input, new AntlrErrorListener(this) );
            return TryCompile( cst, out script );
        }

        // Compilation methods
        private bool TryCompile( MessageScriptParser.CompilationUnitContext context, out MessageScript script )
        {
            if ( !TryCompileImpl( context, out script ) )
            {
                LogError( context, "Failed to compile message script" );
                return false;
            }

            return true;
        }

        private bool TryCompileImpl( MessageScriptParser.CompilationUnitContext context, out MessageScript script )
        {
            LogContextInfo( context );

            script = null;

            if ( !TryGetFatal( context, () => context.messageWindow(), "Expected message dialog window", out var messageWindowContexts))
            {
                return false;
            }

            script = new MessageScript( mVersion, mEncoding );

            foreach ( var messageWindowContext in messageWindowContexts )
            {
                IMessageScriptWindow messageWindow;

                if ( TryGet( messageWindowContext, () => messageWindowContext.dialogWindow(), out var dialogWindowContext))
                {
                    if ( !TryCompileDialogWindow( dialogWindowContext, out var dialogWindow ) )
                    {
                        LogError( dialogWindowContext, "Failed to compile dialog window" );
                        return false;
                    }

                    messageWindow = dialogWindow;
                }
                else if ( TryGet( messageWindowContext, () => messageWindowContext.selectionWindow(), out var selectionWindowContext ) )
                {
                    if ( !TryCompileSelectionWindow( selectionWindowContext, out var selectionWindow ) )
                    {
                        LogError( selectionWindowContext, "Failed to compile selection window" );
                        return false;
                    }

                    messageWindow = selectionWindow;
                }
                else
                {
                    LogError( messageWindowContext, "Expected dialog or selection window" );
                    return false;
                }

                script.Windows.Add( messageWindow );
            }

            return true;
        }

        private bool TryCompileDialogWindow( MessageScriptParser.DialogWindowContext context, out MessageScriptDialogWindow dialogWindow )
        {
            LogContextInfo( context );

            dialogWindow = null;

            //
            // Parse identifier
            //
            string identifier;
            {
                if ( !TryGetFatal( context, () => context.Identifier(), "Expected dialog window name", out var identifierNode ) )
                    return false;

                identifier = identifierNode.Symbol.Text;
            }

            //
            // Parse speaker name
            //
            IMessageScriptSpeaker speaker = null;
            if ( TryGet( context, () => context.dialogWindowSpeakerName(), out var speakerNameContentContext ) )
            {
                if ( !TryGetFatal( speakerNameContentContext, () => speakerNameContentContext.tagText(), "Expected dialog window speaker name text", out var speakerNameTagTextContext ) )
                    return false;

                if ( !TryCompileLines( speakerNameTagTextContext, out var speakerNameLines ) )
                {
                    LogError( speakerNameContentContext, "Failed to compile dialog window speaker name" );
                    return false;
                }

                if ( speakerNameLines.Count != 0 )
                {
                    if ( speakerNameLines.Count > 1 )
                        LogWarning( speakerNameTagTextContext, "More than 1 line for dialog window speaker name. Only the 1st line will be used" );

                    speaker = new MessageScriptNamedSpeaker( speakerNameLines[0] );
                }
            }

            // 
            // Parse text content
            //
            List<MessageScriptLine> lines;
            {
                if ( !TryGetFatal( context, () => context.tagText(), "Expected dialog window text", out var tagTextContext ) )
                    return false;

                if ( !TryCompileLines( tagTextContext, out lines ) )
                {
                    LogError( tagTextContext, "Failed to compile dialog window text" );
                    return false;
                }
            }

            //
            // Create dialog window
            //
            dialogWindow = new MessageScriptDialogWindow( identifier, speaker, lines );

            return true;
        }

        private bool TryCompileSelectionWindow( MessageScriptParser.SelectionWindowContext context, out MessageScriptSelectionWindow selectionWindow )
        {          
            LogContextInfo( context );

            selectionWindow = null;

            //
            // Parse identifier
            //
            string identifier;
            {
                if ( !TryGetFatal( context, () => context.Identifier(), "Expected selection window name", out var identifierNode ) )
                    return false;

                identifier = identifierNode.Symbol.Text;
            }

            // 
            // Parse text content
            //
            List<MessageScriptLine> lines;
            {
                if ( !TryGetFatal( context, () => context.tagText(), "Expected selection window text", out var tagTextContext ) )
                    return false;

                if ( !TryCompileLines( tagTextContext, out lines ) )
                {
                    LogError( tagTextContext, "Failed to compile selection window text" );
                    return false;
                }
            }

            //
            // Create Selection window
            //
            selectionWindow = new MessageScriptSelectionWindow( identifier, lines );

            return true;
        }

        private bool TryCompileLines( MessageScriptParser.TagTextContext context, out List<MessageScriptLine> lines )
        {
            LogContextInfo( context );

            lines = new List<MessageScriptLine>();
            MessageScriptLineBuilder lineBuilder = null;

            foreach ( var node in context.children )
            {
                IMessageScriptLineToken lineToken = null;

                if ( TryCast<MessageScriptParser.TagContext>( node, out var tagContext ) )
                {
                    if ( !TryGetFatal( context, () => tagContext.Identifier(), "Expected tag id", out var tagIdNode ) )
                        return false;

                    var tagId = tagIdNode.Symbol.Text;

                    switch ( tagId.ToLowerInvariant() )
                    {
                        case "f":
                            if ( !TryCompileFunctionToken( tagContext, out var functionToken ) )
                            {
                                mLogger.Error( "Failed to compile function token" );
                                return false;
                            }

                            lineToken = functionToken;
                            break;

                        case "n":
                            lineToken = new MessageScriptNewLineToken();
                            break;

                        case "e":
                            {
                                if ( lineBuilder == null )
                                {
                                    LogWarning( context, "Empty line" );
                                    lines.Add( new MessageScriptLine() );
                                }
                                else
                                {
                                    lines.Add( lineBuilder.Build() );
                                    lineBuilder = null;
                                }

                                continue;
                            }

                        case "x":
                            if ( !TryCompileCodePointToken( tagContext, out var codePointToken ) )
                            {
                                mLogger.Error( "Failed to compile code point token" );
                                return false;
                            }

                            lineToken = codePointToken;
                            break;

                        default:
                            {
                                LogError( tagContext, $"Unknown tag with id {tagId}" );
                                return false;
                            }
                    }
                }
                else if ( TryCast<ITerminalNode>( node, out var textNode ) )
                {
                    var text = textNode.Symbol.Text;

                    var textWithoutNewlines = Regex.Replace( text, @"\r?\n", "" );
                    if ( textWithoutNewlines.Length == 0 )
                        continue; // filter out standalone newlines

                    lineToken = new MessageScriptTextToken( textWithoutNewlines );
                }
                else
                {
                    if ( node is ParserRuleContext )
                    {
                        LogError( node as ParserRuleContext, "Expected a tag or text, but got neither." );
                    }
                    else
                    {
                        LogError( context, "Expected a tag or text, but got neither." );
                    }

                    return false;
                }

                if ( lineBuilder == null )
                    lineBuilder = new MessageScriptLineBuilder();

                Debug.Assert( lineToken != null, "Line token shouldn't be null" );

                lineBuilder.AddToken( lineToken );
            }

            if ( lineBuilder != null )
            {
                lines.Add( lineBuilder.Build() );
            }

            return true;
        }

        private bool TryCompileFunctionToken( MessageScriptParser.TagContext context,  out MessageScriptFunctionToken functionToken )
        {
            LogContextInfo( context );

            functionToken = new MessageScriptFunctionToken();

            if ( !TryGetFatal( context, () => context.IntLiteral(), "Expected arguments", out var argumentNodes ) )
                return false;

            if ( !TryParseShortIntLiteral( context, "Expected function table index", () => argumentNodes[0], out var functionTableIndex ) )
                return false;

            if ( !TryParseShortIntLiteral( context, "Expected function index", () => argumentNodes[1], out var functionIndex ) )
                return false;

            if ( argumentNodes.Length > 2 )
            {
                List<short> arguments = new List<short>( argumentNodes.Length - 2 );
                for ( int i = 2; i < argumentNodes.Length; i++ )
                {
                    if ( !TryParseShortIntLiteral( context, "Expected function argument", () => argumentNodes[i], out var argument ) )
                        return false;

                    arguments.Add( argument );
                }

                functionToken = new MessageScriptFunctionToken( functionTableIndex, functionIndex, arguments );
            }
            else
            {
                functionToken = new MessageScriptFunctionToken( functionTableIndex, functionIndex );
            }

            return true;
        }

        private bool TryCompileCodePointToken( MessageScriptParser.TagContext context, out MessageScriptCodePointToken codePointToken )
        {
            LogContextInfo( context );

            codePointToken = new MessageScriptCodePointToken();

            if ( !TryGetFatal( context, () => context.IntLiteral(), "Expected code point surrogate pair", out var argumentNodes ) )
                return false;

            if ( !TryParseByteIntLiteral( context, "Expected code point high surrogate", () => argumentNodes[0], out var highSurrogate ) )
                return false;

            if ( !TryParseByteIntLiteral( context, "Expected code point low surrogate", () => argumentNodes[1], out var lowSurrogate ) )
                return false;

            codePointToken = new MessageScriptCodePointToken( highSurrogate, lowSurrogate );

            return true;
        }

        // Predicate helpers
        private bool TryGetFatal<T>( ParserRuleContext context, Func<T> getFunc, string errorText, out T value )
        {
            bool success = TryGet( context, getFunc, out value );

            if ( !success )
                LogError( context, errorText );

            return success;
        }

        private bool TryGet<T>( ParserRuleContext context, Func<T> getFunc, out T value )
        {
            try
            {
                value = getFunc();
            }
            catch ( Exception e )
            {
                value = default( T );
                return false;
            }

            if ( value == null )
                return false;

            return true;
        }

        private bool TryCast<T>( object obj, out T value ) where T : class
        {
            value = obj as T;
            return value != null;
        }

        // Int literal parsing
        private bool TryParseShortIntLiteral( ParserRuleContext context, string failureText, Func<ITerminalNode> getFunc, out short value )
        {
            value = -1;

            if ( !TryGetFatal( context, getFunc, failureText, out var node ) )
                return false;

            if ( !TryParseIntLiteral( node, out var intValue ) )
                return false;

            // Todo: range checking?
            value = (short)intValue;

            return true;
        }

        private bool TryParseByteIntLiteral( ParserRuleContext context, string failureText, Func<ITerminalNode> getFunc, out byte value )
        {
            value = 0;

            if ( !TryGetFatal( context, getFunc, failureText, out var node ) )
                return false;

            if ( !TryParseIntLiteral( node, out var intValue ) )
                return false;

            // Todo: range checking?
            value = ( byte )intValue;

            return true;
        }

        private bool TryParseIntLiteral( ITerminalNode node, out int value )
        {
            bool succeeded;

            if ( node.Symbol.Text.StartsWith( "0x" ) )
            {
                succeeded = int.TryParse( node.Symbol.Text.Substring( 2 ), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value );
            }
            else
            {
                succeeded = int.TryParse( node.Symbol.Text, out value );
            }

            if ( !succeeded )
            {
                LogError( node.Symbol, "Invalid integer format" );
            }

            return succeeded;
        }

        // Logging
        private void LogContextInfo( ParserRuleContext context )
        {
            mLogger.Info( $"Compiling {MessageScriptParser.ruleNames[context.RuleIndex]} ({context.Start.Line}:{context.Start.Column})" );
        }

        private void LogError( ParserRuleContext context, string str )
        {
            mLogger.Error( $"{str} ({context.Start.Line}:{context.Start.Column})" );
        }

        private void LogError( IToken token, string str )
        {
            mLogger.Error( $"{str} ({token.Line}:{token.Column})" );
        }

        private void LogWarning( ParserRuleContext context, string str )
        {
            mLogger.Warning( $"{str} ({context.Start.Line}:{context.Start.Column})" );
        }

        /// <summary>
        /// Antlr error listener for catching syntax errors while parsing.
        /// </summary>
        private class AntlrErrorListener : IAntlrErrorListener<IToken>
        {
            private MessageScriptCompiler mCompiler;

            public AntlrErrorListener( MessageScriptCompiler compiler )
            {
                mCompiler = compiler;
            }

            public void SyntaxError( IRecognizer recognizer, IToken offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e )
            {
                mCompiler.mLogger.Error( $"Syntax error: {msg} ({offendingSymbol.Line}:{offendingSymbol.Column})" );
            }
        }
    }

    public class MessageScriptCompilationFailureException : Exception
    {
        public MessageScriptCompilationFailureException()
            : base("Failed to compile message script")
        {
        }
    }
}
