using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AtlusScriptLib.Common.Registry;
using AtlusScriptLib.Common;

namespace AtlusScriptLib.MessageScriptLanguage.Decompiler
{
    public sealed class MessageScriptDecompiler : IDisposable
    {
        private readonly TextWriter mWriter;

        public LibraryRegistry LibraryRegistry { get; set; }

        public bool OmitUnusedFunctions { get; set; } = true;

        public MessageScriptDecompiler( TextWriter writer )
        {
            mWriter = writer;
        }

        public void Decompile( MessageScript script )
        {
            foreach ( var message in script.Windows )
            {
                Decompile( message );
                mWriter.WriteLine();
            }
        }

        public void Decompile( IMessageScriptWindow message )
        {
            switch ( message.Type )
            {
                case MessageScriptWindowType.Dialogue:
                    Decompile( ( MessageScriptDialogWindow )message );
                    break;
                case MessageScriptWindowType.Selection:
                    Decompile( ( MessageScriptSelectionWindow )message );
                    break;

                default:
                    throw new NotImplementedException( message.Type.ToString() );
            }
        }

        public void Decompile( MessageScriptDialogWindow message )
        {
            if ( message.Speaker != null )
            {
                switch ( message.Speaker.Type )
                {
                    case MessageScriptSpeakerType.Named:
                        {
                            WriteOpenTag( "dlg" );
                            WriteTagArgument( message.Identifier );
                            {
                                mWriter.Write( " " );

                                var speaker = ( MessageScriptNamedSpeaker )message.Speaker;
                                if ( speaker.Name != null )
                                {
                                    WriteOpenTag();
                                    Decompile( speaker.Name, false );
                                    WriteCloseTag();
                                }
                            }
                            WriteCloseTag();
                        }
                        break;

                    case MessageScriptSpeakerType.Variable:
                        {
                            WriteOpenTag( "dlg" );
                            WriteTagArgument( message.Identifier );
                            {
                                mWriter.Write( " " );
                                WriteOpenTag();
                                mWriter.Write( ( ( MessageScriptVariableSpeaker )message.Speaker ).Index.ToString() );
                                WriteCloseTag();
                            }
                            WriteCloseTag();
                        }
                        break;
                }
            }
            else
            {
                WriteTag( "dlg", message.Identifier );
            }

            mWriter.WriteLine();

            foreach ( var line in message.Lines )
            {
                Decompile( line );
                mWriter.WriteLine();
            }
        }

        public void Decompile( MessageScriptSelectionWindow message )
        {
            WriteTag( "sel", message.Identifier );
            mWriter.WriteLine();

            foreach ( var line in message.Lines )
            {
                Decompile( line );
                mWriter.WriteLine();
            }
        }

        public void Decompile( MessageScriptLine line, bool emitLineEndTag = true )
        {
            foreach ( var token in line.Tokens )
            {
                Decompile( token );
            }

            if ( emitLineEndTag )
                WriteTag( "e" );
        }

        public void Decompile( IMessageScriptLineToken token )
        {
            switch ( token.Type )
            {
                case MessageScriptTokenType.Text:
                    Decompile( ( MessageScriptTextToken )token );
                    break;
                case MessageScriptTokenType.Function:
                    Decompile( ( MessageScriptFunctionToken )token );
                    break;
                case MessageScriptTokenType.CodePoint:
                    Decompile( ( MessageScriptCodePointToken )token );
                    break;
                case MessageScriptTokenType.NewLine:
                    Decompile( ( MessageScriptNewLineToken )token );
                    break;

                default:
                    throw new NotImplementedException( token.Type.ToString() );
            }
        }

        public void Decompile( MessageScriptFunctionToken token )
        {
            if ( LibraryRegistry != null )
            {
                var library = LibraryRegistry.MessageScriptLibraries.FirstOrDefault( x => x.Index == token.FunctionTableIndex );
                if ( library != null )
                {
                    var function = library.Functions.FirstOrDefault( x => x.Index == token.FunctionIndex );
                    if ( function != null )
                    {
                        if ( function.Name == "@Unused" && OmitUnusedFunctions )
                            return;

                        if ( !string.IsNullOrWhiteSpace( function.Name ) )
                        {
                            WriteOpenTag( function.Name );

                            for ( var i = 0; i < function.Parameters.Count; i++ )
                            {
                                var argument = function.Parameters[i];
                                WriteTagArgument( token.Arguments[i].ToString() );
                            }

                            WriteCloseTag();
                            return;
                        }
                    }
                }
            }

            if ( token.Arguments.Count == 0 )
            {
                WriteTag( "f", token.FunctionTableIndex.ToString(), token.FunctionIndex.ToString() );
            }
            else
            {
                WriteOpenTag( "f" );
                WriteTagArgument( token.FunctionTableIndex.ToString() );
                WriteTagArgument( token.FunctionIndex.ToString() );

                foreach ( var tokenArgument in token.Arguments )
                {
                    WriteTagArgument( tokenArgument.ToString() );
                }

                WriteCloseTag();
            }
        }

        public void Decompile( MessageScriptTextToken token )
        {
            mWriter.Write( token.Text );
        }

        public void Decompile( MessageScriptCodePointToken token )
        {
            WriteTag( $"x 0x{token.HighSurrogate:X2} 0x{token.LowSurrogate:X2}" );
        }

        public void Decompile( MessageScriptNewLineToken token )
        {
            WriteTag( "n" );
        }

        public void Dispose()
        {
            mWriter.Dispose();
        }

        private void WriteOpenTag()
        {
            mWriter.Write( "[" );
        }

        private void WriteOpenTag( string tag )
        {
            mWriter.Write( $"[{tag}" );
        }

        private void WriteTagArgument( string argument )
        {
            mWriter.Write( " " );
            mWriter.Write( argument );
        }

        private void WriteCloseTag()
        {
            mWriter.Write( "]" );
        }

        private void WriteTag( string tag, params string[] arguments )
        {
            WriteOpenTag( tag );

            if ( arguments.Length != 0 )
            {
                foreach ( var argument in arguments )
                {
                    WriteTagArgument( argument );
                }
            }

            WriteCloseTag();
        }
    }
}
