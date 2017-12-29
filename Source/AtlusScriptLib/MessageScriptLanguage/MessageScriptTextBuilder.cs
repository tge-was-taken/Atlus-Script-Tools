using System.Collections.Generic;

namespace AtlusScriptLib.MessageScriptLanguage
{
    public class MessageScriptTextBuilder
    {
        private List<IMessageScriptTextToken> mTokens;

        public MessageScriptTextBuilder()
        {
            mTokens = new List<IMessageScriptTextToken>();
        }

        public MessageScriptTextBuilder AddToken( IMessageScriptTextToken token )
        {
            mTokens.Add( token );
            return this;
        }

        public MessageScriptTextBuilder AddString( string value )
        {
            return AddToken( new MessageScriptStringToken( value ) );
        }

        public MessageScriptTextBuilder AddFunction( int functionTableIndex, int functionIndex, params short[] args )
        {
            return AddToken( new MessageScriptFunctionToken( functionTableIndex, functionIndex, args ) );
        }

        public MessageScriptTextBuilder AddCodePoint( byte highSurrogate, byte lowSurrogate )
        {
            return AddToken( new MessageScriptCodePointToken( highSurrogate, lowSurrogate ) );
        }

        public MessageScriptTextBuilder AddNewLine()
        {
            return AddToken( new MessageScriptNewLineToken() );
        }

        public MessageScriptText Build()
        {
            return new MessageScriptText( mTokens );
        }
    }
}
