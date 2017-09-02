using System.Collections.Generic;

namespace AtlusScriptLib
{
    public class MessageScriptLineBuilder
    {
        private List<IMessageScriptLineToken> mTokens;

        public MessageScriptLineBuilder()
        {
            mTokens = new List<IMessageScriptLineToken>();
        }

        public MessageScriptLineBuilder AddToken( IMessageScriptLineToken token )
        {
            mTokens.Add( token );
            return this;
        }

        public MessageScriptLineBuilder AddText( string text )
        {
            return AddToken( new MessageScriptTextToken( text ) );
        }

        public MessageScriptLineBuilder AddFunction( int functionTableIndex, int functionIndex, params short[] args )
        {
            return AddToken( new MessageScriptFunctionToken( functionTableIndex, functionIndex, args ) );
        }

        public MessageScriptLineBuilder AddCodePoint( byte highSurrogate, byte lowSurrogate )
        {
            return AddToken( new MessageScriptCodePointToken( highSurrogate, lowSurrogate ) );
        }

        public MessageScriptLineBuilder AddNewLine()
        {
            return AddToken( new MessageScriptNewLineToken() );
        }

        public MessageScriptLine Build()
        {
            return new MessageScriptLine( mTokens );
        }
    }
}
