using System.Collections.Generic;

namespace AtlusScriptLib.MessageScriptLanguage
{
    public class TextBuilder
    {
        private List<IToken> mTokens;

        public TextBuilder()
        {
            mTokens = new List<IToken>();
        }

        public TextBuilder AddToken( IToken token )
        {
            mTokens.Add( token );
            return this;
        }

        public TextBuilder AddString( string value )
        {
            return AddToken( new StringToken( value ) );
        }

        public TextBuilder AddFunction( int functionTableIndex, int functionIndex, params short[] args )
        {
            return AddToken( new FunctionToken( functionTableIndex, functionIndex, args ) );
        }

        public TextBuilder AddCodePoint( byte highSurrogate, byte lowSurrogate )
        {
            return AddToken( new CodePointToken( highSurrogate, lowSurrogate ) );
        }

        public TextBuilder AddNewLine()
        {
            return AddToken( new NewLineToken() );
        }

        public TokenText Build()
        {
            return new TokenText( mTokens );
        }
    }
}
