using System.Collections.Generic;

namespace AtlusScriptLibrary.MessageScriptLanguage
{
    public class TokenTextBuilder
    {
        private readonly List<IToken> mTokens;

        public TokenTextBuilder()
        {
            mTokens = new List<IToken>();
        }

        public TokenTextBuilder AddToken( IToken token )
        {
            mTokens.Add( token );
            return this;
        }

        public TokenTextBuilder AddString( string value )
        {
            return AddToken( new StringToken( value ) );
        }

        public TokenTextBuilder AddFunction( int functionTableIndex, int functionIndex, params short[] args )
        {
            return AddToken( new FunctionToken( functionTableIndex, functionIndex, args ) );
        }

        public TokenTextBuilder AddCodePoint( byte highSurrogate, byte lowSurrogate )
        {
            return AddToken( new CodePointToken( highSurrogate, lowSurrogate ) );
        }

        public TokenTextBuilder AddNewLine()
        {
            return AddToken( new NewLineToken() );
        }

        public TokenText Build()
        {
            return new TokenText( mTokens );
        }
    }
}
