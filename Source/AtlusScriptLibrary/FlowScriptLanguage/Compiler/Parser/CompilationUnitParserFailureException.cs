using System;
using System.Runtime.Serialization;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    [Serializable]
    public class FlowScriptSyntaxParserFailureException : Exception
    {
        public FlowScriptSyntaxParserFailureException()
        {
        }

        public FlowScriptSyntaxParserFailureException( string message ) : base( message )
        {
        }

        public FlowScriptSyntaxParserFailureException( string message, Exception innerException ) : base( message, innerException )
        {
        }

        protected FlowScriptSyntaxParserFailureException( SerializationInfo info, StreamingContext context ) : base( info, context )
        {
        }
    }
}