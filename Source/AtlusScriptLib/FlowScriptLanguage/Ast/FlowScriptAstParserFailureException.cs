using System;
using System.Runtime.Serialization;

namespace AtlusScriptLib.FlowScriptLanguage.Ast
{
    [Serializable]
    public class FlowScriptAstParserFailureException : Exception
    {
        public FlowScriptAstParserFailureException()
        {
        }

        public FlowScriptAstParserFailureException( string message ) : base( message )
        {
        }

        public FlowScriptAstParserFailureException( string message, Exception innerException ) : base( message, innerException )
        {
        }

        protected FlowScriptAstParserFailureException( SerializationInfo info, StreamingContext context ) : base( info, context )
        {
        }
    }
}