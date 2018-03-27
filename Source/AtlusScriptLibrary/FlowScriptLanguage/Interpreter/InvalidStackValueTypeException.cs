using System;
using System.Runtime.Serialization;

namespace AtlusScriptLibrary.FlowScriptLanguage.Interpreter
{
    [Serializable]
    public class InvalidStackValueTypeException : InvalidOperationException
    {
        public InvalidStackValueTypeException( StackValueKind expected, StackValueKind got ) : base( $"The parameter type is invalid. Expected: {expected}. Got: {got}." )
        {
        }

        public InvalidStackValueTypeException( string message ) : base( message )
        {
        }

        public InvalidStackValueTypeException( string message, Exception innerException ) : base( message, innerException )
        {
        }

        protected InvalidStackValueTypeException( SerializationInfo info, StreamingContext context ) : base( info, context )
        {
        }
    }
}