using System;
using System.Runtime.Serialization;

namespace AtlusScriptLibrary.FlowScriptLanguage.Interpreter
{
    [Serializable]
    public class StackUnderflowException : InvalidOperationException
    {
        public StackUnderflowException() : base( "The interpreter attempted to pop a value off the stack while the stack is empty" )
        {
        }

        public StackUnderflowException( string message ) : base( message )
        {
        }

        public StackUnderflowException( string message, Exception innerException ) : base( message, innerException )
        {
        }

        protected StackUnderflowException( SerializationInfo info, StreamingContext context ) : base( info, context )
        {
        }
    }
}