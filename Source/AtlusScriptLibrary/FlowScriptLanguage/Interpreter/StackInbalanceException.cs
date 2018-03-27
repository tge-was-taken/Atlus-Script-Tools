using System;
using System.Runtime.Serialization;

namespace AtlusScriptLibrary.FlowScriptLanguage.Interpreter
{
    [Serializable]
    internal class StackInbalanceException : Exception
    {
        public StackInbalanceException() : base("More than 1 value on the stack after execution has finished")
        {
        }

        public StackInbalanceException( string message ) : base( message )
        {
        }

        public StackInbalanceException( string message, Exception innerException ) : base( message, innerException )
        {
        }

        protected StackInbalanceException( SerializationInfo info, StreamingContext context ) : base( info, context )
        {
        }
    }
}