using System;
using System.Runtime.Serialization;

namespace AtlusScriptDocGen.Exceptions
{
    [Serializable]
    internal class MissingArgumentValueException : Exception
    {
        public string ArgumentName { get; }

        public string MissingValueDescription { get; }

        public MissingArgumentValueException( string argumentName, string missingValueDescription ) : this(argumentName, missingValueDescription, null )
        {
        }

        public MissingArgumentValueException( string argumentName, string missingValueDescription, Exception innerException ) : base( "", innerException )
        {
            ArgumentName = argumentName;
            MissingValueDescription = missingValueDescription;
        }

        protected MissingArgumentValueException( SerializationInfo info, StreamingContext context ) : base( info, context )
        {
        }
    }
}