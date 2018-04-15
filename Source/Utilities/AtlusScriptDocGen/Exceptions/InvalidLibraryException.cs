using System;
using System.Runtime.Serialization;

namespace AtlusScriptDocGen.Exceptions
{
    [Serializable]
    internal class InvalidLibraryException : Exception
    {
        public string LibraryName { get; }

        public InvalidLibraryException()
        {
        }

        public InvalidLibraryException( string libraryName ) : base( libraryName, null )
        {
        }

        public InvalidLibraryException( string libraryName, Exception innerException ) : base( $"No library with name '{libraryName}' exists.", innerException )
        {
            LibraryName = libraryName;
        }

        protected InvalidLibraryException( SerializationInfo info, StreamingContext context ) : base( info, context )
        {
        }
    }
}