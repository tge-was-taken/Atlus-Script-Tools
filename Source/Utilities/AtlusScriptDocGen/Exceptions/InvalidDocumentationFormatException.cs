using System;

namespace AtlusScriptDocGen.Exceptions
{
    internal sealed class InvalidDocumentationFormatException : Exception
    {
        public string DocumentFormat { get; }

        public InvalidDocumentationFormatException( string docFormatStr ) : base( $"No documentation format with name '{docFormatStr}' exists")
        {
            DocumentFormat = docFormatStr;
        }
    }
}