using System;

namespace AtlusScriptDocGen
{
    public class MissingMandatoryArgumentException : Exception
    {
        public string ArgumentName { get; }

        public MissingMandatoryArgumentException( string name ) : base( $"Missing mandatory argument: {name}" )
        {
            ArgumentName = name;
        }
    }
}