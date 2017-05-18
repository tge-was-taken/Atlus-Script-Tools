using System.Collections.Generic;

namespace AtlusScriptLib.Common
{
    public enum CommandLineOptionNecessity
    {
        Required,
        Optional
    }

    public class CommandLineOption : CommandLineArgument
    {
        public int ArgumentCount { get; }

        public CommandLineOptionNecessity Necessity { get; }

        public bool TakesArguments => ArgumentCount > 0;

        public List<string> Arguments { get; }

        public CommandLineOption(string identifier, int argCount, CommandLineOptionNecessity necessity)
            : base(identifier)
        {
            ArgumentCount = argCount;
            Necessity = necessity;
            Arguments = new List<string>();
        }
    }
}
