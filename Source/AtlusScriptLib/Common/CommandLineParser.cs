using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common
{
    public class CommandLineParser
    {
        private string[] mArgs;
        private Dictionary<string, CommandLineOption> mRegisteredOptions;

        public CommandLineParser(string[] args)
        {
            mArgs = args;
            mRegisteredOptions = new Dictionary<string, CommandLineOption>();
        }

        public void RegisterOption(CommandLineOption option)
        {
            mRegisteredOptions.Add(option.Identifier, option);
        }

        public Dictionary<string, CommandLineOption> Parse()
        {
            var options = new Dictionary<string, CommandLineOption>();

            int argIndex = 0;
            while (argIndex < mArgs.Length)
            {
                string identifier = mArgs[argIndex++].TrimStart('-');

                bool isOption = mRegisteredOptions.ContainsKey(identifier);
                if (!isOption)
                    continue;

                var option = mRegisteredOptions[identifier];
                if (option.TakesArguments)
                {
                    for (int i = 0; i < option.ArgumentCount; i++)
                    {
                        if (argIndex >= mArgs.Length)
                            throw new Exception($"Argument {i + 1} for '{option.Identifier}' is missing");

                        option.Arguments.Add(mArgs[argIndex++]);
                    }
                }

                options.Add(option.Identifier, option);
            }

            var requiredOptions = mRegisteredOptions.Values.Where(x => x.Necessity == CommandLineOptionNecessity.Required);
            foreach (var requiredOption in requiredOptions)
            {
                if (!options.Values.Contains(requiredOption))
                {
                    throw new Exception($"Required argument '{requiredOption.Identifier}' is missing");
                }
            }

            return options;
        }
    }
}
