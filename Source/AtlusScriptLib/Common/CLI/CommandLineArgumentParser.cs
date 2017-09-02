using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace AtlusScriptLib.CLI
{
    public sealed class CommandLineArgumentParser
    {
        private string[] mStrArgs;
        private int mStrArgIndex;
        private readonly List<ICommandLineArgument> mArgs;
        private readonly Dictionary<string, ICommandLineArgument> mArgsByKey;

        public string Description { get; set; }

        public IReadOnlyList<ICommandLineArgument> Arguments
        {
            get { return mArgs.AsReadOnly(); }
        }

        public IReadOnlyDictionary<string, ICommandLineArgument> ArgumentsByKey
        {
            get { return new ReadOnlyDictionary<string, ICommandLineArgument>( mArgsByKey ); }
        }

        public CommandLineArgumentParser()
        {
            mArgs = new List<ICommandLineArgument>();
            mArgsByKey = new Dictionary<string, ICommandLineArgument>();
        }

        public void AddArgument( ICommandLineArgument argument )
        {
            mArgs.Add( argument );
            mArgsByKey[argument.Key] = argument;
        }

        public void AddArguments( params ICommandLineArgument[] arguments )
        {
            foreach ( var arg in arguments )
            {
                AddArgument( arg );
            }
        }

        public void Parse( string[] args )
        {
            mStrArgs = args;
            ParseInternal();
        }

        public string GetArgumentInfoString()
        {
            int columnWidth = 10;

            var stringBuilder = new StringBuilder()

            // info header

            /*
            .AppendLine()
            .AppendLine(Description)
            */
            .AppendLine()
            .AppendLine( "Possible arguments:" )
            .AppendLine()

            // argument info header row
            .Append( "key".PadRight( columnWidth ) )
            .Append( "required".PadRight( columnWidth ) )
            .Append( "default".PadRight( columnWidth ) )
            .Append( "description".PadRight( columnWidth ) )
            .AppendLine();

            foreach ( var arg in mArgs )
            {
                // argument info row
                stringBuilder
                    .Append( arg.Key.PadRight( columnWidth ) )
                    .Append( ( arg.Required ? "yes" : "no" ).PadRight( columnWidth ) )
                    .Append( ( ( arg.DefaultValue ?? "none" ).ToString() ).ToLower().PadRight( columnWidth ) )
                    .Append( ( arg.Description ?? "no description" ).PadRight( columnWidth ) )
                    .AppendLine();
            }

            return stringBuilder.ToString();
        }

        private void ParseInternal()
        {
            while ( FindArgumentKey( out string key ) )
            {
                var arg = mArgsByKey[key];
                var argValues = FindArgumentValues();

                arg.IsValueProvided = true;

                if ( arg.TakesParameters )
                {
                    if ( argValues.Count == 0 )
                        throw new Exception( $"Missing parameter for argument {arg.Key}" );

                    arg.Value = argValues[0];
                }
                else
                {
                    arg.Value = true;
                }
            }

            VerifyParsedArguments();
        }

        private void VerifyParsedArguments()
        {
            foreach ( var arg in Arguments )
            {
                if ( arg.Required && !arg.IsValueProvided )
                    throw new Exception( $"Missing required argument {arg.Key}" );

                if ( arg.IsValueProvided && arg.PossibleValues != null && !arg.PossibleValues.Any( x => x == arg.Value ) )
                    throw new Exception( $"Argument {arg.Key} has an invalid value" );
            }
        }

        private bool FindArgumentKey( out string key )
        {
            while ( mStrArgIndex < mStrArgs.Length )
            {
                key = mStrArgs[mStrArgIndex++];

                if ( key.StartsWith( "-" ) )
                {
                    return true;
                }
            }

            key = null;
            return false;
        }

        private List<string> FindArgumentValues()
        {
            var values = new List<string>();

            while ( mStrArgIndex < mStrArgs.Length )
            {
                string value = mStrArgs[mStrArgIndex++];

                if ( value.StartsWith( "-" ) )
                {
                    mStrArgIndex--;
                    break;
                }
                else
                {
                    values.Add( value );
                }
            }

            return values;
        }
    }
}
