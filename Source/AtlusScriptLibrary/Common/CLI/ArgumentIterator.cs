using System;
using System.Collections;
using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.CLI
{
    public sealed class ArgumentIterator : IEnumerator<string>
    {
        public string[] Arguments { get; }

        public int Index { get; private set; }

        public string Current => Arguments[ Index ];

        public bool HasNext => Index + 1 < Arguments.Length;

        object IEnumerator.Current => Current;

        public ArgumentIterator( string[] arguments )
        {
            Arguments = arguments;
        }

        public bool MoveNext()
        {
            if ( !HasNext )
                return false;

            ++Index;
            return true;
        }

        public bool TryGetNextArgument( out string arg )
        {
            if ( !MoveNext() )
            {
                arg = null;
                return false;
            }

            arg = Current;
            return true;
        }

        public void Reset()
        {
            Index = 0;
        }

        public void Dispose()
        {
            // Nothing to dispose
        }
    }
}