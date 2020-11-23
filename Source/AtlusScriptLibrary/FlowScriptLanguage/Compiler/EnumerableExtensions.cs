using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler
{
    internal static class EnumerableExtensions
    {
        public static TOut MaxOrDefault<TIn, TOut>( this IEnumerable<TIn> enumerable, Func<TIn, TOut> selector, TOut defaultValue )
            where TOut : IComparable<TOut>
        {
            var max = defaultValue;
            foreach ( var item in enumerable )
            {
                var val = selector( item );
                if ( val.CompareTo( max ) > 0 )
                    max = val;
            }

            return max;
        }
    }
}
