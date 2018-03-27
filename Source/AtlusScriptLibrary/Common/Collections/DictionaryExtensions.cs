using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.Collections
{
    public static class DictionaryExtensions
    {
        public static Dictionary<TValue, TKey> Reverse<TKey, TValue>( this IDictionary<TKey, TValue> source )
        {
            var dictionary = new Dictionary<TValue, TKey>();
            foreach ( var entry in source )
            {
                if ( !dictionary.ContainsKey( entry.Value ) )
                    dictionary.Add( entry.Value, entry.Key );
            }
            return dictionary;
        }
    }
}
