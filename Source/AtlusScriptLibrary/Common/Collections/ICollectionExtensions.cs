using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.Collections
{
    public static class ICollectionExtensions
    {
        public static void Add<T>( this ICollection<T> collection, params T[] items )
        {
            foreach ( T item in items )
            {
                collection.Add( item );
            }
        }
    }
}
