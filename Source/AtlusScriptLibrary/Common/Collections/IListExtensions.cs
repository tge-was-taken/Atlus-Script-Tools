using System.Collections.Generic;
using System.Diagnostics;

namespace AtlusScriptLibrary.Common.Collections
{
    public static class IListExtensions
    {
        /// <summary>
        /// Retrieves the last entry of the list.
        /// </summary>
        public static T GetLast<T>( this IList<T> list )
        {
            return list[list.Count - 1];
        }

        /// <summary>
        /// Retrieves the previous entry of the list given the current index.
        /// </summary>
        public static T GetPrevious<T>( this IList<T> list, int curIndex )
        {
            return list[curIndex - 1];
        }

        public static void AddRange<T>( this IList<T> list, params T[] items )
        {
            foreach ( var item in items )
            {
                list.Add( item );
            }
        }

        public static void RemoveLast<T>( this IList<T> list, T obj )
        {
            int index = -1;
            for ( int i = list.Count - 1; i >= 0; i-- )
            {
                if ( list[i].Equals( obj ) )
                {
                    index = i;
                    break;
                }
            }

            if ( index == -1 )
            {
                //throw new Exception("Element to remove not present in List");
                Debug.WriteLine( $"Element {obj} to remove not present in List" );
            }
            else
            {
                list.RemoveAt( index );
            }
        }

        public static void RemoveLast<T>( this IList<T> list, params T[] objs )
        {
            foreach ( var obj in objs )
            {
                list.RemoveLast( obj );
            }
        }

        public static void ReplaceLast<T>( this IList<T> list, T replacement, T replacee )
        {
            int index = -1;
            for ( int i = list.Count - 1; i >= 0; i-- )
            {
                if ( list[i].Equals( replacee ) )
                {
                    index = i;
                    break;
                }
            }

            if ( index == -1 )
            {
                //throw new Exception("Element to replace not present in List");
                Debug.WriteLine( $"Element {replacee} to replace not present in List" );
            }
            else
            {
                list[index] = replacement;
            }
        }

        public static void ReplaceLast<T>( this IList<T> list, T replacement, params T[] replacees )
        {
            foreach ( var replacee in replacees )
            {
                list.ReplaceLast( replacement, replacee );
            }
        }
    }
}
