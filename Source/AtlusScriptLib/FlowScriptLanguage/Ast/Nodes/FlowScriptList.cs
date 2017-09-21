using System.Collections;
using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptList<T> : FlowScriptAstNode, IList<T> where T : FlowScriptAstNode
    {
        private List<T> mList;

        public T this[int index] { get => ( ( IList<T> )mList )[index]; set => ( ( IList<T> )mList )[index] = value; }

        public int Count => ( ( IList<T> )mList ).Count;

        public bool IsReadOnly => ( ( IList<T> )mList ).IsReadOnly;

        public void Add( T item )
        {
            ( ( IList<T> )mList ).Add( item );
        }

        public void Clear()
        {
            ( ( IList<T> )mList ).Clear();
        }

        public bool Contains( T item )
        {
            return ( ( IList<T> )mList ).Contains( item );
        }

        public void CopyTo( T[] array, int arrayIndex )
        {
            ( ( IList<T> )mList ).CopyTo( array, arrayIndex );
        }

        public IEnumerator<T> GetEnumerator()
        {
            return ( ( IList<T> )mList ).GetEnumerator();
        }

        public int IndexOf( T item )
        {
            return ( ( IList<T> )mList ).IndexOf( item );
        }

        public void Insert( int index, T item )
        {
            ( ( IList<T> )mList ).Insert( index, item );
        }

        public bool Remove( T item )
        {
            return ( ( IList<T> )mList ).Remove( item );
        }

        public void RemoveAt( int index )
        {
            ( ( IList<T> )mList ).RemoveAt( index );
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ( ( IList<T> )mList ).GetEnumerator();
        }
    }
}
