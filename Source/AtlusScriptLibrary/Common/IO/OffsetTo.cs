namespace AtlusScriptLibrary.Common.IO
{
    /// <summary>
    /// Nice little mutable struct for holding an address & its object to which the address points.
    /// </summary>
    /// <typeparam name="TValue"></typeparam>
    public struct OffsetTo<TValue>
    {
        /// <summary>
        /// Offset of the value.
        /// </summary>
        public int Offset;

        /// <summary>
        /// Value the offset points to.
        /// </summary>
        public TValue Value;

        public OffsetTo( int offset )
        {
            Offset = offset;
            Value = default( TValue );
        }

        public OffsetTo( TValue value )
        {
            Offset = 0;
            Value = value;
        }

        public OffsetTo( int address, TValue value )
        {
            Offset = address;
            Value = value;
        }
    }
}
