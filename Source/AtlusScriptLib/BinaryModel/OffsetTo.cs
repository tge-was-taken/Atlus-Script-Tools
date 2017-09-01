using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.BinaryModel
{
    // Nice little mutable struct for holding an address & its object to which the address points
    public struct OffsetTo<TValue>
    {
        public int Offset;

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
