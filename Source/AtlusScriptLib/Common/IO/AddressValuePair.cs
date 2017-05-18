using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.IO
{
    // Nice little mutable struct for holding an address & its object to which the address points
    public struct AddressValuePair<TValue>
    {
        public int Address;

        public TValue Value;

        public AddressValuePair(int address)
        {
            Address = address;
            Value = default(TValue);
        }

        public AddressValuePair(TValue value)
        {
            Address = 0; 
            Value = value;
        }

        public AddressValuePair(int address, TValue value)
        {
            Address = address;
            Value = value;
        }
    }
}
