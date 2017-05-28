using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Text
{
    public interface ITextOutputProvider : IDisposable
    {
        void WriteLine();

        void WriteLine(string value);

        void WriteLine(object value);

        void Write(char value);

        void Write(string value);

        void Write(object value);
    }
}
