using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Text
{
    public class StringBuilderTextOutputProvider : ITextOutputProvider
    {
        public StringBuilder StringBuilder { get; }

        public StringBuilderTextOutputProvider()
        {
            StringBuilder = new StringBuilder();
        }

        public StringBuilderTextOutputProvider(StringBuilder stringBuilder)
        {
            StringBuilder = stringBuilder ?? throw new ArgumentNullException(nameof(stringBuilder));
        }

        public void WriteLine()
        {
            StringBuilder.AppendLine();
        }

        public void WriteLine(string value)
        {
            StringBuilder.AppendLine(value);
        }

        public void WriteLine(object value)
        {
            StringBuilder.AppendLine(value.ToString());
        }

        public void Write(char value)
        {
            StringBuilder.Append(value);
        }

        public void Write(string value)
        {
            StringBuilder.Append(value);
        }

        public void Write(object value)
        {
            StringBuilder.Append(value);
        }

        void IDisposable.Dispose()
        {
        }
    }
}
