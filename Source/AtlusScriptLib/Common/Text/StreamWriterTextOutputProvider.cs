using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Text
{
    public class StreamWriterTextOutputProvider : ITextOutputProvider
    {
        public StreamWriter Writer { get; }

        public StreamWriterTextOutputProvider(StreamWriter writer)
        {
            Writer = writer ?? throw new ArgumentNullException(nameof(writer));
        }

        public void Write(char value)
        {
            Writer.Write(value);
        }

        public void Write(string value)
        {
            Writer.Write(value);
        }

        public void Write(object value)
        {
            Writer.Write(value);
        }

        public void WriteLine()
        {
            Writer.WriteLine();
        }

        public void WriteLine(string value)
        {
            Writer.WriteLine(value);
        }

        public void WriteLine(object value)
        {
            Writer.WriteLine(value);
        }

        public void Dispose()
        {
            Writer.Dispose();
        }
    }
}
