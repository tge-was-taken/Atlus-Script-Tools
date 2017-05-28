using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Text
{
    public class FileTextOutputProvider : ITextOutputProvider
    {
        private readonly StreamWriterTextOutputProvider mOutput;

        public string Path { get; }

        public FileTextOutputProvider(string path)
        {
            Path = path ?? throw new ArgumentNullException(nameof(path));
            mOutput = new StreamWriterTextOutputProvider(new StreamWriter(path));
        }

        public void WriteLine()
        {
            mOutput.WriteLine();
        }

        public void WriteLine(string value)
        {
            mOutput.WriteLine(value);
        }

        public void WriteLine(object value)
        {
            mOutput.WriteLine(value);
        }

        public void Write(char value)
        {
            mOutput.Write(value);
        }

        public void Write(string value)
        {
            mOutput.Write(value);
        }

        public void Write(object value)
        {
            mOutput.Write(value);
        }

        public void Dispose()
        {
            mOutput.Dispose();
        }
    }
}
