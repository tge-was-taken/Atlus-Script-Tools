using System;
using System.IO;

namespace AtlusScriptLib.Text.OutputProviders
{
    public class StreamTextOutputProvider : ITextOutputProvider
    {
        private readonly StreamWriterTextOutputProvider mOutput;

        public Stream Stream { get; }

        public StreamTextOutputProvider(Stream stream)
        {
            Stream = stream ?? throw new ArgumentNullException(nameof(stream));
            mOutput = new StreamWriterTextOutputProvider(new StreamWriter(stream));
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
