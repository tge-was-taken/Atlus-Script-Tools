using System;
using System.IO;

namespace AtlusScriptLib.Text.OutputProviders
{
    public class TextWriterTextOutputProvider : ITextOutputProvider
    {
        private readonly TextWriter mTextWriter;

        public TextWriterTextOutputProvider(TextWriter writer)
        {
            mTextWriter = writer ?? throw new ArgumentNullException(nameof(writer));
        }

        public void WriteLine()
        {
            mTextWriter.WriteLine();
        }

        public void WriteLine(string value)
        {
            mTextWriter.WriteLine(value);
        }

        public void WriteLine(object value)
        {
            mTextWriter.WriteLine(value);
        }

        public void Write(char value)
        {
            mTextWriter.Write(value);
        }

        public void Write(string value)
        {
            mTextWriter.Write(value);
        }

        public void Write(object value)
        {
            mTextWriter.Write(value);
        }

        public void Dispose()
        {
            mTextWriter.Dispose();
        }

    }
}
