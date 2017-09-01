using System;

namespace AtlusScriptLib.Text.OutputProviders
{
    public class StringTextOutputProvider : ITextOutputProvider
    {
        private readonly StringBuilderTextOutputProvider mOutput;

        public string Text => mOutput.ToString();

        public StringTextOutputProvider()
        {
            mOutput = new StringBuilderTextOutputProvider();
        }

        public void Dispose()
        {
            ((IDisposable)mOutput).Dispose();
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
    }
}
