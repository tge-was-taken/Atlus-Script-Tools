using System;

namespace AtlusScriptLib.Text.OutputProviders
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
