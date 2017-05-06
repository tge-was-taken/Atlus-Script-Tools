using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared.Tokenizing
{
    public class Token
    {
        public string Text { get; }

        public Token(string text)
        {
            Text = text;
        }
    }

    public class Tokenizer : IDisposable
    {
        private StreamReader mReader;
        private StringBuilder mBuilder;

        public Tokenizer(Stream input)
        {
            mReader = new StreamReader(input);
        }

        public Tokenizer(string input)
        {
            var bytes = Encoding.Default.GetBytes(input);
            var mstream = new MemoryStream(bytes);
            mReader = new StreamReader(mstream);
        }

        public void Dispose()
        {
            ((IDisposable)mReader).Dispose();
        }

        public bool GetToken(out Token token)
        {
            mBuilder.Clear();

            int peekValue;
            char c;

            // Read & Peek return -1 if there are no more characters available
            while ( (peekValue = mReader.Peek()) != -1)
            {
                c = (char)peekValue;

                // is the current character whitespace?
                if (char.IsWhiteSpace(c))
                {
                    // create new token if other characters have already been read
                    if (mBuilder.Length != 0)
                    {
                        token = new Token(mBuilder.ToString());
                        return true;
                    }
                    else
                    {
                        // read all whitespace characters and turn them into a single token as to preserve 
                        do
                        {
                            mBuilder.Append(c);
                            mReader.Read();
                        }
                        while ((peekValue = mReader.Peek()) != -1 && char.IsWhiteSpace(c = (char)peekValue) );

                        token = new Token(mBuilder.ToString());
                        return true;
                    }
                }

                // is the current character a symbol?
                if (char.IsSymbol(c))
                {
                    // create new token if other characters have already been read
                    if (mBuilder.Length == 0)
                    {
                        mReader.Read();
                        token = new Token(c.ToString());
                        return true;
                    }
                    else
                    {
                        // each symbol gets its own token
                        token = new Token(mBuilder.ToString());
                        return true;
                    }
                }

                mBuilder.Append(c);
            }

            if (mBuilder.Length > 0)
            {
                token = new Token(mBuilder.ToString());
                return true;
            }
            else
            {
                token = new Token(null);
                return false;
            }
        }
    }
}
