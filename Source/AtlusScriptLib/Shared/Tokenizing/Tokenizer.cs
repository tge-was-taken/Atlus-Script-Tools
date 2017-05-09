using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AtlusScriptLib.Shared.Tokenizing
{
    public struct Token
    {
        public string Text { get; }

        public SourceFileInfo SourceInfo { get; }

        public Token(string text, string fileName, int lineNumber, int characterNumber)
        {
            Text = text;
            SourceInfo = new SourceFileInfo(fileName, lineNumber, characterNumber);
        }
    }

    public class Tokenizer : IDisposable, IEnumerable<Token>
    {
        private StreamReader mReader;
        private StringBuilder mBuilder;
        private char? mPrevChar;
        private string mFileName;
        private int mCharNumber;
        private int mLineNumber;

        public bool KeepWhitespace { get; set; }

        public Tokenizer(StreamReader reader, string fileName)
        {
            Init(reader, fileName);
        }

        public Tokenizer(Stream input, string fileName)
        {
            Init(new StreamReader(input), fileName);
        }

        public Tokenizer(string input, string fileName)
        {
            var bytes = Encoding.Default.GetBytes(input);
            var mstream = new MemoryStream(bytes);
            Init(new StreamReader(mstream), fileName);
        }

        private void Init(StreamReader reader, string fileName)
        {
            mReader = reader;
            mBuilder = new StringBuilder();
            mFileName = fileName;
            mPrevChar = null;
            mCharNumber = 1;
            mLineNumber = 1;

            KeepWhitespace = false;
        }

        private void SetPrevChar(char value)
        {
            mPrevChar = value;
        }

        private bool TryGetChar(out char value)
        {
            int val = mReader.Peek();
            if (val == -1)
            {
                value = new char();
                return false;
            }

            value = (char)mReader.Read();

            mCharNumber++;
            if (value == 0x0A) // new line
            {
                mLineNumber++;
            }

            return true;
        }

        private bool TryGetPrevChar(out char value)
        {
            if (!mPrevChar.HasValue)
            {
                value = new char();
                return false;
            }

            value = mPrevChar.Value;
            mPrevChar = null;
            return true;
        }

        private bool TryGetAccumulatedString(out string value)
        {
            if (mBuilder.Length == 0)
            {
                value = null;
                return false;
            }

            value = GetAccumulatedString();
            return true;
        }

        private string GetAccumulatedString()
        {
            string value = mBuilder.ToString();
            mBuilder.Clear();

            return value;
        }

        private Token CreateToken(string text, int charNumber)
        {
            return new Token(text, mFileName, mLineNumber, charNumber);
        }

        private Token CreateToken(string text)
        {
            return CreateToken(text, mCharNumber);
        }

        private Token CreateToken()
        {
            return CreateToken(GetAccumulatedString());
        }

        public void Dispose()
        {
            ((IDisposable)mReader).Dispose();
        }

        public bool TryGetToken(out Token token)
        {
            string tokenText;
            int startCharNumber = mCharNumber;

            while ( true )
            {
                // Try to get the previous character if it was saved from the last iteration
                if ( !TryGetPrevChar(out char c) )
                {
                    // If the previous character wasn't saved, grab a new character from the reader
                    if ( !TryGetChar(out c) )
                    {
                        // No saved character or new character to work with, we're done here
                        break;
                    }
                }

                // Check if the character is whitespace
                // These are handled in a special way
                if ( char.IsWhiteSpace(c) )
                {
                    // create new token if other characters have already been read
                    if ( TryGetAccumulatedString(out tokenText) )
                    {
                        // Save the current char
                        SetPrevChar(c);

                        // New token for out string
                        token = CreateToken(tokenText, startCharNumber);
                        return true;
                    }
                    else if (KeepWhitespace)
                    {
                        // read all whitespace characters and turn them into a single token
                        do
                        {
                            mBuilder.Append(c);
                        }
                        while ( TryGetChar(out c) && char.IsWhiteSpace(c) );

                        // If the character we ended on isn't whitespace, we should save it for the next token
                        if ( !char.IsWhiteSpace(c) )
                        {
                            SetPrevChar(c);
                        }

                        token = CreateToken(GetAccumulatedString(), startCharNumber);
                        return true;
                    }
                    else
                    {
                        continue;
                    }
                }

                // Check if the character is a symbol
                // Each symbol gets their own token
                if ( char.IsSymbol(c) || char.IsPunctuation(c) || char.IsSeparator(c) )
                {
                    // create new token if other characters have already been read
                    if ( TryGetAccumulatedString(out string value) )
                    {
                        // Save character for next token
                        SetPrevChar(c);
                        token = CreateToken(value, startCharNumber);
                        return true;
                    }
                    else
                    {
                        // make token for symbol
                        token = CreateToken(c.ToString());
                        return true;
                    }
                }

                // If the character isn't a special character, append it to the builder
                mBuilder.Append(c);
            }

            if (TryGetAccumulatedString(out tokenText))
            {
                token = CreateToken(tokenText, startCharNumber);
                return true;
            }
            else
            {
                token = new Token();
                return false;
            }         
        }

        public Token GetToken()
        {
            var success = TryGetToken(out Token token);
            if (success)
            {
                return token;
            }
            else
            {
                throw new Exception("There are no more tokens present");
            }
        }

        public IEnumerator<Token> GetEnumerator()
        {
            return new TokenEnumerator(this);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }

    public class TokenEnumerator : IEnumerator<Token>
    {
        private Tokenizer mTokenizer;

        public Token Current { get; private set; }

        object IEnumerator.Current => Current;

        public TokenEnumerator(Tokenizer tokenizer)
        {
            mTokenizer = tokenizer;
        }

        public void Dispose()
        {
            mTokenizer.Dispose();
        }

        public bool MoveNext()
        {
            var next = mTokenizer.TryGetToken(out Token token);
            Current = token;
            return next;
        }

        public void Reset()
        {
            throw new InvalidOperationException();
        }
    }
}
