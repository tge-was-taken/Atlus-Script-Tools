using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Encodings
{
    public class PersonaEncoding : Encoding
    {
        private static char[] sCharTable = new[]
        {

        };

        public override int GetByteCount( char[] chars, int index, int count )
        {
            throw new NotImplementedException();
        }

        public override int GetBytes( char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex )
        {
            throw new NotImplementedException();
        }

        public override int GetCharCount( byte[] bytes, int index, int count )
        {
            throw new NotImplementedException();
        }

        public override int GetChars( byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex )
        {
            throw new NotImplementedException();
        }

        public override int GetMaxByteCount( int charCount )
        {
            throw new NotImplementedException();
        }

        public override int GetMaxCharCount( int byteCount )
        {
            throw new NotImplementedException();
        }
    }
}
