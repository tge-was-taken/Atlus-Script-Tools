using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib
{
    /// <summary>
    /// Represents a single newline token.
    /// </summary>
    public class MessageScriptNewLineToken : IMessageScriptLineToken
    {
        /// <summary>
        /// The constant value of a newline token.
        /// </summary>
        public const byte Value = 0x0A;

        /// <summary>
        /// Gets the type of this token.
        /// </summary>
        public MessageScriptTokenType Type => MessageScriptTokenType.NewLine;

        /// <summary>
        /// Converts this token to its string reprentation.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return "<new line>";
        }
    }
}
