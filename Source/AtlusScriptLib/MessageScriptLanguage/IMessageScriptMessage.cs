using System.Collections.Generic;

namespace AtlusScriptLib.MessageScriptLanguage
{
    /// <summary>
    /// Common interface for message script windows.
    /// </summary>
    public interface IMessageScriptWindow
    {
        /// <summary>
        /// Gets the window type of this window.
        /// </summary>
        MessageScriptWindowType Type { get; }

        /// <summary>
        /// Gets the text identifier of this window.
        /// </summary>
        string Identifier { get; }

        /// <summary>
        /// Gets the list of lines contained in this window.
        /// </summary>
        List<MessageScriptLine> Lines { get; }
    }
}