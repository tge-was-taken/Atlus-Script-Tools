using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class MessageScriptLibraryFunction
    {
        public int Index { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        public List<MessageScriptLibraryParameter> Parameters { get; set; }
    }
}