using System.Collections.Generic;

namespace AtlusScriptLibrary.Common.Libraries
{
    public class MessageScriptLibrary
    {
        public int Index { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        public List<MessageScriptLibraryFunction> Functions { get; set; }
    }
}