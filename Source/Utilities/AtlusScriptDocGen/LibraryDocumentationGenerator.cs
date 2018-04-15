using AtlusScriptLibrary.Common.Libraries;

namespace AtlusScriptDocGen
{
    public abstract class LibraryDocumentationGenerator
    {
        public Library Library { get; }

        public DocumentationFormat Format { get; }

        protected LibraryDocumentationGenerator( Library library, DocumentationFormat format )
        {
            Library = library;
            Format = format;
        }

        public abstract void Generate( string path );
    }
}