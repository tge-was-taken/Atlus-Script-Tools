using System;
using AtlusScriptDocGen.Generators;
using AtlusScriptLibrary.Common.Libraries;

namespace AtlusScriptDocGen
{
    public static class LibraryDocumentationGeneratorFactory
    {
        public static LibraryDocumentationGenerator Create( Library library, DocumentationFormat format )
        {
            switch ( format )
            {
                case DocumentationFormat.Npp:
                    return new NppLibraryDocumentationGenerator( library );

                case DocumentationFormat.SweetScape010Editor:
                    return new SweetScape010EditorEnumGenerator( library );

                default:
                    throw new ArgumentOutOfRangeException( nameof( format ), format, null );
            }
        }
    }
}