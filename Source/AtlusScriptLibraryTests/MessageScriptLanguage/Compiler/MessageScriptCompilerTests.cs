using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLibrary.MessageScriptLanguage.Compiler.Tests
{
    [TestClass]
    public class MessageScriptCompilerTests
    {
        [TestMethod]
        [Ignore]
        public void TryCompile_DialogWindow_ShouldReturnTrue()
        {
            string input =
                $"[dlg {GenerateTestIdentifier()} {GenerateTestIdentifier()}][f 0 5 0xFFFF][f 3 77 0xffff][f 222 222 -1][x 8223 39755]jasdhjdhquyqwy2893y38973290188290804759856273y3dhjakbdnbx zx dkjaughwuidhkadjiyquwd9u892y3gahsdkjqbwhgua../,/.,.,/..,/.,';;';';';';!!!!!=-=-=-=\\\\  \n\\!@##@#$%^&***()_+:[e][e]-80253895639258310-11239057825257389";

            var compiler = new MessageScriptCompiler( FormatVersion.Version1BigEndian );
            Assert.IsTrue( compiler.TryCompile( input, out var script ) );
        }

        [TestMethod]
        [Ignore]
        public void TryCompile_SelectionWindow_ShouldReturnTrue()
        {
            string input =
                $"[sel {GenerateTestIdentifier()}][f 0 5 0xFFFF][f 3 77 0xffff][f 222 222 -1][x 8223 39755]jasdhjdhquyqwy2893y38973290188290804759856273y3dhjakbdnbx zx dkjaughwuidhkadjiyquwd9u892y3gahsdkjqbwhgua../,/.,.,/..,/.,';;';';';';!!!!!=-=-=-=\\\\  \n\\!@##@#$%^&***()_+:[e][e]-80253895639258310-11239057825257389";

            var compiler = new MessageScriptCompiler( FormatVersion.Version1BigEndian );
            Assert.IsTrue( compiler.TryCompile( input, out var script ) );
        }

        private string GenerateTestIdentifier()
        {
            string identifier = string.Empty;

            for ( char c = 'a'; c < ( 'z' + 1 ); c++ )
                identifier += c;

            for ( char c = 'A'; c < ( 'Z' + 1 ); c++ )
                identifier += c;

            for ( char c = '0'; c < ( '9' + 1 ); c++ )
                identifier += c;

            identifier += '_';

            return identifier;
        }
    }
}