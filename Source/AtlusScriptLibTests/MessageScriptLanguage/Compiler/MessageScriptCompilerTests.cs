using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib.MessageScriptLanguage.Compiler;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.MessageScriptLanguage.Compiler.Tests
{
    [TestClass()]
    public class MessageScriptCompilerTests
    {
        /*
         * Uncomment when ctor isnt just a stub
        [TestMethod()]
        public void MessageScriptCompilerTest()
        {
            throw new NotImplementedException();
        }
        */

        [TestMethod()]
        public void TryCompileTest()
        {
            string input =
                "[dlg fev0410_02_mes01 [Sakura]]\n" +
                "[f 0 5 0xffff][f 2 1][f 4 6 0 103 600 0 0]Sheesh, that was annoying...[n]I didn't think the traffic[n]jam would get that bad.[n][f 2 0][e]\n" +
                "[f 0 5 0xffff][f 2 1]I wonder what I should[n]do about the shop today.[n][f 1 1][e]\n" +
                "[sel FCL_MSG_COMBINE_SELECT]\n" +
                "[f 0 5 0xffff][f 2 1]Go ahead.[e]\n" +
                "[f 0 5 0xffff][f 2 1]Never mind.[e]\n";

            var compiler = new MessageScriptCompiler();
            compiler.TryCompile( input, out var script );
        }
    }
}