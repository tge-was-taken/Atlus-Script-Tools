using AtlusScriptLib.Common.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler
{
    [TestClass]
    public class FlowScriptCompilerTests
    {
        [TestMethod]
        public void CanAccessAndAssignScriptLocalVariableFromWithinMethod()
        {
            string source = 
@"
int test;

void Main()
{
    test = 1;
    int test2 = test;
}";

            var compiler = new FlowScriptCompiler( FormatVersion.Version3BigEndian );
            compiler.AddListener( new DebugLogListener() );
            Assert.IsTrue( compiler.TryCompile( source, out _ ) );
        }
    }
}
