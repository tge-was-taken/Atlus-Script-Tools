using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibraryTests.FlowScriptLanguage.Compiler
{
    [TestClass]
    public class FlowScriptCompilerTests
    {
        private void RunTest(string source, IEnumerable<Instruction> instructions)
        {
            var compiler = new FlowScriptCompiler(FormatVersion.Version3BigEndian);
            compiler.Library = LibraryLookup.GetLibrary("p5");
            compiler.EnableProcedureTracing = false;
            compiler.AddListener(new DebugLogListener());
            if (!compiler.TryCompile(source, out var script))
            {
                throw new Exception("Script failed to compile");
            }

            var compiledInstructions = script.EnumerateInstructions().ToList();

            Console.WriteLine("Compiled Instructions:");
            Console.WriteLine();
            Console.WriteLine(string.Join('\n', compiledInstructions.Select(z => z.ToString())));

            Console.WriteLine();
            Console.WriteLine();

            Console.WriteLine("Expected Instructions:");
            Console.WriteLine();
            Console.WriteLine(string.Join('\n', instructions.Select(z => z.ToString())));
            
            Assert.IsTrue(compiledInstructions.SequenceEqual(instructions));
        }

        [TestMethod]
        public void negative_float()
        {
            var source = @"
void test()
{
    float value = -420.69f;
}";

            RunTest(source, new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHF(-420.69f),
                Instruction.POPLFX(0),
                Instruction.END(),
            });
        }

        [TestMethod]
        public void negative_float_without_f_suffix()
        {
            var source = @"
void test()
{
    float value = -420.69;
}";

            RunTest(source, new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHF(-420.69f),
                Instruction.POPLFX(0),
                Instruction.END(),
            });
        }
    }
}
