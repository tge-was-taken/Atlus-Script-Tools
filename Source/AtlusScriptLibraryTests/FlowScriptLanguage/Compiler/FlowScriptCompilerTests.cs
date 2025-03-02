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
        private void RunTest(string source, FormatVersion version, string library, IEnumerable<Instruction> instructions)
        {
            var compiler = new FlowScriptCompiler(version);
            compiler.Library = LibraryLookup.GetLibrary(library);
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

            RunTest(source, FormatVersion.Version3BigEndian, "p5", new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHF(420.69f),
                Instruction.MINUS(),
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

            RunTest(source, FormatVersion.Version3BigEndian, "p5", new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHF(420.69f),
                Instruction.MINUS(),
                Instruction.POPLFX(0),
                Instruction.END(),
            });
        }

        [TestMethod]
        public void negative_float_zero()
        {
            var source = @"
void test()
{
    float value = -0.00f;
}";

            RunTest(source, FormatVersion.Version3BigEndian, "p5", new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHF(0),
                Instruction.MINUS(),
                Instruction.POPLFX(0),
                Instruction.END(),
            });
        }

        [TestMethod]
        public void popreg_parameter_passing()
        {
            var source = @"
global(0) int g0;
void foo() {
    bar(0, 1, 2);
}

void bar(int p0, int p1, int p2)
{
    g0 = (p0 + p1) + p2;
}
";

            RunTest(source, FormatVersion.Version4, "p3re", new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHIS(2), // bar(0,1)
                Instruction.PUSHIS(1),
                Instruction.PUSHIS(0),
                Instruction.CALL(1),
                Instruction.END(),

                Instruction.PROC(1),
                // parameter passing
                Instruction.POPREG(),  // -ra
                Instruction.POPLIX(0), // -p0
                Instruction.POPLIX(1), // -p1
                Instruction.POPLIX(2), // -p2
                Instruction.PUSHREG(), // +ra
                Instruction.PUSHLIX(2), // +p2
                // p0 + p1
                Instruction.PUSHLIX(1),
                Instruction.PUSHLIX(0),
                Instruction.ADD(),
                // (result) + p2
                Instruction.ADD(),
                // g0 = result
                Instruction.POPIX(0),
                Instruction.END()
            });
        }

        [TestMethod]
        public void intmax_sign_handling()
        {
            var source = @"
void test()
{
    int foo = 0x80000000;
}";

            RunTest(source, FormatVersion.Version3BigEndian, "p5", new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHI(0x80000000),
                Instruction.POPLIX(0),
                Instruction.END(),
            });
        }


        [TestMethod]
        public void return_statement_handling()
        {
            var source = @"
int test()
{
    return 1;
}";

            RunTest(source, FormatVersion.Version3BigEndian, "p5", new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHIS(1),
                Instruction.POPLIX(0),
                Instruction.END(),
            });
        }


        [TestMethod]
        public void parameter_passing()
        {
            var source = @"
global(0) int g0;
void foo() {
    bar(0, 1, 2);
}

void bar(int p0, int p1, int p2)
{
    g0 = (p0 + p1) + p2;
}
";

            RunTest(source, FormatVersion.Version3BigEndian, "p5", new[]
            {
                Instruction.PROC(0),
                Instruction.PUSHIS(0), // bar(0,1, 2)
                Instruction.POPLIX(0),
                Instruction.PUSHIS(1),
                Instruction.POPLIX(1),
                Instruction.PUSHIS(2),
                Instruction.POPLIX(2),
                Instruction.CALL(1),
                Instruction.END(),

                Instruction.PROC(1),
                // parameter passing
                Instruction.PUSHLIX(0), // p0
                Instruction.POPLIX(3),
                Instruction.PUSHLIX(1), // p1
                Instruction.POPLIX(4),
                Instruction.PUSHLIX(2), // p2
                Instruction.POPLIX(5),
                
                Instruction.PUSHLIX(5), // p2
                Instruction.PUSHLIX(4), // p1
                Instruction.PUSHLIX(3), // p0
                Instruction.ADD(), // p0 + p1
                Instruction.ADD(), // (result) + p2
                Instruction.POPIX(0), // g0 = (result)
                Instruction.END()
            });
        }
    }
}
