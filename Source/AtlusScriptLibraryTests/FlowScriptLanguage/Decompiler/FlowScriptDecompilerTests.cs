using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.FlowScriptLanguage.Decompiler;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLibraryTests.FlowScriptLanguage.Decompiler;

[TestClass]
public class FlowScriptDecompilerTests
{
    private void DecompileScript(string path, string libraryName)
    {
        var script = FlowScript.FromFile(path);
        var decompiler = new FlowScriptDecompiler
        {
            Library = LibraryLookup.GetLibrary(libraryName),
            DecompileMessageScript = false,
            StrictMode = true,
        };
        decompiler.AddListener(new DebugLogListener());
        var result = decompiler.TryDecompile(script, out var compilationUnit);
        if (!result)
        {
            decompiler.StrictMode = false;
            decompiler.TryDecompile(script, out compilationUnit);
        }
        var writer = new CompilationUnitWriter();
        writer.Write(compilationUnit, Console.Out);
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void can_decompile_script_with_popreg_instruction()
        => DecompileScript("TestResources/POPREG.bf", "p3re");

    [TestMethod]
    [Ignore] // this script seems to have more issues than just jump
    public void can_decompile_script_with_jump_instruction()
        => DecompileScript("TestResources/JumpInstruction.bf", "p5r");


    [TestMethod]
    public void can_decompile_script_with_jump_instruction_2()
        => DecompileScript("TestResources/JumpInstruction2.bf", "p5");

    [TestMethod]
    public void can_decompile_script_complex()
        => DecompileScript("TestResources/Complex.bf", "p5r");


    [TestMethod]
    public void can_decompile_script_cat()
        => DecompileScript("TestResources/Cat.bf", "cat");
}
