using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.FlowScriptLanguage.Decompiler;
using System;
using System.Collections.Generic;
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
        };
        decompiler.AddListener(new DebugLogListener());
        Assert.IsTrue(decompiler.TryDecompile(script, out var compilationUnit));
    }

    [TestMethod]
    public void can_decompile_script_with_jump_instruction()
        => DecompileScript("TestResources/JumpInstruction.bf", "p5r");
}
