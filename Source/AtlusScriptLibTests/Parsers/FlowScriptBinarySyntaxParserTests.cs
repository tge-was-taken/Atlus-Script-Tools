using AtlusScriptLib.FunctionTables;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLib.Parsers.Tests
{
    [TestClass()]
    public class FlowScriptBinarySyntaxParserTests
    {
        [TestMethod()]
        public void ParseTest()
        {
            //var script = FlowScript.FromFile(@"D:\Modding\Persona 5 EU\Main game\Extracted\data\battle\script\PlayerAI.bf");
            var script = FlowScriptBinary.FromFile(@"D:\Modding\Persona 5 EU\Main game\Extracted\data\battle\script\PlayerAI_MorganaNew.bf");
            //FlowScriptBinary.LoadFromFile(@"D:\Modding\Persona 5 EU\Main game\Extracted\data\battle\script\PlayerAI_MorganaNew.bf", out FlowScriptBinary script);
            //FlowScriptBinary.LoadFromFile(@"D:\Modding\Persona 5 EU\Main game\Extracted\data\script\scr0000_00_00.bf", out FlowScriptBinary script);
            var parser = new FlowScriptBinarySyntaxParser();
            var tree = parser.Parse(script, P5FunctionTable.Instance);
        }
    }
}