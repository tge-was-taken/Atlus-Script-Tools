using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLib.FlowScript.Parsers.Tests
{
    [TestClass()]
    public class FlowScriptBinarySyntaxParserTests
    {
        public FlowScriptBinarySyntaxParser Parser = new FlowScriptBinarySyntaxParser();

        [TestMethod()]
        public void ParseTest()
        {
            FlowScriptBinary.LoadFromFile(@"D:\Modding\Persona 5 EU\Main game\Extracted\data\battle\script\PlayerAI_MorganaNew.bf", out FlowScriptBinary script);
            //FlowScriptBinary.LoadFromFile(@"D:\Modding\Persona 5 EU\Main game\Extracted\data\script\scr0000_00_00.bf", out FlowScriptBinary script);
            Parser.Parse(script);
        }
    }
}