using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser.Grammar;

if (args.Length == 0)
{
    Console.WriteLine($"Missing filename");
    return;
}

var filePath = args[0];
var outFilePath = $"{Path.GetFileNameWithoutExtension(args[0])}_procedure_ids.txt";

if (filePath.EndsWith("bf", StringComparison.InvariantCultureIgnoreCase))
{
    var script = FlowScript.FromFile(filePath);
    WriteProcedureIds(outFilePath, script.Procedures.Select(x => x.Name));
}
else if (filePath.EndsWith("flow"))
{
    var compilationUnit = FlowScriptParserHelper.ParseCompilationUnit(File.OpenText(filePath));
    WriteProcedureIds(outFilePath,
                       compilationUnit.declarationStatement().Where(x => x.procedureDeclarationStatement() != null && x.procedureDeclarationStatement().Identifier() != null)
                                      .Select(x => x.procedureDeclarationStatement().Identifier().Symbol.Text));
}
else
{
    Console.WriteLine("Can't detect input type (unknown extension)");
    return;
}

static void WriteProcedureIds(string filePath, IEnumerable<string> procedureNames)
{
    using (var writer = File.CreateText(filePath))
    {
        var i = 0;
        foreach (var name in procedureNames)
        {
            writer.WriteLine($"{i}\t\t{name}");
            ++i;
        }
    }
}