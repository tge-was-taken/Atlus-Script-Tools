using AtlusScriptLibrary.Common;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.Common.Text.Encodings;
using AtlusScriptLibrary.FlowScriptLanguage;
using AtlusScriptLibrary.FlowScriptLanguage.Decompiler;
using System.Text;

if (args.Length == 0)
{
    Console.WriteLine("Missing directory path argument");
    return;
}

var directoryPath = args[0];
var logger = new Logger("AtlusFlowScriptExtractor");
var listener = new ConsoleLogListener(true, LogLevel.All);
listener.Subscribe(logger);

using (var streamWriter = FileUtils.CreateText("AtlusFlowScriptExtractorOutput.txt"))
{
    foreach (var file in Directory.EnumerateFiles(directoryPath, "*", SearchOption.AllDirectories))
    {
        foreach (var foundScript in FindFlowScripts(file, AtlusEncoding.Persona5))
        {
            var decompiler = new FlowScriptDecompiler();
            decompiler.AddListener(listener);
            decompiler.Library = LibraryLookup.GetLibrary("p5");
            decompiler.DecompileMessageScript = false;

            if (!decompiler.TryDecompile(foundScript.Item1, out var compilationUnit))
            {
                logger.Error($"Failed to decompile FlowScript in: {foundScript.Item2}");
                continue;
            }

            var writer = new CompilationUnitWriter();
            streamWriter.WriteLine();
            streamWriter.WriteLine("//");
            streamWriter.WriteLine($"// File: {foundScript.Item2}");
            streamWriter.WriteLine("//");
            streamWriter.WriteLine();
            writer.Write(compilationUnit, streamWriter);
        }
    }
}

logger.Info("Done");

static IEnumerable<(FlowScript, string)> FindFlowScripts(string file, Encoding encoding, Archive archive = null, string archiveFilePath = null)
{
    if (file.EndsWith("bf", StringComparison.InvariantCultureIgnoreCase))
    {
        if (archive == null)
            yield return (FlowScript.FromFile(file, encoding), file);
        else
            yield return (FlowScript.FromStream(archive.OpenFile(file), encoding), Path.Combine(archiveFilePath, file));
    }
    else if (archive == null ? Archive.TryOpenArchive(File.OpenRead(file), out var subArchive) : Archive.TryOpenArchive(archive.OpenFile(file), out subArchive))
    {
        foreach (string entry in subArchive)
        {
            foreach (var script in FindFlowScripts(entry, encoding, subArchive, archive == null ? file : Path.Combine(archiveFilePath, file)))
                yield return script;
        }
    }
}
