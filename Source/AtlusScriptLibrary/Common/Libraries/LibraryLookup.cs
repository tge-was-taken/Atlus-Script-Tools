using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using AtlusScriptLibrary.Common.Libraries.Serialization;
using System.Text.Json;

namespace AtlusScriptLibrary.Common.Libraries;

public static class LibraryLookup
{
    internal static string LibraryBaseDirectoryPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Libraries");
    private static List<(string Name, string ShortName, string Path)> sIndex;
    private static Dictionary<string, string> sPathsByShortName;
    private static Dictionary<string, string> sPathsByFullName;
    private static readonly Dictionary<string, Library> sLoaded = new Dictionary<string, Library>(StringComparer.Ordinal);
    private static bool sInitialized;

    public static void SetLibraryPath(string path)
    {
        LibraryBaseDirectoryPath = path;
    }

    /// <summary>
    /// Every library, each parsed on first use. Prefer <see cref="LibraryNames"/> when only the
    /// names are needed; a library's modules are several megabytes of JSON.
    /// </summary>
    public static IEnumerable<Library> Libraries
    {
        get
        {
            EnsureInitialized();
            return sIndex.Select(x => Load(x.Path));
        }
    }

    /// <summary>
    /// The full and short name of every library, without parsing its modules.
    /// </summary>
    public static IEnumerable<(string Name, string ShortName)> LibraryNames
    {
        get
        {
            EnsureInitialized();
            return sIndex.Select(x => (x.Name, x.ShortName));
        }
    }

    public static void EnsureInitialized()
    {
        if (sInitialized)
            return;

        sInitialized = true;
        sIndex = new List<(string, string, string)>();
        sPathsByShortName = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
        sPathsByFullName = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

        foreach (var path in Directory.EnumerateFiles(LibraryBaseDirectoryPath, "*.json"))
        {
            // Only the names, so that one invocation does not parse the modules of every game.
            var (name, shortName) = ReadLibraryNames(path);
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(shortName))
                throw new InvalidDataException($"Library {path} has no name or short name");

            if (sPathsByFullName.ContainsKey(name) || sPathsByShortName.ContainsKey(shortName))
                throw new InvalidDataException($"Library {path} repeats the name of another library");

            sIndex.Add((name, shortName, path));
            sPathsByFullName.Add(name, path);
            sPathsByShortName.Add(shortName, path);
        }
    }

    public static Library GetLibrary(string name)
    {
        EnsureInitialized();

        if (sPathsByShortName.TryGetValue(name, out var path) ||
            sPathsByFullName.TryGetValue(name, out path))
            return Load(path);

        return null;
    }

    private static Library Load(string path)
    {
        if (sLoaded.TryGetValue(path, out var library))
            return library;

        library = ParseLibrary(path);
        sLoaded[path] = library;
        return library;
    }

    private static (string Name, string ShortName) ReadLibraryNames(string path)
    {
        using (var document = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { AllowTrailingCommas = true }))
        {
            document.RootElement.TryGetProperty("Name", out var name);
            document.RootElement.TryGetProperty("ShortName", out var shortName);
            return (name.ValueKind == JsonValueKind.String ? name.GetString() : null,
                    shortName.ValueKind == JsonValueKind.String ? shortName.GetString() : null);
        }
    }

    private static bool ValidateLibrary(Library library, out List<string> errors)
    {
        errors = new List<string>();

        // Validate the library's own name and short name
        if (string.IsNullOrWhiteSpace(library.Name))
            errors.Add("Library name cannot be null or empty.");

        if (string.IsNullOrWhiteSpace(library.ShortName))
            errors.Add("Library short name cannot be null or empty.");

        // Track unique FlowScriptModule names
        var flowModuleNameSet = new HashSet<string>();
        if (library.FlowScriptModules != null)
        {
            foreach (var module in library.FlowScriptModules)
            {
                if (!flowModuleNameSet.Add(module.Name))
                    errors.Add($"Duplicate FlowScriptModule name found: {module.Name}");

                // Validate enum members within each FlowScriptModule, if applicable
                foreach (var item in module.Enums)
                {
                    var enumMemberNameSet = new HashSet<string>();
                    foreach (var enumMember in item.Members)
                    {
                        if (!enumMemberNameSet.Add(enumMember.Name))
                            errors.Add($"Duplicate enum member name '{enumMember.Name}' in FlowScriptModule '{module.Name}'.");
                    }
                }
            }
        }

        // Track unique MessageScriptLibrary names and indices
        var messageLibraryNameSet = new HashSet<string>();
        var messageLibraryIndexSet = new HashSet<int>();
        if (library.MessageScriptLibraries != null)
        {
            foreach (var msgLibrary in library.MessageScriptLibraries)
            {
                if (!string.IsNullOrWhiteSpace(msgLibrary.Name) && !messageLibraryNameSet.Add(msgLibrary.Name))
                    errors.Add($"Duplicate MessageScriptLibrary name found: {msgLibrary.Name}");

                if (!messageLibraryIndexSet.Add(msgLibrary.Index))
                    errors.Add($"Duplicate MessageScriptLibrary index found: {msgLibrary.Index}");

                // Validate functions within each MessageScriptLibrary
                var functionNameSet = new HashSet<string>();
                var functionIndexSet = new HashSet<int>();
                foreach (var function in msgLibrary.Functions ?? Enumerable.Empty<MessageScriptLibraryFunction>())
                {
                    if (!string.IsNullOrWhiteSpace(function.Name) && !functionNameSet.Add(function.Name))
                        errors.Add($"Duplicate function name '{function.Name}' in MessageScriptLibrary '{msgLibrary.Name}'.");

                    if (!functionIndexSet.Add(function.Index))
                        errors.Add($"Duplicate function index '{function.Index}' in MessageScriptLibrary '{msgLibrary.Name}'.");
                }
            }
        }

        return errors.Count == 0;
    }

    private static Library ParseLibrary(string path)
    {
        EnsureInitialized();
        string jsonText = File.ReadAllText(path);
        var lib = JsonSerializer.Deserialize(jsonText, LibraryJsonContext.Default.Library);
        if (!ValidateLibrary(lib, out var errors))
            throw new Exception($"Failed to load library {path}:\n{string.Join("\n", errors)}");
        return lib;
    }
}
