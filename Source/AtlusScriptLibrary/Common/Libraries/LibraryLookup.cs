using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace AtlusScriptLibrary.Common.Libraries;

public static class LibraryLookup
{
    internal static string LibraryBaseDirectoryPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Libraries");
    private static List<Library> sLibraries;
    private static Dictionary<string, Library> sLibrariesByShortName;
    private static Dictionary<string, Library> sLibrariesByFullName;
    private static bool sInitialized;

    public static void SetLibraryPath(string path)
    {
        LibraryBaseDirectoryPath = path;
    }

    public static IEnumerable<Library> Libraries
    {
        get
        {
            EnsureInitialized();
            return sLibraries;
        }
    }

    public static void EnsureInitialized()
    {
        if (sInitialized)
            return;

        sInitialized = true;
        sLibraries = new List<Library>();
        foreach (var path in Directory.EnumerateFiles(LibraryBaseDirectoryPath, "*.json"))
        {
            var library = ParseLibrary(path);
            sLibraries.Add(library);
        }

        sLibrariesByShortName = Libraries.ToDictionary(x => x.ShortName, StringComparer.InvariantCultureIgnoreCase);
        sLibrariesByFullName = Libraries.ToDictionary(x => x.Name, StringComparer.InvariantCultureIgnoreCase);
    }

    public static Library GetLibrary(string name)
    {
        EnsureInitialized();

        if (sLibrariesByShortName.TryGetValue(name, out var value))
            return value;

        if (sLibrariesByFullName.TryGetValue(name, out value))
            return value;

        return null;
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
        var lib = JsonSerializer.Deserialize<Library>(jsonText);
        if (!ValidateLibrary(lib, out var errors))
            throw new Exception($"Failed to load library {path}:\n{string.Join("\n", errors)}");
        return lib;
    }
}
