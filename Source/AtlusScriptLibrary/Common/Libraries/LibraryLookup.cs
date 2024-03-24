using System;
using System.Collections.Generic;
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

    private static void EnsureInitialized()
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

    private static Library ParseLibrary(string path)
    {
        EnsureInitialized();
        string jsonText = File.ReadAllText(path);
        return JsonSerializer.Deserialize<Library>(jsonText);
    }
}
