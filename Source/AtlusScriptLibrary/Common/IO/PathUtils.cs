using System;
using System.IO;

namespace AtlusScriptLibrary.Common.IO;

public static class PathUtils
{
    /// <summary>
    /// Returns <paramref name="path"/> relative to <paramref name="baseDirectory"/>, using forward
    /// slashes so emitted import paths stay portable across platforms.
    /// </summary>
    public static string GetRelativePathPortable(string baseDirectory, string path)
    {
        if (string.IsNullOrEmpty(path))
            return path;

        if (string.IsNullOrEmpty(baseDirectory))
            return Normalize(path);

#if NETSTANDARD2_0
        var relative = GetRelativePathFallback(baseDirectory, path);
#else
        string relative;
        try
        {
            relative = Path.GetRelativePath(baseDirectory, path);
        }
        catch (ArgumentException)
        {
            relative = Path.GetFileName(path);
        }
#endif
        return Normalize(relative);
    }

    private static string Normalize(string path)
        => path.Replace('\\', '/');

#if NETSTANDARD2_0
    private static string GetRelativePathFallback(string baseDirectory, string path)
    {
        try
        {
            var baseUri = new Uri(AppendDirectorySeparator(Path.GetFullPath(baseDirectory)));
            var pathUri = new Uri(Path.GetFullPath(path));
            if (baseUri.Scheme != pathUri.Scheme)
                return Path.GetFileName(path);

            return Uri.UnescapeDataString(baseUri.MakeRelativeUri(pathUri).ToString());
        }
        catch (Exception)
        {
            return Path.GetFileName(path);
        }
    }

    private static string AppendDirectorySeparator(string directory)
        => directory.EndsWith(Path.DirectorySeparatorChar.ToString()) || directory.EndsWith("/")
            ? directory
            : directory + Path.DirectorySeparatorChar;
#endif
}
