using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AtlusScriptLibrary.Common.Logging;

public class ConsoleLogListener : LogListener
{
    public bool UseColors { get; set; }

    public ConsoleLogListener(bool useColors, LogLevel filter) : base(filter)
    {
        UseColors = useColors;
        TrySetConsoleEncoding();
    }

    public ConsoleLogListener(string channelName, bool useColors) : base(channelName)
    {
        UseColors = useColors;
        TrySetConsoleEncoding();
    }

    private static void TrySetConsoleEncoding()
    {
        try
        {
            // UTF-16 only round-trips through the Windows console; every other platform
            // expects bytes on stdout, where UTF-16 renders as interleaved nulls.
            Console.OutputEncoding = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Encoding.Unicode
                : new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        }
        catch (Exception)
        {
        }
    }

    protected override void OnLogCore(object sender, LogEventArgs e)
    {
        ConsoleColor prevColor = 0;

        if (UseColors)
        {
            prevColor = Console.ForegroundColor;
            Console.ForegroundColor = GetConsoleColorForSeverityLevel(e.Level);
        }

        Console.WriteLine($"{DateTime.Now} {e.ChannelName} {e.Level}: {e.Message}");

        if (UseColors)
        {
            Console.ForegroundColor = prevColor;
        }
    }

    private ConsoleColor GetConsoleColorForSeverityLevel(LogLevel level)
    {
        switch (level)
        {
            case LogLevel.Debug:
                return ConsoleColor.White;
            case LogLevel.Info:
                return ConsoleColor.Green;
            case LogLevel.Warning:
                return ConsoleColor.Yellow;
            case LogLevel.Error:
                return ConsoleColor.Red;
            case LogLevel.Fatal:
                return ConsoleColor.DarkRed;
            default:
                return ConsoleColor.White;
        }
    }
}
