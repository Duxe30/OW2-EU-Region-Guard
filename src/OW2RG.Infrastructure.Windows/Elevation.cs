using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;

namespace OW2RG.Infrastructure.Windows;

public static class Elevation
{
    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public enum LaunchResult { Completed, UserCancelled, TimedOut, Failed }

    /// <summary>
    /// Starts <paramref name="exe"/> with the standard UAC consent prompt ("runas") and waits for it.
    /// Never silent: Windows always asks the user. No UAC bypass of any kind.
    /// </summary>
    public static (LaunchResult Result, int ExitCode, string? Error) RunElevatedAndWait(string exe, IReadOnlyList<string> args, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = true,
            Verb = "runas",
            Arguments = JoinArguments(args),
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        try
        {
            using var p = Process.Start(psi);
            if (p is null) return (LaunchResult.Failed, -1, "Process.Start returned null.");
            if (!p.WaitForExit(timeout)) return (LaunchResult.TimedOut, -1, "The elevated helper did not finish in time.");
            return (LaunchResult.Completed, p.ExitCode, null);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return (LaunchResult.UserCancelled, -1, "The administrator prompt was cancelled. Nothing was changed.");
        }
        catch (Exception ex)
        {
            return (LaunchResult.Failed, -1, ex.Message);
        }
    }

    /// <summary>Quotes arguments exactly as CommandLineToArgvW will split them.</summary>
    public static string JoinArguments(IEnumerable<string> args)
    {
        var sb = new StringBuilder();
        foreach (var arg in args)
        {
            if (sb.Length > 0) sb.Append(' ');
            if (arg.Length > 0 && arg.IndexOfAny([' ', '\t', '"', '\n']) < 0)
            {
                sb.Append(arg);
                continue;
            }
            sb.Append('"');
            int backslashes = 0;
            foreach (char c in arg)
            {
                if (c == '\\') { backslashes++; continue; }
                if (c == '"') { sb.Append('\\', backslashes * 2 + 1); sb.Append('"'); }
                else { sb.Append('\\', backslashes); sb.Append(c); }
                backslashes = 0;
            }
            sb.Append('\\', backslashes * 2);
            sb.Append('"');
        }
        return sb.ToString();
    }
}
