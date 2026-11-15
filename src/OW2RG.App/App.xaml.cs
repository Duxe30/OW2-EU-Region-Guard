using System.Windows;
using System.Windows.Threading;
using OW2RG.Infrastructure.Windows;

namespace OW2RG.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Elevated helper mode: no window, do the one requested firewall operation, exit with its code.
        if (e.Args.Length > 0 && e.Args[0] == "--helper")
        {
            int code = HelperHost.Execute(e.Args);
            Shutdown(code);
            return;
        }

        // UI smoke test: "--ui-smoke <out.png> [tabIndex]" renders the initialized window to a PNG and exits.
        if (e.Args.Length >= 2 && e.Args[0] == "--ui-smoke")
        {
            SmokeOutput = Path.GetFullPath(e.Args[1]);
            if (e.Args.Length >= 3 && int.TryParse(e.Args[2], out var tab)) SmokeTab = tab;
        }

        DispatcherUnhandledException += OnUnhandled;
        base.OnStartup(e);
        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    public static string? SmokeOutput { get; private set; }
    public static int SmokeTab { get; private set; }

    private static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            AppPaths.Ensure(AppPaths.Root);
            File.AppendAllText(Path.Combine(AppPaths.Root, "crash.log"), $"{DateTimeOffset.UtcNow:O} {e.Exception}\n\n");
        }
        catch { }
        MessageBox.Show(
            "Unexpected error: " + e.Exception.Message + "\n\nYour firewall was not changed by this error. " +
            "If rules are installed and you want them gone, use RESTORE DEFAULT or scripts\\remove-own-rules.ps1.",
            "OW2 EU Region Guard", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
