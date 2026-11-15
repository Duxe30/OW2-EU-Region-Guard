using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace OW2RG.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();

    public MainWindow()
    {
        InitializeComponent();
        _vm.Owner = this;
        DataContext = _vm;
        Loaded += async (_, _) =>
        {
            await _vm.InitializeAsync();
            if (App.SmokeOutput is { } output) await RenderSmokeAsync(output);
        };
    }

    /// <summary>Renders the fully initialized window to a PNG (UI smoke test), then exits.</summary>
    private async Task RenderSmokeAsync(string output)
    {
        if (FindTabControl(this) is { } tabs && App.SmokeTab >= 0 && App.SmokeTab < tabs.Items.Count) tabs.SelectedIndex = App.SmokeTab;
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        await Task.Delay(600);
        UpdateLayout();
        var root = (FrameworkElement)Content;
        double scale = VisualTreeHelper.GetDpi(this).DpiScaleX;
        var bmp = new RenderTargetBitmap((int)(root.ActualWidth * scale), (int)(root.ActualHeight * scale), 96 * scale, 96 * scale, PixelFormats.Pbgra32);
        bmp.Render(root);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await using (var fs = File.Create(output)) enc.Save(fs);
        Application.Current.Shutdown(0);
    }

    private static TabControl? FindTabControl(DependencyObject node)
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(node); i++)
        {
            var child = VisualTreeHelper.GetChild(node, i);
            if (child is TabControl t) return t;
            if (FindTabControl(child) is { } found) return found;
        }
        return null;
    }
}
