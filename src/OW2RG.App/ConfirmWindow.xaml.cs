using System.Windows;

namespace OW2RG.App;

/// <summary>Modal confirmation with an optional "I understand" checkbox that must be ticked before OK is enabled.</summary>
public partial class ConfirmWindow : Window
{
    private readonly bool _needsAck;

    private ConfirmWindow(string title, string intro, IEnumerable<string> lines, string? ackText, string okText, string cancelText, bool danger)
    {
        InitializeComponent();
        Title = title;
        TitleText.Text = title;
        IntroText.Text = intro;
        IntroText.Visibility = string.IsNullOrEmpty(intro) ? Visibility.Collapsed : Visibility.Visible;
        var list = lines.ToList();
        LinesList.ItemsSource = list;
        LinesBorder.Visibility = list.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        _needsAck = ackText is not null;
        Ack.Visibility = _needsAck ? Visibility.Visible : Visibility.Collapsed;
        AckText.Text = ackText ?? "";
        OkButton.Content = okText;
        CancelButton.Content = cancelText;
        if (danger) OkButton.Style = (Style)FindResource("DangerButton");
        OkButton.IsEnabled = !_needsAck;
    }

    public static bool Ask(Window? owner, string title, string intro, IEnumerable<string> lines, string? ackText, string okText, string cancelText, bool danger)
    {
        var w = new ConfirmWindow(title, intro, lines, ackText, okText, cancelText, danger);
        if (owner is not null && owner.IsVisible) w.Owner = owner;
        else w.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        return w.ShowDialog() == true;
    }

    private void AckChanged(object sender, RoutedEventArgs e) => OkButton.IsEnabled = !_needsAck || Ack.IsChecked == true;
    private void OkClick(object sender, RoutedEventArgs e) => DialogResult = true;
    private void CancelClick(object sender, RoutedEventArgs e) => DialogResult = false;
}
