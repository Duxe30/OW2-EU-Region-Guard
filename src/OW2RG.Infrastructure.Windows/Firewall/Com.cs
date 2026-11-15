using System.Collections;
using System.Reflection;
using System.Runtime.InteropServices;
using OW2RG.Core.Firewall;
using ComTypes = System.Runtime.InteropServices.ComTypes;

namespace OW2RG.Infrastructure.Windows.Firewall;

/// <summary>
/// Thin late-bound IDispatch helper for the documented Windows Firewall COM objects
/// (HNetCfg.FwPolicy2 → INetFwPolicy2, HNetCfg.FWRule → INetFwRule). Only typed values are passed;
/// there is no shell, no netsh and no string-built command line anywhere in the firewall path.
/// </summary>
internal static class Com
{
    public static object Create(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: false)
                   ?? throw new FirewallOperationException($"COM class {progId} is not registered (Windows Firewall API unavailable).");
        return Activator.CreateInstance(type) ?? throw new FirewallOperationException($"Could not create {progId}.");
    }

    public static object? Get(object target, string name, params object[] args) => Invoke(target, name, BindingFlags.GetProperty, args);

    public static void Set(object target, string name, object value) => Invoke(target, name, BindingFlags.SetProperty, [value]);

    public static object? Call(object target, string name, params object[] args) => Invoke(target, name, BindingFlags.InvokeMethod, args);

    public static string? GetString(object target, string name) => Get(target, name) as string;

    public static int GetInt(object target, string name) => Convert.ToInt32(Get(target, name) ?? 0);

    public static bool GetBool(object target, string name) => Convert.ToBoolean(Get(target, name) ?? false);

    private static object? Invoke(object target, string name, BindingFlags flags, object[] args)
    {
        try
        {
            return target.GetType().InvokeMember(name, flags, null, target, args);
        }
        catch (TargetInvocationException tie) when (tie.InnerException is not null)
        {
            throw Translate(tie.InnerException, name);
        }
        catch (COMException ce)
        {
            throw Translate(ce, name);
        }
    }

    private static Exception Translate(Exception ex, string member) => ex switch
    {
        UnauthorizedAccessException => new FirewallOperationException($"Access denied calling {member}.", unchecked((int)0x80070005), ex),
        COMException ce => new FirewallOperationException($"Windows Firewall rejected {member}: {ce.Message.Trim()}", ce.HResult, ce),
        ArgumentException ae => new FirewallOperationException($"Windows Firewall rejected {member}: {ae.Message}", ae.HResult, ae),
        FirewallOperationException f => f,
        _ => new FirewallOperationException($"{member} failed: {ex.Message}", ex.HResult, ex),
    };

    /// <summary>Enumerates a COM collection via IEnumerable or, if needed, IDispatch DISPID_NEWENUM (-4).</summary>
    public static List<object> Enumerate(object collection)
    {
        var items = new List<object>();
        if (collection is IEnumerable enumerable)
        {
            try
            {
                foreach (var item in enumerable)
                {
                    if (item is not null) items.Add(item);
                }
                return items;
            }
            catch (InvalidCastException)
            {
                items.Clear();
            }
            catch (NotSupportedException)
            {
                items.Clear();
            }
        }
        var raw = collection.GetType().InvokeMember("[DISPID=-4]", BindingFlags.GetProperty | BindingFlags.InvokeMethod, null, collection, null);
        if (raw is not ComTypes.IEnumVARIANT enumVariant) throw new FirewallOperationException("Firewall rule collection is not enumerable.");
        var buffer = new object[1];
        while (enumVariant.Next(1, buffer, IntPtr.Zero) == 0)
        {
            if (buffer[0] is not null) items.Add(buffer[0]);
        }
        Release(raw);
        return items;
    }

    public static void Release(object? o)
    {
        if (o is not null && Marshal.IsComObject(o))
        {
            try { Marshal.FinalReleaseComObject(o); } catch { /* best effort */ }
        }
    }
}
