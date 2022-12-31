using System.Runtime.CompilerServices;
using System.Threading.Tasks.Sources;

namespace Dragonhill.SlimSSH.Threading;

internal class ManualResetValueTaskSource<T> : IValueTaskSource<T>
{
    private ManualResetValueTaskSourceCore<T> _taskSource = new();

    public ManualResetValueTaskSource()
    {
        _taskSource.RunContinuationsAsynchronously = true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal ValueTask<T> GetTask()
    {
        return new ValueTask<T>(this, _taskSource.Version);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void SetResult(T result)
    {
        _taskSource.SetResult(result);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void SetException(Exception exception)
    {
        _taskSource.SetException(exception);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void Reset()
    {
        _taskSource.Reset();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public T GetResult(short token) => _taskSource.GetResult(token);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTaskSourceStatus GetStatus(short token) => _taskSource.GetStatus(token);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags) => _taskSource.OnCompleted(continuation, state, token, flags);
}

internal class ManualResetValueTaskSource : IValueTaskSource
{
    private ManualResetValueTaskSourceCore<bool> _taskSource = new();

    public ManualResetValueTaskSource()
    {
        _taskSource.RunContinuationsAsynchronously = true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal ValueTask GetTask()
    {
        return new ValueTask(this, _taskSource.Version);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void SetResult()
    {
        _taskSource.SetResult(true);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void SetException(Exception exception)
    {
        _taskSource.SetException(exception);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void Reset()
    {
        _taskSource.Reset();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void GetResult(short token) => _taskSource.GetResult(token);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTaskSourceStatus GetStatus(short token) => _taskSource.GetStatus(token);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags) => _taskSource.OnCompleted(continuation, state, token, flags);
}
