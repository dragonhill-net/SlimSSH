namespace Dragonhill.SlimSSH.Threading;

public class FifoSingleSemaphore
{
    public readonly struct UnlockToken : IDisposable
    {
        private readonly FifoSingleSemaphore _parent;

        internal UnlockToken(FifoSingleSemaphore parent)
        {
            _parent = parent;
        }

        public void Dispose()
        {
            _parent.Release();
        }
    }

    private SpinLock _lock = new();
    private bool _free = true;
    private Queue<TaskCompletionSource<UnlockToken>>? _waiters;

    public Task<UnlockToken> WaitToEnter()
    {
        Task<UnlockToken>? waitTask = null;

        var lockTaken = false;

        try
        {
            _lock.Enter(ref lockTaken);

            if (_free)
            {
                _free = false;
            }
            else
            {
                _waiters ??= new Queue<TaskCompletionSource<UnlockToken>>();
                // see https://devblogs.microsoft.com/premier-developer/the-danger-of-taskcompletionsourcet-class/
                var taskCompletionSource = new TaskCompletionSource<UnlockToken>(TaskCreationOptions.RunContinuationsAsynchronously);
                _waiters.Enqueue(taskCompletionSource);
                waitTask = taskCompletionSource.Task;
            }
        }
        finally
        {
            if (lockTaken)
            {
                _lock.Exit();
            }
        }

        return waitTask ?? Task.FromResult(new UnlockToken(this));
    }

    private void Release()
    {
        TaskCompletionSource<UnlockToken>? taskCompletionSource = null;

        var lockTaken = false;

        try
        {
            _lock.Enter(ref lockTaken);

            _waiters?.TryDequeue(out taskCompletionSource);

            if (taskCompletionSource == null)
            {
                _free = true;
            }
        }
        finally
        {
            if (lockTaken)
            {
                _lock.Exit();
            }
        }

        taskCompletionSource?.SetResult(new UnlockToken(this));
    }
}
