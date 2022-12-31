namespace Dragonhill.SlimSSH.Threading;

internal interface ITimerHandler
{
    ValueTask OnTimer();
}

internal class FixedDelayTimer : IAsyncDisposable
{
    internal class Entry : IDisposable
    {
        private readonly FixedDelayTimer _timer;
        internal ITimerHandler TimerHandler { get; }
        internal long NextAt;
        internal Entry? Next;
        internal Entry? Previous;

        internal Entry(FixedDelayTimer timer, ITimerHandler handler)
        {
            _timer = timer;
            TimerHandler = handler;
        }

        internal void Reschedule()
        {
            _timer.Reschedule(this);
        }

        public void Dispose()
        {
            _timer.Remove(this);
        }
    }

    private readonly object _lock = new();
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    private readonly int _millisecondPeriod;
    private readonly int _millisecondTolerance;

    private readonly Task _loopTask;

    private Entry? _first;
    private Entry? _last;

    public FixedDelayTimer(TimeSpan period, TimeSpan tolerance)
    {
        if (period <= tolerance)
        {
            throw new ArgumentException("period is smaller or equal to tolerance", nameof(period));
        }

        if (tolerance < TimeSpan.Zero)
        {
            throw new ArgumentException("tolerance is less than zero", nameof(tolerance));
        }

        _millisecondPeriod = (int)period.TotalMilliseconds;
        _millisecondTolerance = (int)tolerance.TotalMilliseconds;

        _loopTask = Loop(_cancellationTokenSource.Token);
    }

    public Entry Register(ITimerHandler timerHandler)
    {
        var handle = new Entry(this, timerHandler);

        lock (_lock)
        {
            Append(handle);
        }

        return handle;
    }

    private void Reschedule(Entry entry)
    {
        lock (_lock)
        {
            TakeOut(entry);
            Append(entry);
        }
    }

    private void Remove(Entry entry)
    {
        lock(_lock)
        {
            TakeOut(entry);
            entry.Next = entry.Previous = null;
            entry.NextAt = long.MaxValue;
        }
    }

    private void Append(Entry entry)
    {

        entry.Next = null;
        entry.Previous = _last;

        _first ??= entry;

        if (_last != null)
        {
            _last.Next = entry;
        }

        _last = entry;

        entry.NextAt = Environment.TickCount64 + _millisecondPeriod;
    }

    private void TakeOut(Entry entry)
    {
        if (entry.Previous == null)
        {
            _first = entry.Next;
        }
        else
        {
            entry.Previous.Next = entry.Next;
        }

        if (entry.Next == null)
        {
            _last = entry.Previous;
        }
        else
        {
            entry.Next.Previous = entry.Previous;
        }
    }

    private async Task Loop(CancellationToken cancellationToken)
    {
        for (;;)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            long delay;
            ITimerHandler? timerHandler = null;

            lock (_lock)
            {
                if (_first != null)
                {
                    var item = _first;
                    delay = item.NextAt - Environment.TickCount64;
                    if (delay < _millisecondTolerance)
                    {
                        timerHandler = _first.TimerHandler;
                        TakeOut(item);
                        Append(item);
                    }
                }
                else
                {
                    delay = _millisecondPeriod;
                }
            }

            if (timerHandler != null)
            {
                await timerHandler.OnTimer();
            }
            else
            {
                await Task.Delay((int)delay, cancellationToken);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cancellationTokenSource.Cancel();
        try
        {
            await _loopTask;
        }
        catch (TaskCanceledException) { }
        finally
        {
            _cancellationTokenSource.Dispose();
            _loopTask.Dispose();
        }
    }
}
