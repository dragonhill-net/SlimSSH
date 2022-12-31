using Dragonhill.SlimSSH.Exceptions;
using Dragonhill.SlimSSH.Helpers;
using Dragonhill.SlimSSH.Localization;
using Dragonhill.SlimSSH.Threading;
using System.Runtime.CompilerServices;

namespace Dragonhill.SlimSSH.Collections;

internal sealed class FifoQueueWithPriorityMode
{
    [Flags]
    private enum SendModeChange : byte
    {
        NoChange = 0,
        SwitchToPriorityOnly,
        SwitchToNormal,
        CloseMessage
    }

    internal enum QueueEntryState : byte
    {
        NotInQueue = 0,
        InQueueNormal,
        InQueuePriority
    }

    public class QueueEntry
    {
        internal QueueEntry? Next { get; set; }
        internal QueueEntryState State { get; set; }
        internal ManualResetValueTaskSource FinishedTaskSource { get; } = new();

        internal SshPacketPlaintextBuffer? Value { get; set; }
    }

    private SpinLock _lock;

    private bool _isClosed;
    private bool _isPriorityOnlyMode;
    private QueueEntry? _firstWaiter;
    private QueueEntry? _lastWaiter;

    private bool _readerWaiting;
    private readonly ManualResetValueTaskSource<SshPacketPlaintextBuffer?> _readerTaskSource = new();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal ValueTask WriteAsyncPriority(SshPacketPlaintextBuffer plaintextBuffer, QueueEntry callersQueueEntry, bool priorityOnlyMode)
    {
        return WriteAsyncInternal(plaintextBuffer, callersQueueEntry, true, priorityOnlyMode ? SendModeChange.SwitchToPriorityOnly : SendModeChange.SwitchToNormal);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal ValueTask WriteAsync(SshPacketPlaintextBuffer plaintextBuffer, QueueEntry callersQueueEntry)
    {
        return WriteAsyncInternal(plaintextBuffer, callersQueueEntry, true, SendModeChange.NoChange);
    }

    internal ValueTask CloseWithPacket(SshPacketPlaintextBuffer plaintextBuffer, QueueEntry callersQueueEntry)
    {
        return WriteAsyncInternal(plaintextBuffer, callersQueueEntry, true, SendModeChange.CloseMessage);
    }

    internal void Close()
    {
        QueueEntry? closeMessages;

        var lockTaken = false;

        try
        {
            _lock.Enter(ref lockTaken);

            // check for possible outstanding closing packets, also close them with a call to this method
            if (_isClosed && _firstWaiter == null)
            {
                return;
            }

            _isClosed = true;

            closeMessages = _firstWaiter;
            _firstWaiter = _lastWaiter = null;
        }
        finally
        {
            if (lockTaken)
            {
                _lock.Exit(false);
            }
        }

        CloseQueueEntries(closeMessages);

        if (_readerWaiting)
        {
            // inform the reader that the queue is closed and no more packets will be coming
            _readerTaskSource.SetResult(null);
        }
    }

    private ValueTask WriteAsyncInternal(SshPacketPlaintextBuffer plaintextBuffer, QueueEntry callersQueueEntry, bool sendPriority, SendModeChange sendModeChange)
    {
        if (callersQueueEntry.State != QueueEntryState.NotInQueue)
        {
            throw new InvalidCastException(Strings.Queue_EntryAlreadyInQueue);
        }

        var notifyReader = false;
        QueueEntry? closeMessages = null;

        var lockTaken = false;

        // increase the claim count as the method probably returns before the reader is done with it
        plaintextBuffer.Claim();

        try
        {
            _lock.Enter(ref lockTaken);

            if (_isClosed)
            {
                QueueClosedException.ThrowHelper();
            }

            switch (sendModeChange)
            {
                case SendModeChange.NoChange:
                    break;

                case SendModeChange.SwitchToNormal:
                    _isPriorityOnlyMode = false;
                    break;

                case SendModeChange.SwitchToPriorityOnly:
                    _isPriorityOnlyMode = true;
                    break;

                case SendModeChange.CloseMessage:
                    closeMessages = _firstWaiter;
                    _firstWaiter = _lastWaiter = null;
                    _isClosed = true;
                    break;
            }

            if (_readerWaiting && (sendPriority || !_isPriorityOnlyMode))
            {
                _readerWaiting = false;
                notifyReader = true;
            }
            else
            {
                if (sendPriority)
                {
                    callersQueueEntry.State = QueueEntryState.InQueuePriority;
                    callersQueueEntry.Value = plaintextBuffer;

                    if (_firstWaiter == null)
                    {
                        _firstWaiter = _lastWaiter = callersQueueEntry;
                    }
                    else
                    {
                        if (_firstWaiter.State == QueueEntryState.InQueuePriority)
                        {
                            throw new InvalidOperationException(Strings.Transport_MultiplePriorityMessages);
                        }

                        callersQueueEntry.Next = _firstWaiter;
                        _firstWaiter = callersQueueEntry;
                    }
                }
                else
                {
                    callersQueueEntry.State = QueueEntryState.InQueueNormal;

                    if (_lastWaiter == null)
                    {
                        _firstWaiter = _lastWaiter = callersQueueEntry;
                    }
                    else
                    {
                        _lastWaiter.Next = callersQueueEntry;
                        _lastWaiter = callersQueueEntry;
                    }
                }

            }
        }
        catch
        {
            // balance the call to claim in case an exception is thrown
            plaintextBuffer.Dispose();
            throw;
        }
        finally
        {
            if (lockTaken)
            {
                _lock.Exit(false);
            }
        }

        if (closeMessages != null)
        {
            CloseQueueEntries(closeMessages);
        }

        if (notifyReader)
        {
            _readerTaskSource.SetResult(plaintextBuffer);
            return ValueTask.CompletedTask;
        }

        try
        {
            callersQueueEntry.FinishedTaskSource.Reset();
            return callersQueueEntry.FinishedTaskSource.GetTask();
        }
        catch
        {
            callersQueueEntry.Value?.Dispose();
            callersQueueEntry.Value = null;
            throw;
        }
    }

    private void CloseQueueEntries(QueueEntry? first)
    {
        var current = first;
        while (current != null)
        {
            var next = current.Next;

            current.Next = null;
            current.State = QueueEntryState.NotInQueue;
            current.FinishedTaskSource.SetException(new SshException(Strings.FifoQueue_Closed));
            current.Value?.Dispose();
            current.Value = null;

            current = next;
        }

        _firstWaiter = _lastWaiter = null;

        if (_readerWaiting)
        {
            // inform the reader that the queue is closed and no more packets will be coming
            _readerTaskSource.SetResult(null);
        }
    }

    internal ValueTask<SshPacketPlaintextBuffer?> ReadAsync()
    {
        var lockTaken = false;

        QueueEntry? entry = null;

        try
        {
            _lock.Enter(ref lockTaken);

            if (_firstWaiter != null && (_firstWaiter.State == QueueEntryState.InQueuePriority || !_isPriorityOnlyMode))
            {
                entry = _firstWaiter;
                _firstWaiter = entry.Next;

                if (_firstWaiter == null)
                {
                    _lastWaiter = null;
                }
            }
            else if (_isClosed)
            {
                return ValueTask.FromResult((SshPacketPlaintextBuffer?)null);
            }
            else
            {
                _readerWaiting = true;
                _readerTaskSource.Reset();
            }
        }
        finally
        {
            if (lockTaken)
            {
                _lock.Exit(false);
            }
        }

        if (entry == null)
        {
            return _readerTaskSource.GetTask();
        }

        var taskResult = ValueTask.FromResult(entry.Value);

        entry.Next = null;
        entry.State = QueueEntryState.NotInQueue;
        entry.Value = default;
        entry.FinishedTaskSource.SetResult();

        return taskResult;
    }
}
