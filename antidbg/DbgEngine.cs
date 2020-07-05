// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2020 Artem Yamshanov, me [at] anticode.ninja

namespace antidbg
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;

    public class DbgEngine
    {
        #region Constants

        private const int WAIT_INTERVAL = 360;

        #endregion Constants

        #region Fields

        private bool _debuggingActive;

        private readonly Process _process;

        private readonly Queue<string> _startCommands;

        private readonly List<string> _exceptions;

        private string _dumpDirectory;

        private Thread _debuggerThread;

        private ICorDebugProcess _debugger;

        private DebuggerCallbacks _debuggerCallbacks;

        #endregion Fields

        #region Methods

        public DbgEngine(string[] args)
        {
            if (args.Length < 1)
                throw new ArgumentException("command line should contain at least one argument: pid or name of target process");

            _process = int.TryParse(args[0], out var pid)
                ? Process.GetProcessById(pid)
                : Process.GetProcessesByName(args[0])[0];

            _dumpDirectory = AppContext.BaseDirectory;
            _startCommands = new Queue<string>(args.Skip(1));
            _exceptions = new List<string>();
        }

        public void Run()
        {
            AppDomain.CurrentDomain.ProcessExit += (sender, args) => DetachDebugger();
            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                eventArgs.Cancel = true;
                DetachDebugger();
            };

            _debuggerCallbacks = new DebuggerCallbacks();
            _debuggerCallbacks.ExceptionHandled += DebugHandlersOnExceptionHandled;
            _debuggerCallbacks.ProcessExited += (sender, args) =>
            {
                var handle = Native.GetStdHandle(Native.STD_INPUT_HANDLE);
                Native.CancelIoEx(handle, IntPtr.Zero);
            };

            _debuggingActive = true;
            _debuggerThread = new Thread(DebuggerThread);
            _debuggerThread.Start();

            while (_debuggingActive)
            {
                try
                {
                    var (command, args) = TakeFirst(_startCommands.Count > 0 ? _startCommands.Dequeue() : Console.ReadLine());

                    switch (command)
                    {
                        case "help":
                            Console.WriteLine("it was joke... it is still in progress");
                            break;

                        case "exit":
                        case null:
                            DetachDebugger();
                            break;

                        case "path":
                            _dumpDirectory = args;
                            break;

                        case "take":
                            TakeDump(_process.Handle, args, IntPtr.Zero);
                            break;

                        case "debug":
                            _debuggerCallbacks.DebugOutput = IsTrue(args);
                            break;

                        case "add_exception":
                            _exceptions.Add(args);
                            break;

                        case "remove_exception":
                            _exceptions.Remove(args);
                            break;

                        case "manual":
                            throw new NotImplementedException("\"manual\" command is still in progress");

                        default:
                            throw new Exception("incorrect input, please use \"help\" to print allowed commands");
                    }
                }
                catch (Exception ex)
                {
                    if (ex is OperationCanceledException)
                        DetachDebugger();
                    else
                        Console.WriteLine($"error: {ex.Message}");
                }
            }

            _debuggerThread.Join();
        }

        private void DetachDebugger()
        {
            _debuggingActive = false;
            _debuggerThread.Join();
        }

        private void DebuggerThread()
        {
            Console.WriteLine($"Attaching to {_process.ProcessName}, pid: {_process.Id}");

            var metahost = CorDebugHelper.GetClrMetaHost();
            var runtimes = metahost.EnumerateLoadedRuntimes(_process.Handle);
            string version = null;
            ICorDebug corDebug = null;

            while (runtimes.Next(1, out var rgelt, IntPtr.Zero) == 0)
            {
                var runtimeInfo = (ICLRRuntimeInfo)rgelt;
                var pwzBuffer = new StringBuilder(30);
                int capacity = pwzBuffer.Capacity;
                runtimeInfo.GetVersionString(pwzBuffer, ref capacity);
                version = pwzBuffer.ToString();

                var riid = typeof (ICorDebug).GUID;
                var rclsid = typeof(ClrDebuggingLegacy).GUID;
                corDebug = (ICorDebug)runtimeInfo.GetInterface(ref rclsid, ref riid);
            }

            if (corDebug == null)
                throw new Exception("error: cannot take corDebug");

            Console.WriteLine($"info: runtime: {version}");

            corDebug.Initialize();
            corDebug.SetManagedHandler(_debuggerCallbacks);
            corDebug.SetUnmanagedHandler(_debuggerCallbacks);
            corDebug.DebugActiveProcess((uint) _process.Id, 0, out _debugger);

            while (_debuggingActive)
                Thread.Sleep(WAIT_INTERVAL);

            if (!_process.HasExited)
            {
                _debugger.Stop(WAIT_INTERVAL);
                _debugger.Detach();
            }
        }

        private void DebugHandlersOnExceptionHandled(object sender, DebuggerCallbacks.ExceptionEventArgs e)
        {
            // TODO Test x64 offsets
            var isX64 = IntPtr.Size == 8;

            var exceptionInformationStart = 0;
            var exceptionInformationThreadId = exceptionInformationStart + 0;
            var exceptionInformationExceptionPointers = exceptionInformationStart + 4;
            var exceptionInformationClientPointers = exceptionInformationStart + (isX64 ? 12 : 8);
            var exceptionInformationSize = isX64 ? 16 : 12;

            var exceptionPointersStart = exceptionInformationStart + exceptionInformationSize;
            var exceptionPointersExceptionRecord = exceptionPointersStart + 0;
            var exceptionPointersThreadContext = exceptionPointersStart + (isX64 ? 8 : 4);
            var exceptionPointersSize = isX64 ? 16 : 8;

            var exceptionRecordStart = exceptionPointersStart + exceptionPointersSize;
            var exceptionRecordCode = exceptionRecordStart + 0;
            var exceptionRecordAddress = exceptionRecordStart + (isX64 ? 16 : 12);
            var exceptionRecordSize = isX64 ? 152 : 80;

            var threadContextStart = exceptionRecordStart + exceptionRecordSize;
            var threadContextFlags = threadContextStart + (isX64 ? 48 : 0);
            var threadContextEip = threadContextStart + (isX64 ? 248 : 184);
            var threadContextSize = isX64 ? 1232 : 716;

            var exCodeBuffer = Marshal.AllocHGlobal(4);
            var exceptionInformation = Marshal.AllocHGlobal(threadContextStart + threadContextSize);

            try
            {
                e.Thread.GetCurrentException(out var ex);
                ex.GetType(out var type);

                ((ICorDebugValue2)ex).GetExactType(out var exType);
                exType.GetClass(out var exClass);

                exClass.GetToken(out var exToken);
                exClass.GetModule(out var module);

                var riid = typeof(IMetadataImport).GUID;
                module.GetMetaDataInterface(ref riid, out var metadataImport);

                var exTypeString = CorDebugHelper.GetTypeName(exType);
                ((ICorDebugClass2)exClass).GetParameterizedType(CorElementType.ELEMENT_TYPE_CLASS, 0, null, out var exBaseType);

                while (CorDebugHelper.GetTypeName(exBaseType) != "System.Exception")
                    exBaseType.GetBase(out exBaseType);

                exBaseType.GetClass(out var exBaseClass);
                exBaseClass.GetToken(out var exBaseToken);
                exBaseClass.GetModule(out var exBaseModule);

                exBaseModule.GetMetaDataInterface(ref riid, out var baseMetadataImport);

                baseMetadataImport.FindField((int)exBaseToken, "_message", null, 0, out var messageField);
                ((ICorDebugReferenceValue)ex).Dereference(out var exReal);

                ((ICorDebugObjectValue)exReal).GetFieldValue(exBaseClass, (uint)messageField, out var messageValue);
                ((ICorDebugReferenceValue)messageValue).Dereference(out var messageReal);

                var messageString = (ICorDebugStringValue)messageReal;
                messageString.GetLength(out var messageLength);
                var messageBuilder = new StringBuilder((int) messageLength + 1);
                messageString.GetString((uint) messageBuilder.Capacity, out _, messageBuilder);

                baseMetadataImport.FindField((int)exBaseToken, "_xcode", null, 0, out var codeField);
                ((ICorDebugObjectValue)exReal).GetFieldValue(exBaseClass, (uint)codeField, out var codeValue);
                ((ICorDebugGenericValue)codeValue).GetValue(exCodeBuffer);
                var code = Marshal.ReadInt32(exCodeBuffer);

                var message = $"{code:X8}.{exTypeString} {messageBuilder}";
                Console.WriteLine($"exception: {message}");

                var takeDump = e.EventType == CorDebugExceptionCallbackType.DEBUG_EXCEPTION_UNHANDLED ||
                               e.EventType == CorDebugExceptionCallbackType.DEBUG_EXCEPTION_FIRST_CHANCE &&
                               _exceptions.Any(x => message.Contains(x));

                if (!takeDump)
                    return;

                e.Thread.GetProcess(out var process);
                e.Thread.GetID(out var threadId);
                process.GetHandle(out var processHandle);

                e.Thread.GetRegisterSet(out var registerSet);

                // MINIDUMP_EXCEPTION_INFORMATION
                Marshal.WriteInt32(exceptionInformation, exceptionInformationThreadId, (int)threadId);
                Marshal.WriteIntPtr(exceptionInformation, exceptionInformationExceptionPointers, IntPtr.Add(exceptionInformation, exceptionPointersStart));
                Marshal.WriteInt32(exceptionInformation, exceptionInformationClientPointers, 0);

                // EXCEPTION_POINTERS
                Marshal.WriteIntPtr(exceptionInformation, exceptionPointersExceptionRecord, IntPtr.Add(exceptionInformation, exceptionRecordStart));
                Marshal.WriteIntPtr(exceptionInformation, exceptionPointersThreadContext, IntPtr.Add(exceptionInformation, threadContextStart));

                // CONTEXT
                Marshal.WriteInt64(exceptionInformation, threadContextFlags, 0x1003F); // CONTEXT_ALL
                registerSet.GetThreadContext((uint) threadContextSize, IntPtr.Add(exceptionInformation, threadContextStart));
                var eip = Marshal.ReadIntPtr(exceptionInformation, threadContextEip);

                // EXCEPTION_RECORD
                for (var i = 0; i < exceptionRecordSize; i += 4)
                    Marshal.WriteInt32(exceptionInformation, exceptionRecordStart + i, 0);
                Marshal.WriteInt32(exceptionInformation, exceptionRecordCode, code);
                Marshal.WriteIntPtr(exceptionInformation, exceptionRecordAddress, eip);

                TakeDump(processHandle, null, exceptionInformation);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"error: {ex.Message}");
            }
            finally
            {
                Marshal.FreeHGlobal(exCodeBuffer);
                Marshal.FreeHGlobal(exceptionInformation);
            }
        }

        private void TakeDump(IntPtr processHandle, string filename, IntPtr exceptionInformation)
        {
                var dumpType = MinidumpType.MiniDumpWithFullMemory |
                   MinidumpType.MiniDumpWithFullMemoryInfo |
                   MinidumpType.MiniDumpWithHandleData |
                   MinidumpType.MiniDumpWithThreadInfo |
                   MinidumpType.MiniDumpWithUnloadedModules;

                filename ??= $"{_process.ProcessName}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.dmp";
                filename = Path.Join(_dumpDirectory, filename);

                using (var fileStream = new FileStream(filename, FileMode.Create))
                {
                    var res = Native.MiniDumpWriteDump(
                        processHandle,
                        (uint) _process.Id,
                        fileStream.SafeFileHandle,
                        dumpType,
                        exceptionInformation,
                        IntPtr.Zero,
                        IntPtr.Zero);

                    if (!res)
                        throw new Exception("cannot write dump");
                }

                Console.WriteLine($"dump: {filename}");
        }

        private static (string, string) TakeFirst(string x)
        {
            if (x == null)
                return (null, null);

            var offset = x.IndexOf(' ');
            return offset > 0
                ? (x.Substring(0, offset), x.Substring(offset + 1))
                : (x, null);
        }

        private static bool IsTrue(string args) => args == "on";

        #endregion Methods
    }
}
