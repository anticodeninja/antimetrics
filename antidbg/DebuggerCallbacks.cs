// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2020 Artem Yamshanov, me [at] anticode.ninja

﻿namespace antidbg
{
    using System;
    using System.Runtime.InteropServices.ComTypes;

    public class DebuggerCallbacks : ICorDebugUnmanagedCallback, ICorDebugManagedCallback, ICorDebugManagedCallback2,
        ICorDebugManagedCallback3
    {
        #region Classes

        public readonly struct ExceptionEventArgs
        {
            public ICorDebugAppDomain AppDomain { get; }
            public ICorDebugThread Thread { get; }
            public ICorDebugFrame Frame { get; }
            public uint Offset { get ;}
            public CorDebugExceptionCallbackType EventType { get; }
            public uint Flags { get; }

            public ExceptionEventArgs(
                ICorDebugAppDomain appDomain,
                ICorDebugThread thread,
                ICorDebugFrame frame,
                uint offset,
                CorDebugExceptionCallbackType eventType,
                uint flags)
            {
                AppDomain = appDomain;
                Thread = thread;
                Frame = frame;
                Offset = offset;
                EventType = eventType;
                Flags = flags;
            }
        }

        public readonly struct ProcessExitedEventArgs
        {
            public ICorDebugProcess Process { get; }

            public ProcessExitedEventArgs(
                ICorDebugProcess process)
            {
                Process = process;
            }
        }

        #endregion Classes

        #region Events

        public event EventHandler<ExceptionEventArgs> ExceptionHandled;

        public event EventHandler<ProcessExitedEventArgs> ProcessExited;

        #endregion Events

        #region Properties

        public bool DebugOutput { get; set; }

        #endregion Properties

        #region Methods

        void ICorDebugUnmanagedCallback.DebugEvent(IntPtr pDebugEvent, int fOutOfBand)
        {
            if (DebugOutput)
                Console.WriteLine("info: DebugEvent");
            // TODO Add continue
        }

        void ICorDebugManagedCallback.Breakpoint(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugBreakpoint breakpoint)
        {
            if (DebugOutput)
                Console.WriteLine("info: Breakpoint");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.StepComplete(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugStepper stepper,
            CorDebugStepReason stepReason)
        {
            if (DebugOutput)
                Console.WriteLine("info: StepComplete");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.Break(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread)
        {
            if (DebugOutput)
                Console.WriteLine("info: Break");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.Exception(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            int unhandled)
        {
            if (DebugOutput)
                Console.WriteLine($"info: Exception");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.EvalComplete(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugEval eval)
        {
            if (DebugOutput)
                Console.WriteLine("info: EvalComplete");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.EvalException(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugEval eval)
        {
            if (DebugOutput)
                Console.WriteLine("info: EvalException");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.CreateProcess(ICorDebugProcess process)
        {
            if (DebugOutput)
                Console.WriteLine("info: CreateProcess");
            process.Continue(0);
        }

        void ICorDebugManagedCallback.ExitProcess(ICorDebugProcess process)
        {
            if (DebugOutput)
                Console.WriteLine("info: ExitProcess");
            ProcessExited?.Invoke(this, new ProcessExitedEventArgs(process));
            process.Continue(0);
        }

        void ICorDebugManagedCallback.CreateThread(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread)
        {
            if (DebugOutput)
                Console.WriteLine("info: CreateThread");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.ExitThread(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread)
        {
            if (DebugOutput)
                Console.WriteLine("info: ExitThread");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.LoadModule(
            ICorDebugAppDomain appDomain,
            ICorDebugModule managedModule)
        {
            if (DebugOutput)
                Console.WriteLine("info: LoadModule");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.UnloadModule(
            ICorDebugAppDomain appDomain,
            ICorDebugModule managedModule)
        {
            if (DebugOutput)
                Console.WriteLine("info: UnloadModule");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.LoadClass(
            ICorDebugAppDomain appDomain,
            ICorDebugClass c)
        {
            if (DebugOutput)
                Console.WriteLine("info: LoadClass");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.UnloadClass(
            ICorDebugAppDomain appDomain,
            ICorDebugClass c)
        {
            if (DebugOutput)
                Console.WriteLine("info: UnloadClass");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.DebuggerError(
            ICorDebugProcess process,
            int errorHR,
            uint errorCode)
        {
            if (DebugOutput)
                Console.WriteLine("info: DebuggerError");
            process.Continue(0);
        }

        void ICorDebugManagedCallback.LogMessage(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            int level,
            string logSwitchName,
            string message)
        {
            if (DebugOutput)
                Console.WriteLine("info: LogMessage");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.LogSwitch(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            int level,
            uint reason,
            string logSwitchName,
            string parentName)
        {
            if (DebugOutput)
                Console.WriteLine("info: LogSwitch");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.CreateAppDomain(
            ICorDebugProcess process,
            ICorDebugAppDomain appDomain)
        {
            if (DebugOutput)
                Console.WriteLine("info: CreateAppDomain");
            process.Continue(0);
        }

        void ICorDebugManagedCallback.ExitAppDomain(
            ICorDebugProcess process,
            ICorDebugAppDomain appDomain)
        {
            if (DebugOutput)
                Console.WriteLine("info: ExitAppDomain");
            process.Continue(0);
        }

        void ICorDebugManagedCallback.LoadAssembly(
            ICorDebugAppDomain appDomain,
            ICorDebugAssembly assembly)
        {
            if (DebugOutput)
                Console.WriteLine("info: LoadAssembly");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.UnloadAssembly(
            ICorDebugAppDomain appDomain,
            ICorDebugAssembly assembly)
        {
            if (DebugOutput)
                Console.WriteLine("info: UnloadAssembly");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.ControlCTrap(ICorDebugProcess process)
        {
            if (DebugOutput)
                Console.WriteLine("info: ControlCTrap");
            process.Continue(0);
        }

        void ICorDebugManagedCallback.NameChange(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread)
        {
            if (DebugOutput)
                Console.WriteLine("info: NameChange");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.UpdateModuleSymbols(
            ICorDebugAppDomain appDomain,
            ICorDebugModule managedModule,
            IStream stream)
        {
            if (DebugOutput)
                Console.WriteLine("info: UpdateModuleSymbols");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.EditAndContinueRemap(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugFunction managedFunction,
            int isAccurate)
        {
            if (DebugOutput)
                Console.WriteLine("info: EditAndContinueRemap");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback.BreakpointSetError(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugBreakpoint breakpoint,
            uint errorCode)
        {
            if (DebugOutput)
                Console.WriteLine("info: BreakpointSetError");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback2.FunctionRemapOpportunity(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugFunction oldFunction,
            ICorDebugFunction newFunction,
            uint oldILoffset)
        {
            if (DebugOutput)
                Console.WriteLine("info: FunctionRemapOpportunity2");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback2.FunctionRemapComplete(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugFunction managedFunction)
        {
            if (DebugOutput)
                Console.WriteLine("info: FunctionRemapComplete2");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback2.CreateConnection(
            ICorDebugProcess process,
            uint connectionId,
            ref ushort connectionName)
        {
            if (DebugOutput)
                Console.WriteLine("info: CreateConnection2");
            process.Continue(0);
        }

        void ICorDebugManagedCallback2.ChangeConnection(
            ICorDebugProcess process,
            uint connectionId)
        {
            if (DebugOutput)
                Console.WriteLine("info: ChangeConnection2");
            process.Continue(0);
        }

        void ICorDebugManagedCallback2.DestroyConnection(
            ICorDebugProcess process,
            uint connectionId)
        {
            if (DebugOutput)
                Console.WriteLine("info: DestroyConnection2");
            process.Continue(0);
        }

        void ICorDebugManagedCallback2.Exception(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            ICorDebugFrame frame,
            uint offset,
            CorDebugExceptionCallbackType eventType,
            uint flags)
        {
            if (DebugOutput)
                Console.WriteLine("info: Exception2");
            ExceptionHandled?.Invoke(this, new ExceptionEventArgs(appDomain, thread, frame, offset, eventType, flags));
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback2.ExceptionUnwind(
            ICorDebugAppDomain appDomain,
            ICorDebugThread thread,
            CorDebugExceptionUnwindCallbackType eventType,
            uint flags)
        {
            if (DebugOutput)
                Console.WriteLine("info: ExceptionUnwind2");
            appDomain.Continue(0);
        }

        void ICorDebugManagedCallback2.MDANotification(
            ICorDebugController pController,
            ICorDebugThread thread,
            ICorDebugMDA pMDA)
        {
            if (DebugOutput)
                Console.WriteLine("info: MDANotification2");
            pController.Continue(0);
        }

        void ICorDebugManagedCallback3.CustomNotification(
            ICorDebugThread thread,
            ICorDebugAppDomain appDomain)
        {
            if (DebugOutput)
                Console.WriteLine("info: CustomNotification3");
            appDomain.Continue(0);
        }

        #endregion Methods
    }
}
