// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2020 Artem Yamshanov, me [at] anticode.ninja

﻿namespace antidbg
{
    using System;
    using System.Reflection;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Runtime.InteropServices.ComTypes;
    using System.Text;
    using Microsoft.Win32.SafeHandles;

    public enum CorDebugCreateProcessFlags
    {
        DEBUG_NO_SPECIAL_OPTIONS,
    }

    public enum CorDebugThreadState
    {
        THREAD_RUN,
        THREAD_SUSPEND,
    }

    [Flags]
    public enum CorDebugMDAFlags
    {
        None = 0,
        MDA_FLAG_SLIP = 2,
    }

    [Flags]
    public enum CorDebugUserState
    {
        USER_NONE = 0,
        USER_STOP_REQUESTED = 1,
        USER_SUSPEND_REQUESTED = 2,
        USER_BACKGROUND = 4,
        USER_UNSTARTED = 8,
        USER_STOPPED = 16, // 0x00000010
        USER_WAIT_SLEEP_JOIN = 32, // 0x00000020
        USER_SUSPENDED = 64, // 0x00000040
        USER_UNSAFE_POINT = 128, // 0x00000080
        USER_THREADPOOL = 256, // 0x00000100
    }

    [Flags]
    public enum CorDebugIntercept
    {
        INTERCEPT_NONE = 0,
        INTERCEPT_ALL = 65535, // 0x0000FFFF
        INTERCEPT_CLASS_INIT = 1,
        INTERCEPT_EXCEPTION_FILTER = 2,
        INTERCEPT_SECURITY = 4,
        INTERCEPT_CONTEXT_POLICY = 8,
        INTERCEPT_INTERCEPTION = 16, // 0x00000010
    }

    [Flags]
    public enum CorDebugUnmappedStop
    {
        STOP_ALL = 65535, // 0x0000FFFF
        STOP_NONE = 0,
        STOP_PROLOG = 1,
        STOP_EPILOG = 2,
        STOP_NO_MAPPING_INFO = 4,
        STOP_OTHER_UNMAPPED = 8,
        STOP_UNMANAGED = 16, // 0x00000010
    }

    public enum CorDebugChainReason
    {
        CHAIN_NONE = 0,
        CHAIN_CLASS_INIT = 1,
        CHAIN_EXCEPTION_FILTER = 2,
        CHAIN_SECURITY = 4,
        CHAIN_CONTEXT_POLICY = 8,
        CHAIN_INTERCEPTION = 16, // 0x00000010
        CHAIN_PROCESS_START = 32, // 0x00000020
        CHAIN_THREAD_START = 64, // 0x00000040
        CHAIN_ENTER_MANAGED = 128, // 0x00000080
        CHAIN_ENTER_UNMANAGED = 256, // 0x00000100
        CHAIN_DEBUGGER_EVAL = 512, // 0x00000200
        CHAIN_CONTEXT_SWITCH = 1024, // 0x00000400
        CHAIN_FUNC_EVAL = 2048, // 0x00000800
    }

    public enum CorDebugStepReason
    {
        STEP_NORMAL,
        STEP_RETURN,
        STEP_CALL,
        STEP_EXCEPTION_FILTER,
        STEP_EXCEPTION_HANDLER,
        STEP_INTERCEPT,
        STEP_EXIT,
    }

    public enum CorDebugExceptionCallbackType
    {
        DEBUG_EXCEPTION_FIRST_CHANCE = 1,
        DEBUG_EXCEPTION_USER_FIRST_CHANCE = 2,
        DEBUG_EXCEPTION_CATCH_HANDLER_FOUND = 3,
        DEBUG_EXCEPTION_UNHANDLED = 4,
    }

    public enum CorDebugExceptionUnwindCallbackType
    {
        DEBUG_EXCEPTION_UNWIND_BEGIN = 1,
        DEBUG_EXCEPTION_INTERCEPTED = 2,
    }

    [Flags]
    public enum CorElementType
    {
        ELEMENT_TYPE_PINNED = 69, // 0x00000045
        ELEMENT_TYPE_SENTINEL = 65, // 0x00000041
        ELEMENT_TYPE_MODIFIER = 64, // 0x00000040
        ELEMENT_TYPE_MAX = 34, // 0x00000022
        ELEMENT_TYPE_INTERNAL = 33, // 0x00000021
        ELEMENT_TYPE_CMOD_OPT = 32, // 0x00000020
        ELEMENT_TYPE_CMOD_REQD = 31, // 0x0000001F
        ELEMENT_TYPE_MVAR = 30, // 0x0000001E
        ELEMENT_TYPE_SZARRAY = 29, // 0x0000001D
        ELEMENT_TYPE_OBJECT = 28, // 0x0000001C
        ELEMENT_TYPE_FNPTR = 27, // 0x0000001B
        ELEMENT_TYPE_U = 25, // 0x00000019
        ELEMENT_TYPE_I = 24, // 0x00000018
        ELEMENT_TYPE_TYPEDBYREF = 22, // 0x00000016
        ELEMENT_TYPE_GENERICINST = 21, // 0x00000015
        ELEMENT_TYPE_ARRAY = 20, // 0x00000014
        ELEMENT_TYPE_VAR = 19, // 0x00000013
        ELEMENT_TYPE_CLASS = 18, // 0x00000012
        ELEMENT_TYPE_VALUETYPE = 17, // 0x00000011
        ELEMENT_TYPE_BYREF = 16, // 0x00000010
        ELEMENT_TYPE_PTR = 15, // 0x0000000F
        ELEMENT_TYPE_STRING = 14, // 0x0000000E
        ELEMENT_TYPE_R8 = 13, // 0x0000000D
        ELEMENT_TYPE_R4 = 12, // 0x0000000C
        ELEMENT_TYPE_U8 = 11, // 0x0000000B
        ELEMENT_TYPE_I8 = 10, // 0x0000000A
        ELEMENT_TYPE_U4 = 9,
        ELEMENT_TYPE_I4 = 8,
        ELEMENT_TYPE_U2 = 7,
        ELEMENT_TYPE_I2 = 6,
        ELEMENT_TYPE_U1 = 5,
        ELEMENT_TYPE_I1 = 4,
        ELEMENT_TYPE_CHAR = 3,
        ELEMENT_TYPE_BOOLEAN = 2,
        ELEMENT_TYPE_VOID = 1,
        ELEMENT_TYPE_END = 0,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct COR_IL_MAP
    {
        public uint oldOffset;
        public uint newOffset;
        public int fAccurate;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct COR_DEBUG_IL_TO_NATIVE_MAP
    {
        public uint ilOffset;
        public uint nativeStartOffset;
        public uint nativeEndOffset;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public class SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Auto)]
    public class STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public SafeFileHandle hStdInput;
        public SafeFileHandle hStdOutput;
        public SafeFileHandle hStdError;

        public STARTUPINFO()
        {
            cb = Marshal.SizeOf((object) this);
            hStdInput = new SafeFileHandle(new IntPtr(0), false);
            hStdOutput = new SafeFileHandle(new IntPtr(0), false);
            hStdError = new SafeFileHandle(new IntPtr(0), false);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public class PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct COR_DEBUG_STEP_RANGE
    {
        public uint startOffset;
        public uint endOffset;
    }

    public static class CorDebugHelper
    {
        [DllImport("mscoree.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        public static extern void CLRCreateInstance(
            ref Guid clsid,
            ref Guid riid,
            [MarshalAs(UnmanagedType.Interface)] out object metahostInterface);

        public static ICLRMetaHost GetClrMetaHost()
        {
            var clsid = typeof(ClrMetaHost).GUID;
            var riid = typeof(ICLRMetaHost).GUID;

            CLRCreateInstance(ref clsid, ref riid, out var metahostInterface);
            if (metahostInterface == null)
                throw new Exception("Cannot create metahost");
            return (ICLRMetaHost) metahostInterface;
        }

        public static string GetTypeName(ICorDebugType type)
        {
            type.GetClass(out var cls);

            cls.GetToken(out var exToken);
            cls.GetModule(out var module);

            var riid = typeof(IMetadataImport).GUID;
            module.GetMetaDataInterface(ref riid, out var metadataImport);

            metadataImport.GetTypeDefProps((int)exToken, null, 0, out var length, out _, out var _);
            var name = new StringBuilder(length + 1);
            metadataImport.GetTypeDefProps((int)exToken, name, name.Capacity, out _, out _, out _);
            return name.ToString();
        }
    }

    [ComImport, Guid("00000100-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IEnumUnknown
    {
        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([MarshalAs(UnmanagedType.U4), In] int celt, [MarshalAs(UnmanagedType.IUnknown)] out object rgelt,
            IntPtr pceltFetched);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Skip([MarshalAs(UnmanagedType.U4), In] int celt);

        void Reset();

        void Clone(out IEnumUnknown ppenum);
    }

    [ComImport, Guid("D332DB9E-B9B3-4125-8207-A14884F53216"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICLRMetaHost
    {
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        IntPtr GetRuntime([In, MarshalAs(UnmanagedType.LPWStr)] string pwzVersion, [In] ref Guid riid);

        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void GetVersionFromFile([In, MarshalAs(UnmanagedType.LPWStr)] string pwzFilePath,
            [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwzBuffer, [In, Out] ref uint pcchBuffer);

        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        IEnumUnknown EnumerateInstalledRuntimes();

        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        IEnumUnknown EnumerateLoadedRuntimes([In] IntPtr hndProcess);

        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void RequestRuntimeLoadedNotification([In, MarshalAs(UnmanagedType.Interface)]
            ICLRMetaHost pCallbackFunction);

        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        IntPtr QueryLegacyV2RuntimeBinding([In] ref Guid riid);

        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void ExitProcess([In] int iExitCode);
    }

    [Guid("9280188D-0E8E-4867-B30C-7FA83884E8DE")]
    public interface ClrMetaHost
    {
    }

    [ComImport, Guid("BD39D1D2-BA2F-486A-89B0-B4B0CB466891"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICLRRuntimeInfo
    {
        void GetVersionString([MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder pwzBuffer,
            [MarshalAs(UnmanagedType.U4), In, Out] ref int pcchBuffer);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int GetRuntimeDirectory([MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder pwzBuffer,
            [MarshalAs(UnmanagedType.U4), In, Out] ref int pcchBuffer);

        int IsLoaded([In] IntPtr hndProcess);

        void LoadErrorString(
            [MarshalAs(UnmanagedType.U4), In] int iResourceID,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder pwzBuffer,
            [MarshalAs(UnmanagedType.U4), In, Out] ref int pcchBuffer,
            [In] int iLocaleID);

        IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPWStr), In] string pwzDllName);

        IntPtr GetProcAddress([MarshalAs(UnmanagedType.LPStr), In] string pszProcName);

        [return: MarshalAs(UnmanagedType.IUnknown)]
        object GetInterface([In] ref Guid rclsid, [In] ref Guid riid);
    }

    [Guid("DF8395B5-A4BA-450b-A77C-A9A47762C520")]
    public interface ClrDebuggingLegacy
    {
    }

    [ComImport, Guid("3D6F5F61-7538-11D3-8D5B-00104B35E7EF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebug
    {
        void Initialize();

        void Terminate();

        void SetManagedHandler([In] ICorDebugManagedCallback pCallback);

        void SetUnmanagedHandler([In] ICorDebugUnmanagedCallback pCallback);

        void CreateProcess(
            [MarshalAs(UnmanagedType.LPWStr), In] string lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr), In] string lpCommandLine,
            [In] SECURITY_ATTRIBUTES lpProcessAttributes,
            [In] SECURITY_ATTRIBUTES lpThreadAttributes,
            [In] int bInheritHandles,
            [In] uint dwCreationFlags,
            [In] IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr), In] string lpCurrentDirectory,
            [In] STARTUPINFO lpStartupInfo,
            [In] PROCESS_INFORMATION lpProcessInformation,
            [In] CorDebugCreateProcessFlags debuggingFlags,
            out ICorDebugProcess ppProcess);

        void DebugActiveProcess([In] uint id, [In] int win32Attach, out ICorDebugProcess ppProcess);

        void EnumerateProcesses(out ICorDebugProcessEnum ppProcess);

        void GetProcess([In] uint dwProcessId, out ICorDebugProcess ppProcess);

        void CanLaunchOrAttach([In] uint dwProcessId, [In] int win32DebuggingEnabled);
    }

    [ComImport, Guid("CC7BCB01-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugEnum
    {
        void Skip([In] uint celt);

        void Reset();

        void Clone(out ICorDebugEnum ppEnum);

        void GetCount(out uint pcelt);
    }

    [ComImport, Guid("F0E18809-72B5-11D2-976F-00A0C9B4D50C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugErrorInfoEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [Out] IntPtr errors, out uint pceltFetched);
    }

    [ComImport, Guid("3D6F5F62-7538-11D3-8D5B-00104B35E7EF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugController
    {
        void Stop([In] uint dwTimeout);

        void Continue([In] int fIsOutOfBand);

        void IsRunning(out int pbRunning);

        void HasQueuedCallbacks([In] ICorDebugThread pThread, out int pbQueued);

        void EnumerateThreads(out ICorDebugThreadEnum ppThreads);

        void SetAllThreadsDebugState([In] CorDebugThreadState state, [In] ICorDebugThread pExceptThisThread);

        void Detach();

        void Terminate([In] uint exitCode);

        void CanCommitChanges(
            [In] uint cSnapshots,
            [In] ref ICorDebugEditAndContinueSnapshot pSnapshots,
            out ICorDebugErrorInfoEnum pError);

        void CommitChanges(
            [In] uint cSnapshots,
            [In] ref ICorDebugEditAndContinueSnapshot pSnapshots,
            out ICorDebugErrorInfoEnum pError);
    }

    [ComImport, Guid("6DC3FA01-D7CB-11D2-8A95-0080C792E5D8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugEditAndContinueSnapshot
    {
        void CopyMetaData([In] IStream pIStream, out Guid pMvid);

        void GetMvid(out Guid pMvid);

        void GetRoDataRVA(out uint pRoDataRVA);

        void GetRwDataRVA(out uint pRwDataRVA);

        void SetPEBytes([In] IStream pIStream);

        void SetILMap([In] uint mdFunction, [In] uint cMapSize, [In] ref COR_IL_MAP map);

        void SetPESymbolBytes([In] IStream pIStream);
    }

    [ComImport, Guid("CC7BCB05-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugProcessEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugProcess[] processes, out uint pceltFetched);
    }

    [ComImport, Guid("3D6F5F64-7538-11D3-8D5B-00104B35E7EF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugProcess : ICorDebugController
    {
        new void Stop([In] uint dwTimeout);

        new void Continue([In] int fIsOutOfBand);

        new void IsRunning(out int pbRunning);

        new void HasQueuedCallbacks([In] ICorDebugThread pThread, out int pbQueued);

        new void EnumerateThreads(out ICorDebugThreadEnum ppThreads);

        new void SetAllThreadsDebugState([In] CorDebugThreadState state, [In] ICorDebugThread pExceptThisThread);

        new void Detach();

        new void Terminate([In] uint exitCode);

        new void CanCommitChanges(
            [In] uint cSnapshots,
            [In] ref ICorDebugEditAndContinueSnapshot pSnapshots,
            out ICorDebugErrorInfoEnum pError);

        new void CommitChanges(
            [In] uint cSnapshots,
            [In] ref ICorDebugEditAndContinueSnapshot pSnapshots,
            out ICorDebugErrorInfoEnum pError);

        void GetID(out uint pdwProcessId);

        void GetHandle(out IntPtr phProcessHandle);

        void GetThread([In] uint dwThreadId, out ICorDebugThread ppThread);

        void EnumerateObjects(out ICorDebugObjectEnum ppObjects);

        void IsTransitionStub([In] ulong address, out int pbTransitionStub);

        void IsOSSuspended([In] uint threadID, out int pbSuspended);

        void GetThreadContext([In] uint threadID, [In] uint contextSize, [In] IntPtr context);

        void SetThreadContext([In] uint threadID, [In] uint contextSize, [In] IntPtr context);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int ReadMemory([In] ulong address, [In] uint size, [MarshalAs(UnmanagedType.LPArray), Out]
            byte[] buffer, out IntPtr read);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int WriteMemory([In] ulong address, [In] uint size, [MarshalAs(UnmanagedType.LPArray), In] byte[] buffer,
            out IntPtr written);

        void ClearCurrentException([In] uint threadID);

        void EnableLogMessages([In] int fOnOff);

        void ModifyLogSwitch([MarshalAs(UnmanagedType.LPWStr), In] string pLogSwitchName, [In] int lLevel);

        void EnumerateAppDomains(out ICorDebugAppDomainEnum ppAppDomains);

        void GetObject(out ICorDebugValue ppObject);

        void ThreadForFiberCookie([In] uint fiberCookie, out ICorDebugThread ppThread);

        void GetHelperThreadID(out uint pThreadID);
    }

    [ComImport, Guid("CC7BCB06-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugThreadEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugThread[] threads, out uint pceltFetched);
    }

    [ComImport, Guid("938C6D66-7FB6-4F69-B389-425B8987329B"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugThread
    {
        void GetProcess(out ICorDebugProcess ppProcess);

        void GetID(out uint pdwThreadId);

        void GetHandle(out IntPtr phThreadHandle);

        void GetAppDomain(out ICorDebugAppDomain ppAppDomain);

        void SetDebugState([In] CorDebugThreadState state);

        void GetDebugState(out CorDebugThreadState pState);

        void GetUserState(out CorDebugUserState pState);

        void GetCurrentException(out ICorDebugValue ppExceptionObject);

        void ClearCurrentException();

        void CreateStepper(out ICorDebugStepper ppStepper);

        void EnumerateChains(out ICorDebugChainEnum ppChains);

        void GetActiveChain(out ICorDebugChain ppChain);

        void GetActiveFrame(out ICorDebugFrame ppFrame);

        void GetRegisterSet(out ICorDebugRegisterSet ppRegisters);

        void CreateEval(out ICorDebugEval ppEval);

        void GetObject(out ICorDebugValue ppObject);
    }

    [ComImport, Guid("63CA1B24-4359-4883-BD57-13F815F58744"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugAppDomainEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugAppDomain[] values, out uint pceltFetched);
    }

    [ComImport, Guid("3D6F5F63-7538-11D3-8D5B-00104B35E7EF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugAppDomain : ICorDebugController
    {
        new void Stop([In] uint dwTimeout);

        new void Continue([In] int fIsOutOfBand);

        new void IsRunning(out int pbRunning);

        new void HasQueuedCallbacks([In] ICorDebugThread pThread, out int pbQueued);

        new void EnumerateThreads(out ICorDebugThreadEnum ppThreads);

        new void SetAllThreadsDebugState([In] CorDebugThreadState state, [In] ICorDebugThread pExceptThisThread);

        new void Detach();

        new void Terminate([In] uint exitCode);

        new void CanCommitChanges(
            [In] uint cSnapshots,
            [In] ref ICorDebugEditAndContinueSnapshot pSnapshots,
            out ICorDebugErrorInfoEnum pError);

        new void CommitChanges(
            [In] uint cSnapshots,
            [In] ref ICorDebugEditAndContinueSnapshot pSnapshots,
            out ICorDebugErrorInfoEnum pError);

        void GetProcess(out ICorDebugProcess ppProcess);

        void EnumerateAssemblies(out ICorDebugAssemblyEnum ppAssemblies);

        void GetModuleFromMetaDataInterface([MarshalAs(UnmanagedType.IUnknown), In]
            object pIMetaData, out ICorDebugModule ppModule);

        void EnumerateBreakpoints(out ICorDebugBreakpointEnum ppBreakpoints);

        void EnumerateSteppers(out ICorDebugStepperEnum ppSteppers);

        void IsAttached(out int pbAttached);

        void GetName([In] uint cchName, out uint pcchName, [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szName);

        void GetObject(out ICorDebugValue ppObject);

        void Attach();

        void GetID(out uint pId);
    }

    [ComImport, Guid("4A2A1EC9-85EC-4BFB-9F15-A89FDFE0FE83"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugAssemblyEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugAssembly[] values, out uint pceltFetched);
    }

    [ComImport, Guid("DF59507C-D47A-459E-BCE2-6427EAC8FD06"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugAssembly
    {
        void GetProcess(out ICorDebugProcess ppProcess);

        void GetAppDomain(out ICorDebugAppDomain ppAppDomain);

        void EnumerateModules(out ICorDebugModuleEnum ppModules);

        void GetCodeBase([In] uint cchName, out uint pcchName, [MarshalAs(UnmanagedType.LPArray)] char[] szName);

        void GetName([In] uint cchName, out uint pcchName, [MarshalAs(UnmanagedType.LPArray)] char[] szName);
    }

    [ComImport, Guid("CC726F2F-1DB7-459B-B0EC-05F01D841B42"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugMDA
    {
        void GetName([In] uint cchName, out uint pcchName, [MarshalAs(UnmanagedType.LPArray)] char[] szName);

        void GetDescription([In] uint cchName, out uint pcchName, [MarshalAs(UnmanagedType.LPArray)] char[] szName);

        void GetXML([In] uint cchName, out uint pcchName, [MarshalAs(UnmanagedType.LPArray)] char[] szName);

        void GetFlags(out CorDebugMDAFlags pFlags);

        void GetOSThreadId(out uint pOsTid);
    }

    [ComImport, Guid("CC7BCB09-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugModuleEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugModule[] modules, out uint pceltFetched);
    }

    [ComImport, Guid("DBA2D8C1-E5C5-4069-8C13-10A7C6ABF43D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugModule
    {
        void GetProcess(out ICorDebugProcess ppProcess);

        void GetBaseAddress(out ulong pAddress);

        void GetAssembly(out ICorDebugAssembly ppAssembly);

        void GetName([In] uint cchName, out uint pcchName, [MarshalAs(UnmanagedType.LPArray)] char[] szName);

        void EnableJITDebugging([In] int bTrackJITInfo, [In] int bAllowJitOpts);

        void EnableClassLoadCallbacks([In] int bClassLoadCallbacks);

        void GetFunctionFromToken([In] uint methodDef, out ICorDebugFunction ppFunction);

        void GetFunctionFromRVA([In] ulong rva, out ICorDebugFunction ppFunction);

        void GetClassFromToken([In] uint typeDef, out ICorDebugClass ppClass);

        void CreateBreakpoint(out ICorDebugModuleBreakpoint ppBreakpoint);

        void GetEditAndContinueSnapshot(
            out ICorDebugEditAndContinueSnapshot ppEditAndContinueSnapshot);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int GetMetaDataInterface([In] ref Guid riid, out IMetadataImport ppObj);

        void GetToken(out uint pToken);

        void IsDynamic(out int pDynamic);

        void GetGlobalVariableValue([In] uint fieldDef, out ICorDebugValue ppValue);

        void GetSize(out uint pcBytes);

        void IsInMemory(out int pInMemory);
    }

    [ComImport, Guid("7DAC8207-D3AE-4c75-9B67-92801A497D44"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IMetadataImport
    {
        [MethodImpl(MethodImplOptions.PreserveSig)]
        void CloseEnum(IntPtr hEnum);

        void CountEnum(IntPtr hEnum, out int pulCount);

        void ResetEnum(IntPtr hEnum, int ulPos);

        void EnumTypeDefs(ref IntPtr phEnum, out int rTypeDefs, uint cMax, out uint pcTypeDefs);

        void EnumInterfaceImpls(
            ref IntPtr phEnum,
            int td,
            out int rImpls,
            uint cMax,
            out uint pcImpls);

        void EnumTypeRefs_();

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int FindTypeDefByName([MarshalAs(UnmanagedType.LPWStr), In] string szTypeDef, [In] int tkEnclosingClass,
            out int token);

        void GetScopeProps([MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szName, [In] int cchName,
            out int pchName, out Guid mvid);

        void GetModuleFromScope_();

        void GetTypeDefProps(
            [In] int td,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szTypeDef,
            [In] int cchTypeDef,
            out int pchTypeDef,
            [MarshalAs(UnmanagedType.U4)] out TypeAttributes pdwTypeDefFlags,
            out int ptkExtends);

        void GetInterfaceImplProps(int iiImpl, out int pClass, out int ptkIface);

        void GetTypeRefProps(
            int tr,
            out int ptkResolutionScope,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szName,
            [In] int cchName,
            out int pchName);

        void ResolveTypeRef(int tr, ref Guid riid, [MarshalAs(UnmanagedType.IUnknown)] out object scope,
            out int typeDef);

        void EnumMembers_();

        void EnumMembersWithName_();

        void EnumMethods(ref IntPtr phEnum, int cl, out int mdMethodDef, int cMax, out int pcTokens);

        void EnumMethodsWithName_();

        void EnumFields(ref IntPtr phEnum, int cl, out int mdFieldDef, int cMax, out uint pcTokens);

        void EnumFieldsWithName_();

        void EnumParams(
            ref IntPtr phEnum,
            int mdMethodDef,
            out int mdParamDef,
            int cMax,
            out uint pcTokens);

        void EnumMemberRefs_();

        void EnumMethodImpls_();

        void EnumPermissionSets_();

        void FindMember_();

        void FindMethod_();

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int FindField(int td, [MarshalAs(UnmanagedType.LPWStr)] string name,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)]
            byte[] pvSigBlob, int cbSigBlob, out int fieldDef);

        void FindMemberRef_();

        void GetMethodProps(
            [In] uint md,
            out int pClass,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szMethod,
            [In] int cchMethod,
            out int pchMethod,
            out uint pdwAttr,
            out IntPtr ppvSigBlob,
            out uint pcbSigBlob,
            out uint pulCodeRVA,
            out uint pdwImplFlags);

        void GetMemberRefProps(
            [In] uint mr,
            out int ptk,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szMember,
            [In] int cchMember,
            out uint pchMember,
            out IntPtr ppvSigBlob,
            out int pbSig);

        void EnumProperties(
            ref IntPtr phEnum,
            int mdTypeDef,
            out int mdPropertyDef,
            int countMax,
            out uint pcTokens);

        void EnumEvents_();

        void GetEventProps_();

        void EnumMethodSemantics_();

        void GetMethodSemantics_();

        void GetClassLayout_();

        void GetFieldMarshal_();

        void GetRVA_();

        void GetPermissionSetProps_();

        void GetSigFromToken(int mdSig, out IntPtr ppvSig, out int pcbSig);

        void GetModuleRefProps(int mur, [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szName, int cchName,
            out int pchName);

        void EnumModuleRefs_();

        void GetTypeSpecFromToken(int typeSpecToken, out IntPtr ppvSig, out int pcbSig);

        void GetNameFromToken_();

        void EnumUnresolvedMethods_();

        void GetUserString([In] int stk, [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szString,
            [In] int cchString, out int pchString);

        void GetPinvokeMap_();

        void EnumSignatures_();

        void EnumTypeSpecs(ref IntPtr phEnum, out int mdTypeSpecs, uint cMax, out uint pcTypeSpecs);

        void EnumUserStrings_();

        void GetParamForMethodIndex_();

        void EnumCustomAttributes(
            ref IntPtr phEnum,
            int tk,
            int tkType,
            out int mdCustomAttribute,
            uint cMax,
            out uint pcTokens);

        void GetCustomAttributeProps(
            int cv,
            out int ptkObj,
            out int ptkType,
            out IntPtr ppBlob,
            out int pcbSize);

        void FindTypeRef_();

        void GetMemberProps_();

        void GetFieldProps(
            int mb,
            out int mdTypeDef,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szField,
            int cchField,
            out int pchField,
            out int pdwAttr,
            out IntPtr ppvSigBlob,
            out int pcbSigBlob,
            out int pdwCPlusTypeFlab,
            out IntPtr ppValue,
            out int pcchValue);

        void GetPropertyProps(
            int mb,
            out int mdTypeDef,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szProperty,
            int cchProperty,
            out int pchProperty,
            out int pdwPropFlags,
            out IntPtr ppvSigBlob,
            out int pcbSigBlob,
            out int pdwCPlusTypeFlag,
            out IntPtr ppDefaultValue,
            out int pcchDefaultValue,
            out int mdSetter,
            out int mdGetter,
            out int rmdOtherMethod,
            int cMax,
            out int pcOtherMethod);

        void GetParamProps(
            int tk,
            out int pmd,
            out int pulSequence,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szName,
            int cchName,
            out int pchName,
            out int pdwAttr,
            out int pdwCPlusTypeFlag,
            out IntPtr ppValue,
            out int pcchValue);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int GetCustomAttributeByName(int tkObj, [MarshalAs(UnmanagedType.LPWStr)] string szName, out IntPtr ppData,
            out uint pcbData);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        bool IsValidToken([MarshalAs(UnmanagedType.U4), In] uint tk);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int GetNestedClassProps(int tdNestedClass, out int tdEnclosingClass);

        void GetNativeCallConvFromSig_();

        void IsGlobal_();
    }

    [ComImport, Guid("CC7BCB04-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugStepperEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugStepper[] steppers, out uint pceltFetched);
    }

    [ComImport, Guid("CC7BCAEC-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugStepper
    {
        void IsActive(out int pbActive);

        void Deactivate();

        void SetInterceptMask([In] CorDebugIntercept mask);

        void SetUnmappedStopMask([In] CorDebugUnmappedStop mask);

        void Step([In] int bStepIn);

        void StepRange([In] int bStepIn, [MarshalAs(UnmanagedType.LPArray), In] COR_DEBUG_STEP_RANGE[] ranges,
            [In] uint cRangeCount);

        void StepOut();

        void SetRangeIL([In] int bIL);
    }

    [ComImport, Guid("CC7BCB08-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugChainEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugChain[] chains, out uint pceltFetched);
    }

    [ComImport, Guid("CC7BCAEE-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugChain
    {
        void GetThread(out ICorDebugThread ppThread);

        void GetStackRange(out ulong pStart, out ulong pEnd);

        void GetContext(out ICorDebugContext ppContext);

        void GetCaller(out ICorDebugChain ppChain);

        void GetCallee(out ICorDebugChain ppChain);

        void GetPrevious(out ICorDebugChain ppChain);

        void GetNext(out ICorDebugChain ppChain);

        void IsManaged(out int pManaged);

        void EnumerateFrames(out ICorDebugFrameEnum ppFrames);

        void GetActiveFrame(out ICorDebugFrame ppFrame);

        void GetRegisterSet(out ICorDebugRegisterSet ppRegisters);

        void GetReason(out CorDebugChainReason pReason);
    }

    [ComImport, Guid("CC7BCB07-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugFrameEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugFrame[] frames, out uint pceltFetched);
    }

    [ComImport, Guid("CC7BCAEF-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugFrame
    {
        void GetChain(out ICorDebugChain ppChain);

        void GetCode(out ICorDebugCode ppCode);

        void GetFunction(out ICorDebugFunction ppFunction);

        void GetFunctionToken(out uint pToken);

        void GetStackRange(out ulong pStart, out ulong pEnd);

        void GetCaller(out ICorDebugFrame ppFrame);

        void GetCallee(out ICorDebugFrame ppFrame);

        void CreateStepper(out ICorDebugStepper ppStepper);
    }

    [ComImport, Guid("CC7BCB0B-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugRegisterSet
    {
        void GetRegistersAvailable(out ulong pAvailable);

        void GetRegisters([In] ulong mask, [In] uint regCount,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), Out]
            ulong[] regBuffer);

        void SetRegisters([In] ulong mask, [In] uint regCount,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), In]
            ulong[] regBuffer);

        void GetThreadContext([In] uint contextSize, [In] IntPtr context);

        void SetThreadContext([In] uint contextSize, [In] IntPtr context);
    }

    [ComImport, Guid("CC7BCAF5-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugClass
    {
        void GetModule(out ICorDebugModule pModule);

        void GetToken(out uint pTypeDef);

        void GetStaticFieldValue([In] uint fieldDef, [In] ICorDebugFrame pFrame, out ICorDebugValue ppValue);
    }

    [ComImport, Guid("B008EA8D-7AB1-43F7-BB20-FBB5A04038AE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugClass2
    {
        void GetParameterizedType(
            [In] CorElementType elementType,
            [In] uint nTypeArgs,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), In]
            ICorDebugType[] ppTypeArgs,
            out ICorDebugType ppType);

        void SetJMCStatus([In] int bIsJustMyCode);
    }

    [ComImport, Guid("CC7BCAF6-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugEval
    {
        void CallFunction([In] ICorDebugFunction pFunction, [In] uint nArgs,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), In]
            ICorDebugValue[] ppArgs);

        void NewObject([In] ICorDebugFunction pConstructor, [In] uint nArgs,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), In]
            ICorDebugValue[] ppArgs);

        void NewObjectNoConstructor([In] ICorDebugClass pClass);

        void NewString([MarshalAs(UnmanagedType.LPWStr), In] string @string);

        void NewArray(
            [In] CorElementType elementType,
            [In] ICorDebugClass pElementClass,
            [In] uint rank,
            [In] ref uint dims,
            [In] ref uint lowBounds);

        void IsActive(out int pbActive);

        void Abort();

        void GetResult(out ICorDebugValue ppResult);

        void GetThread(out ICorDebugThread ppThread);

        void CreateValue(
            [In] CorElementType elementType,
            [In] ICorDebugClass pElementClass,
            out ICorDebugValue ppValue);
    }

    [ComImport, Guid("CC7BCAF3-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugFunction
    {
        void GetModule(out ICorDebugModule ppModule);

        void GetClass(out ICorDebugClass ppClass);

        void GetToken(out uint pMethodDef);

        void GetILCode(out ICorDebugCode ppCode);

        void GetNativeCode(out ICorDebugCode ppCode);

        void CreateBreakpoint(out ICorDebugFunctionBreakpoint ppBreakpoint);

        void GetLocalVarSigToken(out uint pmdSig);

        void GetCurrentVersionNumber(out uint pnCurrentVersion);
    }

    [ComImport, Guid("CC7BCAF4-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugCode
    {
        void IsIL(out int pbIL);

        void GetFunction(out ICorDebugFunction ppFunction);

        void GetAddress(out ulong pStart);

        void GetSize(out uint pcBytes);

        void CreateBreakpoint([In] uint offset, out ICorDebugFunctionBreakpoint ppBreakpoint);

        void GetCode(
            [In] uint startOffset,
            [In] uint endOffset,
            [In] uint cBufferAlloc,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4), Out]
            byte[] buffer,
            out uint pcBufferSize);

        void GetVersionNumber(out uint nVersion);

        void GetILToNativeMapping([In] uint cMap, out uint pcMap,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), Out]
            COR_DEBUG_IL_TO_NATIVE_MAP[] map);

        void GetEnCRemapSequencePoints([In] uint cMap, out uint pcMap, [MarshalAs(UnmanagedType.LPArray), Out]
            uint[] offsets);
    }

    [ComImport, Guid("10F27499-9DF2-43CE-8333-A321D7C99CB4"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugTypeEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugType[] values, out uint pceltFetched);
    }

    [ComImport, Guid("D613F0BB-ACE1-4C19-BD72-E4C08D5DA7F5"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugType
    {
        void GetType(out CorElementType ty);

        void GetClass(out ICorDebugClass ppClass);

        void EnumerateTypeParameters(out ICorDebugTypeEnum ppTyParEnum);

        void GetFirstTypeParameter(out ICorDebugType value);

        void GetBase(out ICorDebugType pBase);

        void GetStaticFieldValue([In] uint fieldDef, [In] ICorDebugFrame pFrame, out ICorDebugValue ppValue);

        void GetRank(out uint pnRank);
    }

    [ComImport, Guid("CC7BCB02-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugObjectEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ulong[] objects, out uint pceltFetched);
    }

    [ComImport, Guid("CC7BCAF7-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugValue
    {
        void GetType(out CorElementType pType);

        void GetSize(out uint pSize);

        void GetAddress(out ulong pAddress);

        void CreateBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);
    }

    [ComImport, Guid("5E0B54E7-D88A-4626-9420-A691E0A78B49"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugValue2
    {
        void GetExactType(out ICorDebugType ppType);
    }

    [ComImport, Guid("CC7BCAF8-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugGenericValue : ICorDebugValue
    {
        new void GetType(out CorElementType pType);

        new void GetSize(out uint pSize);

        new void GetAddress(out ulong pAddress);

        new void CreateBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);

        void GetValue([Out] IntPtr pTo);

        void SetValue([In] IntPtr pFrom);
    }

    [ComImport, Guid("18AD3D6E-B7D2-11D2-BD04-0000F80849BD"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugObjectValue : ICorDebugValue
    {
        new void GetType(out CorElementType pType);

        new void GetSize(out uint pSize);

        new void GetAddress(out ulong pAddress);

        new void CreateBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);

        void GetClass(out ICorDebugClass ppClass);

        void GetFieldValue([In] ICorDebugClass pClass, [In] uint fieldDef, out ICorDebugValue ppValue);

        void GetVirtualMethod([In] uint memberRef, out ICorDebugFunction ppFunction);

        void GetContext(out ICorDebugContext ppContext);

        void IsValueClass(out int pbIsValueClass);

        void GetManagedCopy([MarshalAs(UnmanagedType.IUnknown)] out object ppObject);

        void SetFromManagedCopy([MarshalAs(UnmanagedType.IUnknown), In]
            object pObject);
    }

    [ComImport, Guid("CC7BCAFA-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugHeapValue : ICorDebugValue
    {
        new void GetType(out CorElementType pType);

        new void GetSize(out uint pSize);

        new void GetAddress(out ulong pAddress);

        new void CreateBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);

        void IsValid(out int pbValid);

        void CreateRelocBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);
    }

    [ComImport, Guid("CC7BCAF9-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugReferenceValue : ICorDebugValue
    {
        new void GetType(out CorElementType pType);

        new void GetSize(out uint pSize);

        new void GetAddress(out ulong pAddress);

        new void CreateBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);

        void IsNull(out int pbNull);

        void GetValue(out ulong pValue);

        void SetValue([In] ulong value);

        void Dereference(out ICorDebugValue ppValue);

        void DereferenceStrong(out ICorDebugValue ppValue);
    }

    [ComImport, Guid("CC7BCAFD-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugStringValue : ICorDebugHeapValue, ICorDebugValue
    {
        new void GetType(out CorElementType pType);

        new void GetSize(out uint pSize);

        new void GetAddress(out ulong pAddress);

        new void CreateBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);

        new void IsValid(out int pbValid);

        new void CreateRelocBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);

        void GetLength(out uint pcchString);

        void GetString([In] uint cchString, out uint pcchString,
            [MarshalAs(UnmanagedType.LPWStr), Out] StringBuilder szString);
    }

    [ComImport, Guid("CC7BCB00-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugContext : ICorDebugObjectValue, ICorDebugValue
    {
        new void GetType(out CorElementType pType);

        new void GetSize(out uint pSize);

        new void GetAddress(out ulong pAddress);

        new void CreateBreakpoint(out ICorDebugValueBreakpoint ppBreakpoint);

        new void GetClass(out ICorDebugClass ppClass);

        new void GetFieldValue([In] ICorDebugClass pClass, [In] uint fieldDef, out ICorDebugValue ppValue);

        new void GetVirtualMethod([In] uint memberRef, out ICorDebugFunction ppFunction);

        new void GetContext(out ICorDebugContext ppContext);

        new void IsValueClass(out int pbIsValueClass);

        new void GetManagedCopy([MarshalAs(UnmanagedType.IUnknown)] out object ppObject);

        new void SetFromManagedCopy([MarshalAs(UnmanagedType.IUnknown), In]
            object pObject);
    }

    [ComImport, Guid("CC7BCB03-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugBreakpointEnum : ICorDebugEnum
    {
        new void Skip([In] uint celt);

        new void Reset();

        new void Clone(out ICorDebugEnum ppEnum);

        new void GetCount(out uint pcelt);

        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next([In] uint celt, [MarshalAs(UnmanagedType.LPArray), Out]
            ICorDebugBreakpoint[] breakpoints, out uint pceltFetched);
    }

    [ComImport, Guid("CC7BCAE8-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugBreakpoint
    {
        void Activate([In] int bActive);

        void IsActive(out int pbActive);
    }

    [ComImport, Guid("CC7BCAEA-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugModuleBreakpoint : ICorDebugBreakpoint
    {
        new void Activate([In] int bActive);

        new void IsActive(out int pbActive);

        void GetModule(out ICorDebugModule ppModule);
    }

    [ComImport, Guid("CC7BCAE9-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugFunctionBreakpoint : ICorDebugBreakpoint
    {
        new void Activate([In] int bActive);

        new void IsActive(out int pbActive);

        void GetFunction(out ICorDebugFunction ppFunction);

        void GetOffset(out uint pnOffset);
    }

    [ComImport, Guid("CC7BCAEB-8A68-11D2-983C-0000F808342D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugValueBreakpoint : ICorDebugBreakpoint
    {
        new void Activate([In] int bActive);

        new void IsActive(out int pbActive);

        void GetValue(out ICorDebugValue ppValue);
    }

    [ComImport, Guid("5263E909-8CB5-11D3-BD2F-0000F80849BD"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugUnmanagedCallback
    {
        void DebugEvent([In] IntPtr pDebugEvent, [In] int fOutOfBand);
    }

    [ComImport, Guid("3D6F5F60-7538-11D3-8D5B-00104B35E7EF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugManagedCallback
    {
        void Breakpoint(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] ICorDebugBreakpoint pBreakpoint);

        void StepComplete(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] ICorDebugStepper pStepper,
            [In] CorDebugStepReason reason);

        void Break([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugThread thread);

        void Exception([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugThread pThread, [In] int unhandled);

        void EvalComplete([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugThread pThread, [In] ICorDebugEval pEval);

        void EvalException([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugThread pThread, [In] ICorDebugEval pEval);

        void CreateProcess([In] ICorDebugProcess pProcess);

        void ExitProcess([In] ICorDebugProcess pProcess);

        void CreateThread([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugThread thread);

        void ExitThread([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugThread thread);

        void LoadModule([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugModule pModule);

        void UnloadModule([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugModule pModule);

        void LoadClass([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugClass c);

        void UnloadClass([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugClass c);

        void DebuggerError([In] ICorDebugProcess pProcess, [MarshalAs(UnmanagedType.Error), In] int errorHR,
            [In] uint errorCode);

        void LogMessage(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] int lLevel,
            [MarshalAs(UnmanagedType.LPWStr), In] string pLogSwitchName,
            [MarshalAs(UnmanagedType.LPWStr), In] string pMessage);

        void LogSwitch(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] int lLevel,
            [In] uint ulReason,
            [MarshalAs(UnmanagedType.LPWStr), In] string pLogSwitchName,
            [MarshalAs(UnmanagedType.LPWStr), In] string pParentName);

        void CreateAppDomain([In] ICorDebugProcess pProcess, [In] ICorDebugAppDomain pAppDomain);

        void ExitAppDomain([In] ICorDebugProcess pProcess, [In] ICorDebugAppDomain pAppDomain);

        void LoadAssembly([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugAssembly pAssembly);

        void UnloadAssembly([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugAssembly pAssembly);

        void ControlCTrap([In] ICorDebugProcess pProcess);

        void NameChange([In] ICorDebugAppDomain pAppDomain, [In] ICorDebugThread pThread);

        void UpdateModuleSymbols(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugModule pModule,
            [In] IStream pSymbolStream);

        void EditAndContinueRemap(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] ICorDebugFunction pFunction,
            [In] int fAccurate);

        void BreakpointSetError(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] ICorDebugBreakpoint pBreakpoint,
            [In] uint dwError);
    }

    [ComImport, Guid("250E5EEA-DB5C-4C76-B6F3-8C46F12E3203"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugManagedCallback2
    {
        void FunctionRemapOpportunity(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] ICorDebugFunction pOldFunction,
            [In] ICorDebugFunction pNewFunction,
            [In] uint oldILOffset);

        void CreateConnection([In] ICorDebugProcess pProcess, [In] uint dwConnectionId, [In] ref ushort pConnName);

        void ChangeConnection([In] ICorDebugProcess pProcess, [In] uint dwConnectionId);

        void DestroyConnection([In] ICorDebugProcess pProcess, [In] uint dwConnectionId);

        void Exception(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] ICorDebugFrame pFrame,
            [In] uint nOffset,
            [In] CorDebugExceptionCallbackType dwEventType,
            [In] uint dwFlags);

        void ExceptionUnwind(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] CorDebugExceptionUnwindCallbackType dwEventType,
            [In] uint dwFlags);

        void FunctionRemapComplete(
            [In] ICorDebugAppDomain pAppDomain,
            [In] ICorDebugThread pThread,
            [In] ICorDebugFunction pFunction);

        void MDANotification(
            [In] ICorDebugController pController,
            [In] ICorDebugThread pThread,
            [In] ICorDebugMDA pMDA);
    }

    [ComImport, Guid("264EA0FC-2591-49AA-868E-835E6515323F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorDebugManagedCallback3
    {
        void CustomNotification([In] ICorDebugThread pThread, [In] ICorDebugAppDomain pAppDomain);
    }
}
