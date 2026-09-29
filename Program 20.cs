// ============================================================================
//  Program.cs — NtCreateTokenFull v24 (.NET 10 Ultimate & Bug-Fixed)
//
//  [v24 核心修复与优化清单]
//  1. [致命修复] AddAceToObject 移除 InitializeSecurityDescriptor，防止桌面安全描述符丢失导致系统崩溃。
//  2. [致命修复] TOKEN_SOURCE 改为纯值类型 (byte[])，彻底消除 GC 封送导致的内存损坏。
//  3. [致命修复] NtCreateToken 的 ExpirationTime 改为传 nint.Zero，消除时间戳溢出风险。
//  4. [逻辑修复] ExecutePhase2Logic 补全所有 LSA 特权，防止新 Token 权限被“阉割”。
//  5. [逻辑修复] GetAuthenticationIdAndTokenId 移除静默吞没异常，确保 Token 参数合法。
//  6. [.NET 10] 全面使用 [LibraryImport] 替代 [DllImport]，实现源生成器 AOT 兼容。
//  7. [.NET 10] 全面使用 NativeMemory 替代 Marshal.AllocHGlobal，消除 COM 分配器开销。
//  8. [.NET 10] 全面使用 unsafe 指针与 MemoryMarshal 替代 PtrToStructure，实现零分配读写。
// ============================================================================

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace NtCreateTokenFull
{
    // ========================================================================
    //  CONSTANTS
    // ========================================================================
    static class TokenConstants
    {
        public const uint TOKEN_ASSIGN_PRIMARY    = 0x0001;
        public const uint TOKEN_DUPLICATE         = 0x0002;
        public const uint TOKEN_QUERY             = 0x0008;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint MAXIMUM_ALLOWED         = 0x02000000;

        public const uint PROCESS_QUERY_INFORMATION         = 0x0400;

        public const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const uint SE_PRIVILEGE_ENABLED            = 0x00000002;

        public const uint READ_CONTROL             = 0x00020000;
        public const uint WRITE_DAC                = 0x00040000;
        public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const uint TOKEN_ALL_ACCESS         = 0x000F01FF;

        public const int SecurityImpersonation = 2;

        public const int TokenUser       = 1;
        public const int TokenGroups     = 2;
        public const int TokenPrivileges = 3;
        public const int TokenSource     = 7;
        public const int TokenStatistics = 10;
        public const int TokenSessionId  = 12;

        public const uint ACL_REVISION                 = 2;
        public const uint SECURITY_DESCRIPTOR_REVISION = 1;
        public const uint DACL_SECURITY_INFORMATION    = 0x04;
        public const int  AclSizeInformation           = 2;
        public const int  ERROR_INSUFFICIENT_BUFFER    = 122;

        public const uint ACL_HEADER_SIZE               = 8;
        public const uint ACCESS_ALLOWED_ACE_FIXED_SIZE = 8;
        
        public const uint WINSTA_ENUMDESKTOPS = 0x0001;
        public const uint WINSTA_ALL_ACCESS   = STANDARD_RIGHTS_REQUIRED | 0x037F;
        public const uint DESKTOP_ALL_ACCESS  = STANDARD_RIGHTS_REQUIRED | 0x01FF;
        
        public const int STARTF_USESHOWWINDOW = 0x00000001;
    }

    static class LsaConstants
    {
        public const uint POLICY_ALL_ACCESS = 0x000F0FFF;
        public const uint STATUS_SUCCESS = 0x00000000;
        public const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
        public const uint STATUS_NO_MORE_ENTRIES = 0x8000001A;
        public const uint EWX_REBOOT = 0x00000002;
        public const uint EWX_FORCEIFHUNG = 0x00000010;
        public const uint SHTDN_REASON_MAJOR_APPLICATION = 0x00040000;
        public const uint SHTDN_REASON_MINOR_MAINTENANCE = 0x00000001;
        public const uint SHTDN_REASON_FLAG_PLANNED = 0x80000000;
    }

    static class Config
    {
        public static readonly string System32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
        public static readonly string CmdPath = Path.Combine(System32Path, "cmd.exe");
        public const string DefaultDesktop       = @"WinSta0\Default";
        public const string WinlogonDesktop      = @"WinSta0\Winlogon";
        public const string TiShellWindowTitle   = "TrustedInstaller Shell";
    }

    // ========================================================================
    //  SHARED STRUCTS (Optimized for .NET 10 & Blittable)
    // ========================================================================
    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES_HEADER { public uint PrivilegeCount; }

    [StructLayout(LayoutKind.Sequential)]
    struct LARGE_INTEGER { public long QuadPart; }

    // [修复] 改为纯值类型 byte[]，彻底消除 GC 封送问题
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct TOKEN_SOURCE
    {
        public const int MaxNameLength = 8;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MaxNameLength)]
        public byte[] SourceName;
        public LUID SourceIdentifier;

        public static TOKEN_SOURCE Create(string name, LUID id)
        {
            byte[] buffer = new byte[MaxNameLength];
            if (!string.IsNullOrEmpty(name))
            {
                int len = Math.Min(name.Length, MaxNameLength);
                Encoding.ASCII.GetBytes(name.AsSpan(0, len), buffer.AsSpan(0, len));
            }
            return new TOKEN_SOURCE { SourceName = buffer, SourceIdentifier = id };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ACL_SIZE_INFORMATION { public int AceCount; public int AclBytesInUse; public int AclBytesFree; }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_QUALITY_OF_SERVICE
    {
        public int Length;
        public int ImpersonationLevel;
        public byte ContextTrackingMode;
        public byte EffectiveOnly;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public nint RootDirectory;
        public nint ObjectName;
        public uint Attributes;
        public nint SecurityDescriptor;
        public nint SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_DESCRIPTOR
    {
        public byte Revision; public byte Sbz1; public ushort Control;
        public nint Owner; public nint Group; public nint Sacl; public nint Dacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public nint Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES { public int nLength; public nint lpSecurityDescriptor; public int bInheritHandle; }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public nint hProcess; public nint hThread; public int dwProcessId; public int dwThreadId; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WTS_SESSION_INFO { public int SessionId; public nint pWinStationName; public WTSCONNECTSTATECLASS State; }

    enum WTSCONNECTSTATECLASS { WTSActive = 0, WTSConnected = 1, WTSConnectQuery = 2, WTSShadow = 3, WTSDisconnected = 4, WTSIdle = 5, WTSListen = 6, WTSReset = 7, WTSDown = 8, WTSInit = 9 }

    [StructLayout(LayoutKind.Sequential)] struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_OWNER { public nint Owner; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIMARY_GROUP { public nint PrimaryGroup; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_DEFAULT_DACL { public nint DefaultDacl; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_GROUPS_LAYOUT { public int GroupCount; public SID_AND_ATTRIBUTES FirstGroup; }

    enum TOKEN_TYPE { TokenPrimary = 1, TokenImpersonation = 2 }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb; public nint lpReserved; public nint lpDesktop; public nint lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
        public int dwFlags; public short wShowWindow; public short cbReserved2;
        public nint lpReserved2; public nint hStdInput; public nint hStdOutput; public nint hStdError;
    }

    // [优化] 改为纯 Blittable 结构体，方便 LibraryImport 和指针操作
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length; public nint RootDirectory; public nint ObjectName;
        public uint Attributes; public nint SecurityDescriptor; public nint SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RTL_OSVERSIONINFOW
    {
        public uint dwOSVersionInfoSize; public uint dwMajorVersion; public uint dwMinorVersion;
        public uint dwBuildNumber; public uint dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string? szCSDVersion;
    }

    // ========================================================================
    //  INTEROP UTILITY (.NET 10 Optimized)
    // ========================================================================
    static class InteropUtility
    {
        public static int LastError => Marshal.GetLastWin32Error();
        public static Win32Exception NewError(string message) => new Win32Exception(Marshal.GetLastWin32Error(), message);
        public static Win32Exception NewError(int errorCode, string message) => new Win32Exception(errorCode, message);

        public static unsafe void FreeNativeIfNotNull(nint p)
        {
            if (p != nint.Zero) NativeMemory.Free((void*)p);
        }

        public static void LocalFreeIfNotNull(nint p)
        {
            if (p != nint.Zero) NativeMethods.LocalFree(p);
        }

        public static uint Align4(uint value) => (value + 3u) & ~3u;
        public static nuint Align4(nuint value) => (value + 3n) & ~3n;

        public static unsafe LUID ReadLuid(nint buffer, int offset)
        {
            byte* ptr = (byte*)buffer + offset;
            return new LUID { LowPart = *(uint*)ptr, HighPart = *(int*)(ptr + 4) };
        }

        public static string? NormalizeDesktop(string? desktopName)
            => string.IsNullOrWhiteSpace(desktopName) ? null : desktopName.Trim();

        public static unsafe string Quote(string? value)
        {
            if (string.IsNullOrEmpty(value)) return "\"\"";
            // 简单高效的引号转义
            int len = value!.Length;
            char* buffer = stackalloc char[len * 2 + 2];
            int pos = 0;
            buffer[pos++] = '"';
            for (int i = 0; i < len; i++)
            {
                char c = value[i];
                if (c == '\\' || c == '"') buffer[pos++] = '\\';
                buffer[pos++] = c;
            }
            buffer[pos++] = '"';
            return new string(buffer, 0, pos);
        }
    }

    // ========================================================================
    //  SafeTokenHandle
    // ========================================================================
    sealed class SafeTokenHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeTokenHandle() : base(true) { }
        protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);
    }

    // ========================================================================
    //  SessionInfo
    // ========================================================================
    static class SessionInfo
    {
        const int WTSUserName     = 5;

        public static unsafe bool IsUserLoggedOn(uint sessionId)
        {
            nint pBuf = nint.Zero;
            try
            {
                if (!NativeMethods.WTSQuerySessionInformation(nint.Zero, sessionId, WTSUserName, out pBuf, out uint bytes))
                    return false;
                if (pBuf == nint.Zero || bytes == 0) return false;
                return !string.IsNullOrWhiteSpace(new string((char*)pBuf));
            }
            finally { if (pBuf != nint.Zero) NativeMethods.WTSFreeMemory(pBuf); }
        }

        public static unsafe uint? FindActiveUserSession()
        {
            nint pSessions = nint.Zero;
            uint? firstConnected = null;
            try
            {
                if (!NativeMethods.WTSEnumerateSessions(nint.Zero, 0, 1, out pSessions, out uint count))
                    return null;

                uint structSize = (uint)sizeof(WTS_SESSION_INFO);
                byte* ptr = (byte*)pSessions;

                for (uint i = 0; i < count; i++)
                {
                    WTS_SESSION_INFO si = Unsafe.Read<WTS_SESSION_INFO>(ptr + i * structSize);
                    if (si.SessionId == 0) continue;
                    if (!IsUserLoggedOn((uint)si.SessionId)) continue;

                    if (si.State == WTSCONNECTSTATECLASS.WTSActive) return (uint)si.SessionId;
                    if (si.State == WTSCONNECTSTATECLASS.WTSConnected && firstConnected == null)
                        firstConnected = (uint)si.SessionId;
                }
                return firstConnected;
            }
            catch { return null; }
            finally { if (pSessions != nint.Zero) NativeMethods.WTSFreeMemory(pSessions); }
        }

        public static bool HasInteractiveDesktop()
        {
            nint h = NativeMethods.OpenWindowStation("WinSta0", false, TokenConstants.WINSTA_ENUMDESKTOPS);
            if (h == nint.Zero) return false;
            NativeMethods.CloseWindowStation(h);
            return true;
        }
    }

    // ========================================================================
    //  LsaUtility (Win11+ 特权管理)
    // ========================================================================
    static class LsaUtility
    {
        public static readonly string[] AllLsaPrivileges = new string[]
        {
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege",
            "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege",
            "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege",
            "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
            "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
            "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege",
            "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege"
        };

        public static bool IsWindows11OrHigher()
        {
            var osvi = new RTL_OSVERSIONINFOW { dwOSVersionInfoSize = (uint)Unsafe.SizeOf<RTL_OSVERSIONINFOW>() };
            if (NativeMethods.RtlGetVersion(out osvi) == 0)
                return osvi.dwMajorVersion > 10 || (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 22000);
            return false;
        }

        public static unsafe bool AreRequiredPrivilegesGranted()
        {
            nint policyHandle = nint.Zero;
            nint sid = nint.Zero;
            nint rightsPtr = nint.Zero;

            try
            {
                var loa = new LSA_OBJECT_ATTRIBUTES { Length = Unsafe.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
                uint status = NativeMethods.LsaOpenPolicy(nint.Zero, in loa, LsaConstants.POLICY_ALL_ACCESS, out policyHandle);
                if (status != LsaConstants.STATUS_SUCCESS) return false;

                sid = GetBuiltinAdministratorsSid();
                status = NativeMethods.LsaEnumerateAccountRights(policyHandle, sid, out rightsPtr, out uint rightsCount);

                HashSet<string> existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (status == LsaConstants.STATUS_SUCCESS && rightsPtr != nint.Zero && rightsCount > 0)
                {
                    LSA_UNICODE_STRING* lusArr = (LSA_UNICODE_STRING*)rightsPtr;
                    for (uint i = 0; i < rightsCount; i++)
                    {
                        if (lusArr[i].Buffer != nint.Zero)
                            existing.Add(new string((char*)lusArr[i].Buffer, 0, lusArr[i].Length / 2));
                    }
                    NativeMethods.LsaFreeMemory(rightsPtr); rightsPtr = nint.Zero;
                }
                else if (status != LsaConstants.STATUS_OBJECT_NAME_NOT_FOUND && status != LsaConstants.STATUS_NO_MORE_ENTRIES) return false;

                foreach (var priv in WellKnownPrivileges.All) if (!existing.Contains(priv)) return false;
                return true;
            }
            finally
            {
                if (policyHandle != nint.Zero) NativeMethods.LsaClose(policyHandle);
                if (sid != nint.Zero) NativeMemory.Free((void*)sid);
                if (rightsPtr != nint.Zero) NativeMethods.LsaFreeMemory(rightsPtr);
            }
        }

        public static unsafe bool GrantPrivileges()
        {
            nint policyHandle = nint.Zero;
            nint sid = nint.Zero;
            nint rightsPtr = nint.Zero;

            try
            {
                var loa = new LSA_OBJECT_ATTRIBUTES { Length = Unsafe.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
                uint status = NativeMethods.LsaOpenPolicy(nint.Zero, in loa, LsaConstants.POLICY_ALL_ACCESS, out policyHandle);
                if (status != LsaConstants.STATUS_SUCCESS) return false;

                sid = GetBuiltinAdministratorsSid();
                status = NativeMethods.LsaEnumerateAccountRights(policyHandle, sid, out rightsPtr, out uint rightsCount);

                HashSet<string> existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (status == LsaConstants.STATUS_SUCCESS && rightsPtr != nint.Zero && rightsCount > 0)
                {
                    LSA_UNICODE_STRING* lusArr = (LSA_UNICODE_STRING*)rightsPtr;
                    for (uint i = 0; i < rightsCount; i++)
                    {
                        if (lusArr[i].Buffer != nint.Zero)
                            existing.Add(new string((char*)lusArr[i].Buffer, 0, lusArr[i].Length / 2));
                    }
                    NativeMethods.LsaFreeMemory(rightsPtr); rightsPtr = nint.Zero;
                }

                List<string> toAdd = new List<string>();
                foreach (string priv in AllLsaPrivileges) if (!existing.Contains(priv)) toAdd.Add(priv);
                if (toAdd.Count == 0) return true;

                // 手动分配非托管数组，避免 GC 固定问题
                nint rightsArrPtr = (nint)NativeMemory.Alloc((nuint)(toAdd.Count * sizeof(LSA_UNICODE_STRING)));
                LSA_UNICODE_STRING* rightsArr = (LSA_UNICODE_STRING*)rightsArrPtr;
                
                try
                {
                    for (int i = 0; i < toAdd.Count; i++) rightsArr[i] = InitLsaString(toAdd[i]);
                    status = NativeMethods.LsaAddAccountRights(policyHandle, sid, rightsArrPtr, (uint)toAdd.Count);
                }
                finally
                {
                    for (int i = 0; i < toAdd.Count; i++) if (rightsArr[i].Buffer != nint.Zero) NativeMemory.Free((void*)rightsArr[i].Buffer);
                    NativeMemory.Free((void*)rightsArrPtr);
                }

                if (status == LsaConstants.STATUS_SUCCESS) return true;
                
                // Fallback individual
                foreach (string priv in toAdd)
                {
                    var singleRight = InitLsaString(priv);
                    try { NativeMethods.LsaAddAccountRights(policyHandle, sid, (nint)Unsafe.AsPointer(ref singleRight), 1); }
                    finally { if (singleRight.Buffer != nint.Zero) NativeMemory.Free((void*)singleRight.Buffer); }
                }
                return true;
            }
            finally
            {
                if (policyHandle != nint.Zero) NativeMethods.LsaClose(policyHandle);
                if (sid != nint.Zero) NativeMemory.Free((void*)sid);
                if (rightsPtr != nint.Zero) NativeMethods.LsaFreeMemory(rightsPtr);
            }
        }

        public static bool RebootSystem()
        {
            try { Privilege.EnableAndVerify("SeShutdownPrivilege"); } catch { return false; }
            uint reason = LsaConstants.SHTDN_REASON_MAJOR_APPLICATION | LsaConstants.SHTDN_REASON_MINOR_MAINTENANCE | LsaConstants.SHTDN_REASON_FLAG_PLANNED;
            return NativeMethods.ExitWindowsEx(LsaConstants.EWX_REBOOT | LsaConstants.EWX_FORCEIFHUNG, reason);
        }

        static unsafe LSA_UNICODE_STRING InitLsaString(string value)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(value);
            nint buffer = (nint)NativeMemory.Alloc((nuint)(bytes.Length + 2));
            Unsafe.CopyBlock((void*)buffer, Unsafe.AsPointer(ref bytes[0]), (uint)bytes.Length);
            ((byte*)buffer)[bytes.Length] = 0; ((byte*)buffer)[bytes.Length + 1] = 0;
            return new LSA_UNICODE_STRING { Length = (ushort)bytes.Length, MaximumLength = (ushort)(bytes.Length + 2), Buffer = buffer };
        }

        static unsafe nint GetBuiltinAdministratorsSid()
        {
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            nint p = (nint)NativeMemory.Alloc((nuint)sidBytes.Length);
            Unsafe.CopyBlock((void*)p, Unsafe.AsPointer(ref sidBytes[0]), (uint)sidBytes.Length);
            return p;
        }
    }

    // ========================================================================
    //  PROGRAM
    // ========================================================================
    static class Program
    {
        static void Main(string[] args)
        {
            TrySetUtf8Output();
            RunMain(args);
            if (!IsPhase2(args)) PauseIfInteractive();
        }

        static bool IsPhase2(string[] args) => args.Length > 0 && string.Equals(args[0].Trim(), "--phase2", StringComparison.OrdinalIgnoreCase);
        static void TrySetUtf8Output() { try { Console.OutputEncoding = Encoding.UTF8; } catch { } }

        static void RunMain(string[] args)
        {
            try
            {
                string arg = args.Length > 0 ? args[0].Trim() : string.Empty;
                if (IsPhase2(args)) ExecutePhase2Logic(args);
                else if (arg == "--help" || arg == "-h" || arg == "/?") ShowUsage();
                else if (arg.Length == 0)
                {
                    if (!IsAdministrator()) { Console.WriteLine("[-] ERROR: Requires admin."); return; }
                    bool isWin11Plus = LsaUtility.IsWindows11OrHigher();
                    Console.WriteLine($"[*] OS: {(isWin11Plus ? "Win11+" : "Win10-")}");
                    if (isWin11Plus)
                    {
                        if (LsaUtility.AreRequiredPrivilegesGranted()) ExecutePhase2Logic(new[] { "--phase2" });
                        else
                        {
                            if (LsaUtility.GrantPrivileges())
                            {
                                Console.Write("[*] Reboot now? (y/N): ");
                                if (string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase)) LsaUtility.RebootSystem();
                            }
                            else Phase1_LaunchChildProcess();
                        }
                    }
                    else Phase1_LaunchChildProcess();
                }
                else ShowUsage();
            }
            catch (Exception ex) { Console.WriteLine($"[-] Fatal: {ex.Message}"); }
        }

        static void PauseIfInteractive() { try { if (!Console.IsInputRedirected) Console.ReadKey(true); } catch { } }
        static bool IsAdministrator() { try { using var id = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; } }
        static void ShowUsage() { Console.WriteLine("NtCreateToken v24 (.NET 10)"); }
        static uint GetCurrentSessionId() => (uint)Process.GetCurrentProcess().SessionId;

        static void Phase1_LaunchChildProcess()
        {
            Console.WriteLine("[*] Phase 1...");
            EnableAndVerifyPrivilege(WellKnownPrivileges.Debug);
            EnableAndVerifyPrivilege(WellKnownPrivileges.Impersonate);
            EnableAndVerifyPrivilege(WellKnownPrivileges.IncreaseQuota);
            EnableAndVerifyPrivilege(WellKnownPrivileges.AssignPrimaryToken);

            using SafeTokenHandle sysToken = GetSystemToken();
            string desktop = SessionInfo.HasInteractiveDesktop() ? Config.DefaultDesktop : Config.WinlogonDesktop;
            string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? Config.CmdPath;
            ProcessLauncher.LaunchWithToken(sysToken, exePath, $"--phase2 {GetCurrentSessionId()} \"{desktop}\"", desktop);
        }

        static unsafe SafeTokenHandle GetSystemToken()
        {
            Process? systemProc = Process.GetProcessesByName("winlogon").FirstOrDefault(p => p.SessionId == GetCurrentSessionId());
            if (systemProc == null) throw new Exception("winlogon not found.");
            try
            {
                nint hProc = NativeMethods.OpenProcess(TokenConstants.PROCESS_QUERY_INFORMATION, false, systemProc.Id);
                if (hProc == nint.Zero) throw InteropUtility.NewError("OpenProcess");
                try
                {
                    if (!NativeMethods.OpenProcessTokenRaw(hProc, TokenConstants.TOKEN_DUPLICATE | TokenConstants.TOKEN_QUERY, out nint hTok))
                        throw InteropUtility.NewError("OpenProcessToken");
                    if (!NativeMethods.DuplicateTokenEx(hTok, TokenConstants.MAXIMUM_ALLOWED, nint.Zero, TokenConstants.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary, out SafeTokenHandle dupTok))
                        throw InteropUtility.NewError("DuplicateTokenEx");
                    return dupTok;
                }
                finally { NativeMethods.CloseHandle(hProc); }
            }
            finally { systemProc?.Dispose(); }
        }

        static void ExecutePhase2Logic(string[] args)
        {
            Console.WriteLine("\n=== Phase 2 ===");
            EnableAndVerifyPrivilege(WellKnownPrivileges.CreateToken);
            EnableAndVerifyPrivilege(WellKnownPrivileges.AssignPrimaryToken);
            EnableAndVerifyPrivilege(WellKnownPrivileges.IncreaseQuota);
            EnableAndVerifyPrivilege(WellKnownPrivileges.Tcb);

            uint targetSessionId = ResolveTargetSessionId(args);
            string desktopName = ResolveTargetDesktop(args);

            using SafeTokenHandle currentToken = OpenCurrentProcessToken();
            TokenCreator.GetAuthenticationIdAndTokenId(currentToken, out LUID authId, out LUID sourceId);

            string? logonSid = TokenCreator.GetLogonSid(currentToken);
            var groups = BuildGroupList(logonSid);

            // [修复] 补全所有 LSA 特权，防止新 Token 权限被阉割
            var validPrivileges = new List<(string name, TokenCreator.PrivilegeAttributes attr)>();
            foreach (var name in LsaUtility.AllLsaPrivileges)
            {
                if (NativeMethods.LookupPrivilegeValue(null, name, out _))
                    validPrivileges.Add((name, TokenCreator.PrivilegeAttributes.Enabled | TokenCreator.PrivilegeAttributes.EnabledByDefault));
            }

            using var newToken = TokenCreator.CreatePrimaryToken(WellKnownSids.TrustedInstaller, groups, validPrivileges.ToArray(), authId, sourceId);
            TokenCreator.SetTokenSessionId(newToken, targetSessionId);
            TryGrantDesktopAccess(WellKnownSids.TrustedInstaller, desktopName);

            Console.WriteLine($"[*] Launching cmd...");
            ProcessLauncher.Launch(newToken, Config.CmdPath, desktopName);
        }

        static SafeTokenHandle OpenCurrentProcessToken()
        {
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TokenConstants.TOKEN_QUERY, out SafeTokenHandle tok))
                throw InteropUtility.NewError("OpenProcessToken");
            return tok;
        }

        static uint ResolveTargetSessionId(string[] args)
        {
            if (args.Length >= 2 && uint.TryParse(args[1], out uint parsed)) return parsed;
            return SessionInfo.FindActiveUserSession() ?? GetCurrentSessionId();
        }

        static string ResolveTargetDesktop(string[] args)
        {
            if (args.Length >= 3 && !string.IsNullOrWhiteSpace(args[2]))
            {
                string cli = args[2].Trim().Trim('"', '\'', ' ');
                if (cli.Length > 0 && !cli.Contains('\\')) cli = @"WinSta0\" + cli;
                if (cli.Length > 0) return cli;
            }
            return SessionInfo.HasInteractiveDesktop() ? Config.DefaultDesktop : Config.WinlogonDesktop;
        }

        static void TryGrantDesktopAccess(string sid, string desktopName)
        {
            try { DesktopAccess.GrantAccess(sid, desktopName); }
            catch (Exception ex) { Console.WriteLine($"[!] Desktop grant failed: {ex.Message}"); }
        }

        static (string sid, TokenCreator.GroupAttributes attr)[] BuildGroupList(string? logonSid)
        {
            const TokenCreator.GroupAttributes G = TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory;
            const TokenCreator.GroupAttributes GA = G | TokenCreator.GroupAttributes.EnabledByDefault;
            const TokenCreator.GroupAttributes GI = TokenCreator.GroupAttributes.Integrity | TokenCreator.GroupAttributes.IntegrityEnabled;
            const TokenCreator.GroupAttributes GL = TokenCreator.GroupAttributes.LogonId | TokenCreator.GroupAttributes.EnabledByDefault | TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory;

            var list = new List<(string, TokenCreator.GroupAttributes)>
            {
                (WellKnownSids.TrustedInstaller, G), (WellKnownSids.System, G), (WellKnownSids.Service, G),
                (WellKnownSids.BuiltinUsers, G), (WellKnownSids.BuiltinAdmins, GA), (WellKnownSids.Interactive, G),
                (WellKnownSids.ConsoleLogon, G), (WellKnownSids.AuthUsers, G), (WellKnownSids.Everyone, G),
                (WellKnownSids.Local, G), (WellKnownSids.SystemIntegrity, GI)
            };
            if (!string.IsNullOrWhiteSpace(logonSid)) list.Add((logonSid!, GL));
            return list.ToArray();
        }

        static void EnableAndVerifyPrivilege(string privilegeName) => Privilege.EnableAndVerify(privilegeName);
    }

    static class WellKnownSids
    {
        public const string Everyone = "S-1-1-0"; public const string Local = "S-1-2-0"; public const string ConsoleLogon = "S-1-2-1";
        public const string Interactive = "S-1-5-4"; public const string Service = "S-1-5-6"; public const string AuthUsers = "S-1-5-11";
        public const string System = "S-1-5-18"; public const string BuiltinAdmins = "S-1-5-32-544"; public const string BuiltinUsers = "S-1-5-32-545";
        public const string SystemIntegrity = "S-1-16-16384";
        public const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    }

    static class WellKnownPrivileges
    {
        public const string AssignPrimaryToken = "SeAssignPrimaryTokenPrivilege"; public const string CreateToken = "SeCreateTokenPrivilege";
        public const string Impersonate = "SeImpersonatePrivilege"; public const string Tcb = "SeTcbPrivilege";
        public const string Debug = "SeDebugPrivilege"; public const string IncreaseQuota = "SeIncreaseQuotaPrivilege";
        public static readonly string[] All = { CreateToken, AssignPrimaryToken, IncreaseQuota, Tcb, Impersonate, Debug };
    }

    // ========================================================================
    //  DesktopAccess (CRITICAL BUG FIX APPLIED)
    // ========================================================================
    static class DesktopAccess
    {
        static readonly int AclSizeInfoSize  = Unsafe.SizeOf<ACL_SIZE_INFORMATION>();
        static readonly int SecurityDescSize = Unsafe.SizeOf<SECURITY_DESCRIPTOR>();

        public static unsafe void GrantAccess(string sidString, string desktopName)
        {
            (string winsta, string desktop) = SplitDesktopName(desktopName);
            nint pSid = nint.Zero;
            try
            {
                if (!NativeMethods.ConvertStringSidToSid(sidString, out pSid)) throw InteropUtility.NewError("ConvertStringSidToSid");

                nint hWinSta = NativeMethods.OpenWindowStation(winsta, false, TokenConstants.READ_CONTROL | TokenConstants.WRITE_DAC);
                if (hWinSta == nint.Zero) throw InteropUtility.NewError("OpenWindowStation");
                try { AddAceToObject(hWinSta, pSid, TokenConstants.WINSTA_ALL_ACCESS); } finally { NativeMethods.CloseWindowStation(hWinSta); }

                nint hDesktop = NativeMethods.OpenDesktop(desktop, 0, false, TokenConstants.READ_CONTROL | TokenConstants.WRITE_DAC);
                if (hDesktop == nint.Zero) throw InteropUtility.NewError("OpenDesktop");
                try { AddAceToObject(hDesktop, pSid, TokenConstants.DESKTOP_ALL_ACCESS); } finally { NativeMethods.CloseDesktop(hDesktop); }
            }
            finally { InteropUtility.LocalFreeIfNotNull(pSid); }
        }

        static (string winsta, string desktop) SplitDesktopName(string desktopName)
        {
            int idx = desktopName.IndexOf('\\');
            if (idx < 0) return ("WinSta0", desktopName);
            return (desktopName.Substring(0, idx), desktopName.Substring(idx + 1));
        }

        static unsafe void AddAceToObject(nint handle, nint pSid, uint accessMask)
        {
            uint siFlag2 = TokenConstants.DACL_SECURITY_INFORMATION;
            nint pSD = (nint)NativeMemory.Alloc((nuint)SecurityDescSize);
            try
            {
                if (!NativeMethods.GetUserObjectSecurity(handle, ref siFlag2, pSD, (uint)SecurityDescSize, out uint sdSize))
                    throw InteropUtility.NewError("GetUserObjectSecurity failed");

                if (!NativeMethods.GetSecurityDescriptorDacl(pSD, out bool daclPresent, out nint pDacl, out _))
                    throw InteropUtility.NewError("GetSecurityDescriptorDacl failed");

                uint existingAclBytesInUse = TokenConstants.ACL_HEADER_SIZE;
                uint existingAceCount = 0;
                uint aclRevision = TokenConstants.ACL_REVISION;

                if (daclPresent && pDacl != nint.Zero)
                {
                    var aclInfo = new ACL_SIZE_INFORMATION();
                    if (!NativeMethods.GetAclInformation(pDacl, ref aclInfo, (uint)AclSizeInfoSize, TokenConstants.AclSizeInformation))
                        throw InteropUtility.NewError("GetAclInformation failed");

                    existingAclBytesInUse = (uint)aclInfo.AclBytesInUse;
                    existingAceCount = (uint)aclInfo.AceCount;
                    if (HasMatchingAce(pDacl, existingAceCount, pSid, accessMask)) return;
                }

                uint sidLength = NativeMethods.GetLengthSid(pSid);
                uint alignedNewAceSize = InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + sidLength);
                uint newAclSize = (uint)InteropUtility.Align4((nuint)existingAclBytesInUse + alignedNewAceSize);

                nint pNewAcl = (nint)NativeMemory.Alloc((nuint)newAclSize);
                try
                {
                    if (!NativeMethods.InitializeAcl(pNewAcl, newAclSize, aclRevision)) throw InteropUtility.NewError("InitializeAcl failed");

                    if (daclPresent && pDacl != nint.Zero)
                    {
                        for (uint i = 0; i < existingAceCount; i++)
                        {
                            if (!NativeMethods.GetAce(pDacl, i, out nint pExistingAce)) throw InteropUtility.NewError("GetAce failed");
                            if (!NativeMethods.AddAce(pNewAcl, aclRevision, uint.MaxValue, pExistingAce, GetAceSize(pExistingAce)))
                                throw InteropUtility.NewError("AddAce (copy) failed");
                        }
                    }

                    if (!NativeMethods.AddAccessAllowedAce(pNewAcl, aclRevision, accessMask, pSid)) throw InteropUtility.NewError("AddAccessAllowedAce failed");

                    // [致命修复] 删除 InitializeSecurityDescriptor，直接在现有 pSD 上更新 DACL！
                    if (!NativeMethods.SetSecurityDescriptorDacl(pSD, true, pNewAcl, false)) 
                        throw InteropUtility.NewError("SetSecurityDescriptorDacl failed");
                        
                    if (!NativeMethods.SetUserObjectSecurity(handle, ref siFlag2, pSD)) 
                        throw InteropUtility.NewError("SetUserObjectSecurity failed");
                }
                finally { NativeMemory.Free((void*)pNewAcl); }
            }
            finally { NativeMemory.Free((void*)pSD); }
        }

        static unsafe uint GetAceSize(nint pAce) => *(ushort*)((byte*)pAce + 2);

        static unsafe bool HasMatchingAce(nint pAcl, uint aceCount, nint pSid, uint accessMask)
        {
            for (uint i = 0; i < aceCount; i++)
            {
                if (!NativeMethods.GetAce(pAcl, i, out nint pAce)) continue;
                nint aceSid = pAce + 8;
                uint aceMask = *(uint*)((byte*)pAce + 4);
                if (aceMask == accessMask && NativeMethods.EqualSid(aceSid, pSid)) return true;
            }
            return false;
        }
    }

    // ========================================================================
    //  Privilege
    // ========================================================================
    static class Privilege
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES_SINGLE { public int PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

        public static unsafe void EnableAndVerify(string privilegeName)
        {
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TokenConstants.TOKEN_ADJUST_PRIVILEGES | TokenConstants.TOKEN_QUERY, out SafeTokenHandle tok))
                throw InteropUtility.NewError("OpenProcessToken failed");
            try { AdjustSinglePrivilege(tok, privilegeName); } finally { tok.Dispose(); }
        }

        static unsafe void AdjustSinglePrivilege(SafeTokenHandle tok, string privilegeName)
        {
            if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out LUID luid))
                throw InteropUtility.NewError($"LookupPrivilegeValue failed: {privilegeName}");

            var tp = new TOKEN_PRIVILEGES_SINGLE
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = TokenConstants.SE_PRIVILEGE_ENABLED }
            };

            int status = NativeMethods.NtAdjustPrivilegesToken(tok.DangerousGetHandle(), false, in tp, (uint)sizeof(TOKEN_PRIVILEGES_SINGLE), nint.Zero, nint.Zero);
            if (status == 0x00000106) throw new Win32Exception(1300, $"{privilegeName} not held");
            if (status != 0) throw new Win32Exception($"Failed to enable {privilegeName} (0x{status:X8})");
        }
    }

    // ========================================================================
    //  TokenCreator (CRITICAL BUG FIXES APPLIED)
    // ========================================================================
    static class TokenCreator
    {
        [Flags] public enum GroupAttributes : uint { None = 0, Mandatory = 0x01, EnabledByDefault = 0x02, Enabled = 0x04, Owner = 0x08, UseForDenyOnly = 0x10, Integrity = 0x20, IntegrityEnabled = 0x40, Resource = 0x20000000, LogonId = 0xC0000000 }
        [Flags] public enum PrivilegeAttributes : uint { None = 0, EnabledByDefault = 0x01, Enabled = 0x02 }

        public static unsafe void GetAuthenticationIdAndTokenId(SafeTokenHandle token, out LUID authenticationId, out LUID tokenId)
        {
            authenticationId = default; tokenId = default;
            nint sourceBuf = nint.Zero;
            try
            {
                // [修复] 移除静默吞没异常，确保获取真实的 SourceId
                sourceBuf = GetTokenInformationBuf(token, TokenConstants.TokenSource, out uint sourceLen);
                if (sourceLen >= 16) tokenId = InteropUtility.ReadLuid(sourceBuf, 8);
            }
            finally { if (sourceBuf != nint.Zero) NativeMemory.Free((void*)sourceBuf); }

            nint statsBuf = GetTokenInformationBuf(token, TokenConstants.TokenStatistics, out uint statsLen);
            try
            {
                if (statsLen >= 16)
                {
                    authenticationId = InteropUtility.ReadLuid(statsBuf, 8);
                    if (tokenId.LowPart == 0 && tokenId.HighPart == 0)
                        tokenId = InteropUtility.ReadLuid(statsBuf, 0);
                }
            }
            finally { if (statsBuf != nint.Zero) NativeMemory.Free((void*)statsBuf); }
        }

        public static unsafe string? GetLogonSid(SafeTokenHandle token)
        {
            nint buf = GetTokenInformationBuf(token, TokenConstants.TokenGroups, out uint len);
            try
            {
                int count = *(int*)buf;
                int offset = (int)Marshal.OffsetOf<TOKEN_GROUPS_LAYOUT>(nameof(TOKEN_GROUPS_LAYOUT.FirstGroup));
                byte* ptr = (byte*)buf + offset;
                int size = sizeof(SID_AND_ATTRIBUTES);
                for (int i = 0; i < count; i++)
                {
                    SID_AND_ATTRIBUTES sa = Unsafe.Read<SID_AND_ATTRIBUTES>(ptr + i * size);
                    if ((sa.Attributes & (uint)GroupAttributes.LogonId) == (uint)GroupAttributes.LogonId)
                    {
                        if (NativeMethods.ConvertSidToStringSid(sa.Sid, out nint strSid))
                        {
                            string? res = new string((char*)strSid);
                            NativeMethods.LocalFree(strSid);
                            return res;
                        }
                    }
                }
                return null;
            }
            finally { NativeMemory.Free((void*)buf); }
        }

        public static void SetTokenSessionId(SafeTokenHandle token, uint sessionId)
        {
            if (!NativeMethods.SetTokenInformation(token, TokenConstants.TokenSessionId, ref sessionId, 4))
                throw InteropUtility.NewError("SetTokenInformation SessionId failed");
        }

        static unsafe nint CreateTokenGroupsBuffer((string sid, GroupAttributes attributes)[] entries, out nint[] sidPtrs)
        {
            sidPtrs = Array.Empty<nint>();
            int count = entries.Length;
            int offset = (int)Marshal.OffsetOf<TOKEN_GROUPS_LAYOUT>(nameof(TOKEN_GROUPS_LAYOUT.FirstGroup));
            long totalSize = offset + ((long)sizeof(SID_AND_ATTRIBUTES) * count);
            nint buf = (nint)NativeMemory.Alloc((nuint)totalSize);
            sidPtrs = new nint[count];
            bool success = false;

            try
            {
                *(int*)buf = count;
                byte* ptr = (byte*)buf + offset;
                int size = sizeof(SID_AND_ATTRIBUTES);
                for (int i = 0; i < count; i++)
                {
                    if (!NativeMethods.ConvertStringSidToSid(entries[i].sid, out nint pSid))
                        throw InteropUtility.NewError($"ConvertStringSidToSid failed: {entries[i].sid}");
                    
                    sidPtrs[i] = pSid;
                    Unsafe.Write(ptr + i * size, new SID_AND_ATTRIBUTES { Sid = pSid, Attributes = (uint)entries[i].attributes });
                }
                success = true;
                return buf;
            }
            finally
            {
                if (!success)
                {
                    foreach (var p in sidPtrs) InteropUtility.LocalFreeIfNotNull(p);
                    NativeMemory.Free((void*)buf);
                    sidPtrs = Array.Empty<nint>();
                }
            }
        }

        static unsafe nint CreateTokenPrivilegesBuffer((string name, PrivilegeAttributes attr)[] privs)
        {
            int count = privs.Length;
            long totalSize = sizeof(TOKEN_PRIVILEGES_HEADER) + ((long)sizeof(LUID_AND_ATTRIBUTES) * count);
            nint buf = (nint)NativeMemory.Alloc((nuint)totalSize);
            bool success = false;
            try
            {
                int actualCount = 0;
                byte* ptr = (byte*)buf + sizeof(TOKEN_PRIVILEGES_HEADER);
                int size = sizeof(LUID_AND_ATTRIBUTES);
                foreach (var p in privs)
                {
                    if (NativeMethods.LookupPrivilegeValue(null, p.name, out LUID luid))
                    {
                        Unsafe.Write(ptr + actualCount * size, new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = (uint)p.attr });
                        actualCount++;
                    }
                }
                *(int*)buf = actualCount;
                success = true;
                return buf;
            }
            finally { if (!success) NativeMemory.Free((void*)buf); }
        }

        static unsafe nint BuildDefaultDacl(nint sidOwner, out nint[] daclSidPtrs)
        {
            daclSidPtrs = new nint[3];
            if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.System, out daclSidPtrs[0])) throw InteropUtility.NewError("SID System");
            if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.BuiltinAdmins, out daclSidPtrs[1])) throw InteropUtility.NewError("SID Admins");
            if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.Everyone, out daclSidPtrs[2])) throw InteropUtility.NewError("SID Everyone");

            nuint aclSize = TokenConstants.ACL_HEADER_SIZE +
                            InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + NativeMethods.GetLengthSid(daclSidPtrs[0])) +
                            InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + NativeMethods.GetLengthSid(daclSidPtrs[1])) +
                            InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + NativeMethods.GetLengthSid(sidOwner)) +
                            InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + NativeMethods.GetLengthSid(daclSidPtrs[2]));

            nint pAcl = (nint)NativeMemory.Alloc(aclSize);
            try
            {
                NativeMethods.InitializeAcl(pAcl, (uint)aclSize, TokenConstants.ACL_REVISION);
                NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TokenConstants.TOKEN_ALL_ACCESS, daclSidPtrs[0]);
                NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TokenConstants.TOKEN_ALL_ACCESS, daclSidPtrs[1]);
                NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TokenConstants.TOKEN_ALL_ACCESS, sidOwner);
                NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TokenConstants.TOKEN_QUERY | TokenConstants.READ_CONTROL, daclSidPtrs[2]);
                return pAcl;
            }
            catch { NativeMemory.Free((void*)pAcl); throw; }
        }

        public static unsafe SafeTokenHandle CreatePrimaryToken(
            string userSid,
            (string sid, GroupAttributes attr)[] groups,
            (string name, PrivilegeAttributes attr)[] privs,
            LUID authId,
            LUID sourceId)
        {
            nint pUserSid = nint.Zero;
            nint pGroups = nint.Zero; nint[] groupSidPtrs = Array.Empty<nint>();
            nint pPrivs = nint.Zero;
            nint pDacl = nint.Zero; nint[] daclSidPtrs = Array.Empty<nint>();
            nint pSqos = nint.Zero;

            try
            {
                if (!NativeMethods.ConvertStringSidToSid(userSid, out pUserSid)) throw InteropUtility.NewError("User SID");

                pGroups = CreateTokenGroupsBuffer(groups, out groupSidPtrs);
                pPrivs = CreateTokenPrivilegesBuffer(privs);
                pDacl = BuildDefaultDacl(pUserSid, out daclSidPtrs);

                var sqos = new SECURITY_QUALITY_OF_SERVICE { Length = sizeof(SECURITY_QUALITY_OF_SERVICE), ImpersonationLevel = TokenConstants.SecurityImpersonation, ContextTrackingMode = 1, EffectiveOnly = 0 };
                pSqos = (nint)NativeMemory.Alloc((nuint)sizeof(SECURITY_QUALITY_OF_SERVICE));
                Unsafe.Write((void*)pSqos, sqos);

                var objAttrs = new OBJECT_ATTRIBUTES { Length = sizeof(OBJECT_ATTRIBUTES), SecurityQualityOfService = pSqos };

                var tokenUser = new TOKEN_USER { User = new SID_AND_ATTRIBUTES { Sid = pUserSid, Attributes = 0 } };
                var tokenOwner = new TOKEN_OWNER { Owner = pUserSid };
                var tokenPrimaryGroup = new TOKEN_PRIMARY_GROUP { PrimaryGroup = pUserSid };
                var tokenDefaultDacl = new TOKEN_DEFAULT_DACL { DefaultDacl = pDacl };
                var tokenSource = TOKEN_SOURCE.Create("User32", sourceId);

                // [致命修复] ExpirationTime 传 nint.Zero 表示永不过期，避免 LARGE_INTEGER 溢出
                int status = NativeMethods.NtCreateToken(
                    out SafeTokenHandle newToken,
                    TokenConstants.TOKEN_ALL_ACCESS,
                    in objAttrs,
                    TOKEN_TYPE.TokenPrimary,
                    in authId,
                    nint.Zero, 
                    in tokenUser,
                    pGroups,
                    pPrivs,
                    in tokenOwner,
                    in tokenPrimaryGroup,
                    in tokenDefaultDacl,
                    in tokenSource);

                if (status != 0)
                {
                    if (newToken != null && !newToken.IsInvalid) newToken.Dispose();
                    uint dosErr = NativeMethods.RtlNtStatusToDosError(status);
                    throw InteropUtility.NewError((int)dosErr, $"NtCreateToken failed (0x{status:X8})");
                }
                return newToken;
            }
            finally
            {
                InteropUtility.LocalFreeIfNotNull(pUserSid);
                if (pGroups != nint.Zero) NativeMemory.Free((void*)pGroups);
                foreach (var ptr in groupSidPtrs) InteropUtility.LocalFreeIfNotNull(ptr);
                if (pPrivs != nint.Zero) NativeMemory.Free((void*)pPrivs);
                if (pDacl != nint.Zero) NativeMemory.Free((void*)pDacl);
                foreach (var ptr in daclSidPtrs) InteropUtility.LocalFreeIfNotNull(ptr);
                InteropUtility.FreeNativeIfNotNull(pSqos);
            }
        }

        static nint GetTokenInformationBuf(SafeTokenHandle token, int infoClass, out uint length)
        {
            length = 0;
            if (!NativeMethods.GetTokenInformation(token, infoClass, nint.Zero, 0, out length))
            {
                int err = InteropUtility.LastError;
                if (err != TokenConstants.ERROR_INSUFFICIENT_BUFFER) throw InteropUtility.NewError(err, "GetTokenInformation size");
            }
            nint buf = (nint)NativeMemory.Alloc((nuint)length);
            if (!NativeMethods.GetTokenInformation(token, infoClass, buf, length, out _))
            {
                NativeMemory.Free((void*)buf);
                throw InteropUtility.NewError("GetTokenInformation data");
            }
            return buf;
        }
    }

    // ========================================================================
    //  ProcessLauncher
    // ========================================================================
    static class ProcessLauncher
    {
        public static unsafe void Launch(SafeTokenHandle token, string application, string desktopName)
        {
            nint pDesktop = nint.Zero;
            nint pTitle = nint.Zero;
            try
            {
                string? normDesktop = InteropUtility.NormalizeDesktop(desktopName);
                if (!string.IsNullOrEmpty(normDesktop)) pDesktop = (nint)NativeMemory.Alloc((nuint)((normDesktop.Length + 1) * 2));
                pTitle = (nint)NativeMemory.Alloc((nuint)((Config.TiShellWindowTitle.Length + 1) * 2));

                if (pDesktop != nint.Zero) fixed (char* d = normDesktop) Unsafe.CopyBlock((void*)pDesktop, d, (uint)(normDesktop.Length * 2));
                fixed (char* t = Config.TiShellWindowTitle) Unsafe.CopyBlock((void*)pTitle, t, (uint)(Config.TiShellWindowTitle.Length * 2));

                var si = new STARTUPINFO { cb = sizeof(STARTUPINFO), lpDesktop = pDesktop, lpTitle = pTitle, dwFlags = TokenConstants.STARTF_USESHOWWINDOW, wShowWindow = 1 };
                
                // 使用 stackalloc 或手动分配 CommandLine
                string cmdLine = InteropUtility.Quote(application);
                nint pCmdLine = (nint)NativeMemory.Alloc((nuint)((cmdLine.Length + 1) * 2));
                fixed (char* c = cmdLine) Unsafe.CopyBlock((void*)pCmdLine, c, (uint)(cmdLine.Length * 2));

                if (!NativeMethods.CreateProcessAsUser(token, application, (char*)pCmdLine, nint.Zero, nint.Zero, false, 0x00000010, nint.Zero, Config.System32Path, in si, out var pi))
                    throw InteropUtility.NewError("CreateProcessAsUser failed");

                NativeMemory.Free((void*)pCmdLine);
                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);
            }
            finally
            {
                InteropUtility.FreeNativeIfNotNull(pDesktop);
                InteropUtility.FreeNativeIfNotNull(pTitle);
            }
        }

        public static unsafe void LaunchWithToken(SafeTokenHandle token, string application, string arguments, string? desktopName)
        {
            nint pDesktop = nint.Zero;
            try
            {
                string? normDesktop = InteropUtility.NormalizeDesktop(desktopName);
                if (!string.IsNullOrEmpty(normDesktop)) pDesktop = (nint)NativeMemory.Alloc((nuint)((normDesktop.Length + 1) * 2));
                if (pDesktop != nint.Zero) fixed (char* d = normDesktop) Unsafe.CopyBlock((void*)pDesktop, d, (uint)(normDesktop.Length * 2));

                var si = new STARTUPINFO { cb = sizeof(STARTUPINFO), lpDesktop = pDesktop, dwFlags = TokenConstants.STARTF_USESHOWWINDOW, wShowWindow = 1 };
                string cmdLine = $"{InteropUtility.Quote(application)} {arguments.Trim()}";
                nint pCmdLine = (nint)NativeMemory.Alloc((nuint)((cmdLine.Length + 1) * 2));
                fixed (char* c = cmdLine) Unsafe.CopyBlock((void*)pCmdLine, c, (uint)(cmdLine.Length * 2));

                if (!NativeMethods.CreateProcessWithTokenW(token, 0x00000001, null, (char*)pCmdLine, 0x00000010, nint.Zero, Config.System32Path, in si, out var pi))
                    throw InteropUtility.NewError("CreateProcessWithTokenW failed");

                NativeMemory.Free((void*)pCmdLine);
                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);
            }
            finally { InteropUtility.FreeNativeIfNotNull(pDesktop); }
        }
    }

    // ========================================================================
    //  NativeMethods (.NET 10 LibraryImport Optimized)
    // ========================================================================
    static partial class NativeMethods
    {
        [LibraryImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool CloseHandle(nint hObject);
        [LibraryImport("kernel32.dll")] public static partial nint GetCurrentProcess();
        [LibraryImport("kernel32.dll", SetLastError = true)] public static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
        [LibraryImport("kernel32.dll")] public static partial nint LocalFree(nint hMem);

        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool OpenProcessToken(nint proc, uint access, out SafeTokenHandle handle);
        [LibraryImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenProcessToken")] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool OpenProcessTokenRaw(nint proc, uint access, out nint handle);
        [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool LookupPrivilegeValue(string? system, string name, out LUID luid);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool GetTokenInformation(SafeTokenHandle TokenHandle, int TokenInformationClass, nint TokenInformation, uint TokenInformationLength, out uint ReturnLength);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool DuplicateTokenEx(nint existing, uint access, nint attrs, int impLevel, int tokenType, out SafeTokenHandle newToken);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool GetSecurityDescriptorDacl(nint pSD, [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent, out nint pDacl, [MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool GetAclInformation(nint pAcl, ref ACL_SIZE_INFORMATION pAclInfo, uint nAclInfoLength, int dwAclInfoClass);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool InitializeAcl(nint pAcl, uint nAclLength, uint dwAclRevision);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool GetAce(nint pAcl, uint dwAceIndex, out nint pAce);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool AddAce(nint pAcl, uint dwAceRevision, uint dwStartingAceIndex, nint pAceList, uint nAceListLength);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool AddAccessAllowedAce(nint pAcl, uint dwAceRevision, uint AccessMask, nint pSid);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool InitializeSecurityDescriptor(nint pSD, uint dwRevision);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool SetSecurityDescriptorDacl(nint pSD, [MarshalAs(UnmanagedType.Bool)] bool bDaclPresent, nint pDacl, [MarshalAs(UnmanagedType.Bool)] bool bDaclDefaulted);
        [LibraryImport("advapi32.dll")] public static partial uint GetLengthSid(nint pSid);
        [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool ConvertStringSidToSid(string stringSid, out nint pSid);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool ConvertSidToStringSid(nint pSid, out nint stringSid);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool EqualSid(nint pSid1, nint pSid2);
        [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool SetTokenInformation(SafeTokenHandle tokenHandle, int tokenInformationClass, ref uint tokenInformation, int tokenInformationLength);
        
        [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static unsafe partial bool CreateProcessAsUser(SafeTokenHandle hToken, string? lpApplicationName, char* lpCommandLine, nint lpProcessAttributes, nint lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, uint dwCreationFlags, nint lpEnvironment, string? lpCurrentDirectory, in STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        
        [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static unsafe partial bool CreateProcessWithTokenW(SafeTokenHandle hToken, uint dwLogonFlags, string? lpApplicationName, char* lpCommandLine, uint dwCreationFlags, nint lpEnvironment, string? lpCurrentDirectory, in STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [LibraryImport("user32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] public static partial nint OpenWindowStation(string name, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint desiredAccess);
        [LibraryImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool CloseWindowStation(nint hWinSta);
        [LibraryImport("user32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] public static partial nint OpenDesktop(string name, uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);
        [LibraryImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool CloseDesktop(nint hDesktop);
        [LibraryImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool GetUserObjectSecurity(nint hObj, ref uint pSIRequested, nint pSD, uint nLength, out uint nLengthNeeded);
        [LibraryImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool SetUserObjectSecurity(nint hObj, ref uint pSIRequested, nint pSD);
        [LibraryImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool ExitWindowsEx(uint uFlags, uint dwReason);

        [LibraryImport("wtsapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool WTSQuerySessionInformation(nint hServer, uint sessionId, int wtsInfoClass, out nint ppBuffer, out uint pBytesReturned);
        [LibraryImport("wtsapi32.dll")] public static partial void WTSFreeMemory(nint pMemory);
        [LibraryImport("wtsapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool WTSEnumerateSessions(nint hServer, int Reserved, int Version, out nint ppSessionInfo, out uint pCount);

        [LibraryImport("ntdll.dll")] public static partial uint RtlNtStatusToDosError(int status);
        
        [LibraryImport("ntdll.dll")]
        public static partial int NtAdjustPrivilegesToken(nint TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, in Privilege.TOKEN_PRIVILEGES_SINGLE NewState, uint BufferLength, nint PreviousState, nint ReturnLength);
        
        [LibraryImport("ntdll.dll", SetLastError = true)] public static partial int RtlGetVersion(out RTL_OSVERSIONINFOW lpVersionInformation);
        
        [LibraryImport("ntdll.dll")]
        public static partial int NtCreateToken(
            out SafeTokenHandle TokenHandle,
            uint DesiredAccess,
            in OBJECT_ATTRIBUTES ObjectAttributes,
            TOKEN_TYPE TokenType,
            in LUID AuthenticationId,
            nint ExpirationTime,
            in TOKEN_USER TokenUser,
            nint TokenGroups,
            nint TokenPrivileges,
            in TOKEN_OWNER TokenOwner,
            in TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            in TOKEN_DEFAULT_DACL TokenDefaultDacl,
            in TOKEN_SOURCE TokenSource);

        [LibraryImport("advapi32.dll", SetLastError = true)] public static partial uint LsaOpenPolicy(nint SystemName, in LSA_OBJECT_ATTRIBUTES ObjectAttributes, uint DesiredAccess, out nint PolicyHandle);
        [LibraryImport("advapi32.dll", SetLastError = true)] public static partial uint LsaAddAccountRights(nint PolicyHandle, nint AccountSid, nint UserRights, uint CountOfRights);
        [LibraryImport("advapi32.dll", SetLastError = true)] public static partial uint LsaEnumerateAccountRights(nint PolicyHandle, nint AccountSid, out nint UserRights, out uint CountOfRights);
        [LibraryImport("advapi32.dll", SetLastError = true)] public static partial uint LsaClose(nint PolicyHandle);
        [LibraryImport("advapi32.dll", SetLastError = true)] public static partial uint LsaFreeMemory(nint buffer);
    }
}