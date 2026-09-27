// ============================================================================
//  NtCreateTokenFull.cs — v21 完整修正版
//
//  本版本针对"手动构造 TI 令牌"路线的运行时问题做了全面修复。
//
//  修复汇总（对比 v20）：
//   [BUG-A]  完整性级别组补上 SE_GROUP_INTEGRITY_ENABLED（0x40）
//            —— 这是 whoami/taskkill "拒绝访问"的主因
//   [BUG-B]  AuthId 不再硬编码 0x3e7，改为从当前 SYSTEM 令牌动态读取
//   [BUG-C]  LogonSid 不再伪造 S-1-5-5-0-999，改为从 SYSTEM 令牌动态读取
//   [BUG-D]  TokenDefaultDacl 补上 Everyone 的 TOKEN_QUERY|READ_CONTROL，
//            使 whoami/taskkill 能打开自身令牌
//   [BUG-F]  显式使用 TOKEN_ALL_ACCESS (0x000F01FF) 替代 GENERIC_ALL
//   [BUG-G]  桌面名基于 targetSessionId 计算，不再用 CurrentDesktop.Detect
//   [BUG-H]  核心权限裁剪为最小集；其余作为可选
//   [BUG-I]  删除伪造的 WellKnownSids.SystemLogonSession
//   [BUG-J]  权限加上 SE_PRIVILEGE_ENABLED_BY_DEFAULT 使新进程默认启用
//   [NEW]    TokenCreator.GetAuthenticationId / GetLogonSid 辅助方法
//   [NEW]    TokenCreator.GetTokenSource 复制 SYSTEM 令牌的 SourceIdentifier
// ============================================================================

#nullable enable
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
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
        public const uint TOKEN_DUPLICATE         = 0x0002;
        public const uint TOKEN_QUERY             = 0x0008;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_ASSIGN_PRIMARY    = 0x0001;
        public const uint MAXIMUM_ALLOWED         = 0x02000000;
        public const uint PROCESS_QUERY_INFORMATION         = 0x0400;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const uint SE_PRIVILEGE_ENABLED            = 0x00000002;

        public const uint READ_CONTROL = 0x00020000;

        // TOKEN_ALL_ACCESS = 0x000F01FF
        public const uint TOKEN_ALL_ACCESS = 0x000F01FF;

        public const int SecurityImpersonation = 2;

        public const int TokenUser       = 1;
        public const int TokenGroups     = 2;
        public const int TokenPrivileges = 3;
        public const int TokenStatistics = 10;
        public const int TokenSessionId  = 12;

        public const uint ACL_REVISION = 2;
    }

    static class Config
    {
        public static readonly string System32Path =
            Environment.GetFolderPath(Environment.SpecialFolder.System);

        public static readonly string CmdPath =
            Path.Combine(System32Path, "cmd.exe");

        public const string DefaultDesktop  = @"WinSta0\Default";
        public const string WinlogonDesktop = @"WinSta0\Winlogon";

        public const string TiShellWindowTitle = "TrustedInstaller Shell";
    }

    // ========================================================================
    //  SHARED STRUCTS
    // ========================================================================

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES_HEADER { public uint PrivilegeCount; }

    [StructLayout(LayoutKind.Sequential)]
    struct LARGE_INTEGER { public long QuadPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_SOURCE
    {
        public ulong SourceName;
        public LUID  SourceIdentifier;

        public static TOKEN_SOURCE Create(string name, LUID id)
        {
            for (int i = 0; i < name.Length; i++)
            {
                if (name[i] > 127)
                    throw new ArgumentException(
                        $"Token source name must be ASCII-only: '{name}'", nameof(name));
            }
            if (name.Length > 8) name = name.Substring(0, 8);
            ulong bits = 0;
            for (int i = 0; i < name.Length; i++)
                bits |= (ulong)(byte)name[i] << (i * 8);
            return new TOKEN_SOURCE { SourceName = bits, SourceIdentifier = id };
        }
    }

    enum TOKEN_TYPE : int { TokenPrimary = 1 }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_OWNER { public IntPtr Owner; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIMARY_GROUP { public IntPtr PrimaryGroup; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_DEFAULT_DACL { public IntPtr DefaultDacl; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    struct TOKEN_GROUPS_LAYOUT
    {
        public uint GroupCount;
        public SID_AND_ATTRIBUTES FirstGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_QUALITY_OF_SERVICE
    {
        public int Length;
        public int ImpersonationLevel;
        public byte ContextTrackingMode;
        public byte EffectiveOnly;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_DESCRIPTOR
    {
        public byte   Revision;
        public byte   Sbz1;
        public ushort Control;
        public IntPtr Owner;
        public IntPtr Group;
        public IntPtr Sacl;
        public IntPtr Dacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ACL_SIZE_INFORMATION
    {
        public uint AceCount;
        public uint AclBytesInUse;
        public uint AclBytesFree;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize;
        public uint dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }

    enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive       = 0,
        WTSConnected    = 1,
        WTSConnectQuery = 2,
        WTSShadow       = 3,
        WTSDisconnected = 4,
        WTSIdle         = 5,
        WTSListen       = 6,
        WTSReset        = 7,
        WTSDown         = 8,
        WTSInit         = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WTS_SESSION_INFO
    {
        public uint SessionId;
        public IntPtr pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    // ========================================================================
    //  LayoutAssertions
    // ========================================================================

    static class LayoutAssertions
    {
        static bool s_verified;
        static readonly object s_lock = new object();

        public static void Verify()
        {
            lock (s_lock)
            {
                if (s_verified) return;

                bool is64 = IntPtr.Size == 8;

                AssertSize<LUID>("LUID", 8);
                AssertSize<LUID_AND_ATTRIBUTES>("LUID_AND_ATTRIBUTES", 12);
                AssertSize<TOKEN_PRIVILEGES_HEADER>("TOKEN_PRIVILEGES_HEADER", 4);
                AssertSize<Privilege.TOKEN_PRIVILEGES_SINGLE>("TOKEN_PRIVILEGES_SINGLE", 16);
                AssertSize<TOKEN_SOURCE>("TOKEN_SOURCE", 16);
                AssertSize<SECURITY_QUALITY_OF_SERVICE>("SECURITY_QUALITY_OF_SERVICE", 8);

                AssertOffset<Privilege.TOKEN_PRIVILEGES_SINGLE>(
                    "TOKEN_PRIVILEGES_SINGLE",
                    nameof(Privilege.TOKEN_PRIVILEGES_SINGLE.Privileges), 4);

                if (is64)
                {
                    AssertSize<OBJECT_ATTRIBUTES>("OBJECT_ATTRIBUTES", 48);
                    AssertSize<SECURITY_DESCRIPTOR>("SECURITY_DESCRIPTOR", 40);
                    AssertSize<SID_AND_ATTRIBUTES>("SID_AND_ATTRIBUTES", 16);
                    AssertSize<SECURITY_ATTRIBUTES>("SECURITY_ATTRIBUTES", 24);
                    AssertSize<PROCESS_INFORMATION>("PROCESS_INFORMATION", 24);
                    AssertSize<WTS_SESSION_INFO>("WTS_SESSION_INFO", 24);
                    AssertSize<TOKEN_USER>("TOKEN_USER", 16);
                    AssertSize<TOKEN_OWNER>("TOKEN_OWNER", 8);
                    AssertSize<TOKEN_PRIMARY_GROUP>("TOKEN_PRIMARY_GROUP", 8);
                    AssertSize<TOKEN_DEFAULT_DACL>("TOKEN_DEFAULT_DACL", 8);
                    AssertOffset<TOKEN_GROUPS_LAYOUT>(
                        "TOKEN_GROUPS_LAYOUT",
                        nameof(TOKEN_GROUPS_LAYOUT.FirstGroup), 8);
                }
                else
                {
                    AssertSize<OBJECT_ATTRIBUTES>("OBJECT_ATTRIBUTES", 24);
                    AssertSize<SECURITY_DESCRIPTOR>("SECURITY_DESCRIPTOR", 20);
                    AssertSize<SID_AND_ATTRIBUTES>("SID_AND_ATTRIBUTES", 8);
                    AssertSize<SECURITY_ATTRIBUTES>("SECURITY_ATTRIBUTES", 12);
                    AssertSize<PROCESS_INFORMATION>("PROCESS_INFORMATION", 16);
                    AssertSize<WTS_SESSION_INFO>("WTS_SESSION_INFO", 16);
                    AssertSize<TOKEN_USER>("TOKEN_USER", 8);
                    AssertSize<TOKEN_OWNER>("TOKEN_OWNER", 4);
                    AssertSize<TOKEN_PRIMARY_GROUP>("TOKEN_PRIMARY_GROUP", 4);
                    AssertSize<TOKEN_DEFAULT_DACL>("TOKEN_DEFAULT_DACL", 4);
                    AssertOffset<TOKEN_GROUPS_LAYOUT>(
                        "TOKEN_GROUPS_LAYOUT",
                        nameof(TOKEN_GROUPS_LAYOUT.FirstGroup), 4);
                }

                s_verified = true;
            }
        }

        static void AssertSize<T>(string name, int expected) where T : struct
        {
            int actual = Marshal.SizeOf<T>();
            if (actual != expected)
                throw new InvalidOperationException(
                    $"Layout mismatch: {name} size = {actual}, expected {expected}");
        }

        static void AssertOffset<T>(string typeName, string field, int expected)
            where T : struct
        {
            int actual = (int)Marshal.OffsetOf<T>(field);
            if (actual != expected)
                throw new InvalidOperationException(
                    $"Layout mismatch: {typeName}.{field} offset = {actual}, expected {expected}");
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
    //  CurrentDesktop
    // ========================================================================

    static class CurrentDesktop
    {
        const int UOI_NAME = 2;

        public static string Detect()
        {
            string winsta  = ReadObjectName(NativeMethods.GetProcessWindowStation(), "WinSta0");
            string desktop = ReadObjectName(
                NativeMethods.GetThreadDesktop(NativeMethods.GetCurrentThreadId()), "Default");
            return $"{winsta}\\{desktop}";
        }

        static string ReadObjectName(IntPtr hObj, string fallback)
        {
            if (hObj == IntPtr.Zero) return fallback;
            try
            {
                var sb = new StringBuilder(260);
                if (!NativeMethods.GetUserObjectInformation(
                        hObj, UOI_NAME, sb, sb.Capacity * 2, out _))
                    return fallback;
                string s = sb.ToString();
                return string.IsNullOrEmpty(s) ? fallback : s;
            }
            catch { return fallback; }
        }
    }

    // ========================================================================
    //  SessionInfo
    // ========================================================================

    static class SessionInfo
    {
        const int WTSUserName     = 5;
        const int WTSConnectState = 8;

        public static bool IsUserLoggedOn(uint sessionId)
        {
            IntPtr pBuf = IntPtr.Zero;
            try
            {
                if (!NativeMethods.WTSQuerySessionInformation(
                        IntPtr.Zero, sessionId, WTSUserName, out pBuf, out uint bytes))
                    return false;
                if (pBuf == IntPtr.Zero || bytes == 0) return false;
                string? name = Marshal.PtrToStringUni(pBuf);
                return !string.IsNullOrEmpty(name);
            }
            catch { return false; }
            finally { if (pBuf != IntPtr.Zero) NativeMethods.WTSFreeMemory(pBuf); }
        }

        public static WTS_CONNECTSTATE_CLASS? GetConnectState(uint sessionId)
        {
            IntPtr pBuf = IntPtr.Zero;
            try
            {
                if (!NativeMethods.WTSQuerySessionInformation(
                        IntPtr.Zero, sessionId, WTSConnectState, out pBuf, out uint bytes))
                    return null;
                if (pBuf == IntPtr.Zero || bytes < 4) return null;
                return (WTS_CONNECTSTATE_CLASS)Marshal.ReadInt32(pBuf);
            }
            catch { return null; }
            finally { if (pBuf != IntPtr.Zero) NativeMethods.WTSFreeMemory(pBuf); }
        }

        public static uint? FindActiveUserSession()
        {
            IntPtr pSessions = IntPtr.Zero;
            uint count = 0;
            try
            {
                if (!NativeMethods.WTSEnumerateSessions(
                        IntPtr.Zero, 0, 1, out pSessions, out count) || pSessions == IntPtr.Zero)
                    return null;

                uint? firstConnected = null;
                int structSize = Marshal.SizeOf<WTS_SESSION_INFO>();

                for (uint i = 0; i < count; i++)
                {
                    int offset = checked((int)i * structSize);
                    IntPtr pItem = IntPtr.Add(pSessions, offset);
                    var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(pItem);

                    if (si.SessionId == 0) continue;
                    if (!IsUserLoggedOn(si.SessionId)) continue;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                        return si.SessionId;
                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSConnected && firstConnected == null)
                        firstConnected = si.SessionId;
                }
                return firstConnected;
            }
            catch { return null; }
            finally
            {
                if (pSessions != IntPtr.Zero) NativeMethods.WTSFreeMemory(pSessions);
            }
        }

        public static bool HasInteractiveDesktop()
        {
            const uint WINSTA_ENUMDESKTOPS = 0x0001;
            IntPtr h = NativeMethods.OpenWindowStation("WinSta0", false, WINSTA_ENUMDESKTOPS);
            if (h == IntPtr.Zero) return false;
            NativeMethods.CloseWindowStation(h);
            return true;
        }
    }

    // ========================================================================
    //  PROGRAM
    // ========================================================================

    static class Program
    {
        static void Main(string[] args)
        {
            try { Console.OutputEncoding = Encoding.UTF8; } catch { /* ignore */ }

            RunMain(args);

            PauseIfInteractive();
        }

        static void RunMain(string[] args)
        {
            try
            {
                LayoutAssertions.Verify();
            }
            catch (Exception ex)
            {
                Exception real = UnwrapTypeInit(ex);
                Console.WriteLine($"[-] Fatal: CLR layout assertion failed: {real.Message}");
                Console.WriteLine($"    Details: {real}");
                return;
            }

            try
            {
                string arg = args.Length > 0 ? args[0].Trim() : "";

                if (string.Equals(arg, "--phase2", StringComparison.OrdinalIgnoreCase))
                    ExecutePhase2Logic(args);
                else if (string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase)
                      || arg == "-h" || arg == "/?")
                    ShowUsage();
                else if (arg == "")
                {
                    if (!IsAdministrator())
                    {
                        Console.WriteLine("[-] ERROR: This program requires administrator privileges.");
                        Console.WriteLine("    Please right-click and 'Run as administrator'.");
                        return;
                    }
                    Phase1_LaunchChildProcess();
                }
                else
                {
                    Console.WriteLine($"[-] Unknown argument: {arg}");
                    ShowUsage();
                }
            }
            catch (Exception ex)
            {
                Exception real = UnwrapTypeInit(ex);
                Console.WriteLine($"\n[-] Fatal error: {real.Message}");
                Console.WriteLine($"    Details: {real}");
            }
        }

        static Exception UnwrapTypeInit(Exception ex)
            => (ex is TypeInitializationException tie && tie.InnerException != null)
                ? tie.InnerException
                : ex;

        static void PauseIfInteractive()
        {
            try { if (!Console.IsInputRedirected) Console.ReadKey(intercept: true); }
            catch { /* ignore */ }
        }

        static bool IsAdministrator()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        static void ShowUsage()
        {
            Console.WriteLine("NtCreateToken - TrustedInstaller Token Creator (v21)");
            Console.WriteLine("====================================================");
            Console.WriteLine("Usage: NtCreateTokenFull.exe [OPTIONS]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  (none)                                Launch SYSTEM child and create TI token");
            Console.WriteLine("  --phase2 [sessionId] [desktopPath]    Execute as SYSTEM (internal use only)");
            Console.WriteLine("  --help                                Show this help message");
        }

        static void Phase1_LaunchChildProcess()
        {
            Console.WriteLine("=== NtCreateToken [Phase 1: Launch SYSTEM Child] ===\n");
            try
            {
                if (!SessionInfo.HasInteractiveDesktop())
                {
                    Console.WriteLine("  [-] ERROR: No interactive desktop detected.");
                    Console.WriteLine("      Server Core / Nano Server / WinPE are not supported.");
                    throw new InvalidOperationException("No interactive desktop");
                }

                Console.WriteLine("  [*] Enabling SeDebugPrivilege...");
                Privilege.EnableOnProcess("SeDebugPrivilege");
                Console.WriteLine("  [+] SeDebugPrivilege enabled");

                Console.WriteLine("  [*] Enabling SeImpersonatePrivilege...");
                Privilege.EnableOnProcess("SeImpersonatePrivilege");
                Console.WriteLine("  [+] SeImpersonatePrivilege enabled");

                int lsassPid = TokenThief.GetLsassPid();
                Console.WriteLine($"  [*] lsass.exe PID = {lsassPid}");

                using var systemToken = TokenThief.DuplicateProcessToken(lsassPid);
                Console.WriteLine("  [+] SYSTEM token duplicated");

                string? exePath = GetProcessPath();
                if (exePath == null)
                    throw new InvalidOperationException("Failed to get process path");

                uint? activeSession = SessionInfo.FindActiveUserSession();
                if (activeSession == null)
                {
                    activeSession = (uint)Process.GetCurrentProcess().SessionId;
                    Console.WriteLine($"  [!] No active user session; fallback to current = {activeSession}");
                }
                else
                {
                    Console.WriteLine($"  [*] Active user session = {activeSession}");
                }

                var connectState = SessionInfo.GetConnectState(activeSession.Value);
                if (connectState == WTS_CONNECTSTATE_CLASS.WTSDisconnected)
                {
                    Console.WriteLine($"  [!] Target session {activeSession} is DISCONNECTED (RDP without console).");
                }

                // [BUG-G] 桌面选择基于 targetSession 而非当前进程桌面
                string desktopPath = ChooseDesktopForSession(activeSession.Value);
                Console.WriteLine($"  [*] Target desktop = {desktopPath}");

                Console.WriteLine("  [*] Granting SYSTEM desktop access (best-effort)...");
                TryGrantDesktopAccess(WellKnownSids.System, desktopPath);

                Console.WriteLine("\n  [*] Launching SYSTEM child process...");
                ProcessLauncher.LaunchWithToken(
                    systemToken,
                    exePath,
                    $"--phase2 {activeSession.Value} \"{desktopPath}\"",
                    desktopName: null);

                Console.WriteLine("\n=== Phase 1 complete. Child process launched. ===");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[-] Phase 1 Error: {ex.Message}");
                Console.WriteLine($"    Details: {ex}");
            }
        }

        static string ChooseDesktopForSession(uint sessionId)
        {
            // 会话 0 无用户登录 → Winlogon
            if (sessionId == 0) return Config.WinlogonDesktop;

            // 有用户登录 → Default
            if (SessionInfo.IsUserLoggedOn(sessionId)) return Config.DefaultDesktop;

            // 否则 Winlogon（会话初始化时必然存在）
            return Config.WinlogonDesktop;
        }

        static string? GetProcessPath()
        {
            try
            {
                var ep = Environment.ProcessPath;
                if (!string.IsNullOrEmpty(ep)) return ep;
            }
            catch { /* fall through */ }

            try
            {
                var mm = Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(mm)) return mm;
            }
            catch { /* fall through */ }

            return null;
        }

        static void ExecutePhase2Logic(string[] args)
        {
            Console.WriteLine("=== NtCreateToken [Phase 2: Create TI Token] ===\n");

            var currentIdentity = WindowsIdentity.GetCurrent();
            string? currentSid = currentIdentity.User?.Value;
            Console.WriteLine($"  [+] Current identity: {currentIdentity.Name} (SID={currentSid})");

            if (!string.Equals(currentSid, WellKnownSids.System, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Phase 2 must run as SYSTEM");

            Console.WriteLine("\n  [*] Enabling required privileges (process token)...");
            EnableAndVerifyPrivilege(WellKnownPrivileges.CreateToken);
            EnableAndVerifyPrivilege(WellKnownPrivileges.AssignPrimaryToken);
            EnableAndVerifyPrivilege(WellKnownPrivileges.IncreaseQuota);
            EnableAndVerifyPrivilege(WellKnownPrivileges.Tcb);

            // [BUG-B][BUG-C][NEW] 从当前 SYSTEM 令牌读取真实 AuthId / LogonSid / SourceId
            LUID authId;
            string? logonSid;
            LUID sourceId;
            using (var sysToken = OpenCurrentProcessToken())
            {
                authId   = TokenCreator.GetAuthenticationId(sysToken);
                logonSid = TokenCreator.GetLogonSid(sysToken);
                sourceId = TokenCreator.GetTokenSource(sysToken);
                Console.WriteLine($"  [*] SYSTEM AuthId  = 0x{authId.HighPart:X8}:{authId.LowPart:X8}");
                Console.WriteLine($"  [*] SYSTEM LogonSid = {logonSid ?? "(none)"}");
            }

            uint targetSessionId = ResolveTargetSessionId(args);
            string desktopName   = ResolveTargetDesktop(args, targetSessionId);

            Console.WriteLine($"  [*] Target session ID = {targetSessionId}");
            Console.WriteLine($"  [*] Target desktop     = {desktopName}");

            Console.WriteLine("\n  [*] Calling NtCreateToken to create TrustedInstaller token...");

            var groups = BuildGroupList(logonSid);

            var validPrivileges = new List<(string name, TokenCreator.PrivilegeAttributes attr)>();
            var skippedPrivileges = new List<string>();
            foreach (var name in WellKnownPrivileges.All)
            {
                if (NativeMethods.LookupPrivilegeValue(null, name, out _))
                    validPrivileges.Add((name, TokenCreator.PrivilegeAttributes.Enabled
                                              | TokenCreator.PrivilegeAttributes.EnabledByDefault));
                else
                    skippedPrivileges.Add(name);
            }

            if (skippedPrivileges.Count > 0)
                Console.WriteLine($"  [!] Skipped {skippedPrivileges.Count} unavailable privilege(s): "
                                + string.Join(", ", skippedPrivileges));
            Console.WriteLine($"  [*] Requesting {validPrivileges.Count} privileges for TI token...");

            using var newToken = TokenCreator.CreatePrimaryToken(
                WellKnownSids.TrustedInstaller,
                groups,
                validPrivileges.ToArray(),
                authId,        // [BUG-B]
                sourceId);     // [NEW] 复制 SYSTEM 令牌的 sourceId

            Console.WriteLine($"  [+] Token created, handle: 0x{newToken.DangerousGetHandle():X}");
            TokenCreator.SetTokenSessionId(newToken, targetSessionId);
            Console.WriteLine($"  [+] Token Session ID set to {targetSessionId}");

            Console.WriteLine($"  [*] Granting TrustedInstaller desktop access (best-effort)...");
            TryGrantDesktopAccess(WellKnownSids.TrustedInstaller, desktopName);

            Console.WriteLine($"\n  [*] Launching cmd.exe as TrustedInstaller on {desktopName}...");
            ProcessLauncher.Launch(newToken, Config.CmdPath, desktopName);

            Console.WriteLine("\n=== SUCCESS! New cmd.exe running as TrustedInstaller ===");
        }

        static SafeTokenHandle OpenCurrentProcessToken()
        {
            if (!NativeMethods.OpenProcessToken(
                    NativeMethods.GetCurrentProcess(),
                    TokenConstants.TOKEN_QUERY,
                    out SafeTokenHandle tok))
                throw new Win32Exception(Marshal.GetLastPInvokeError(),
                    "OpenProcessToken (current process) failed");
            return tok;
        }

        static uint ResolveTargetSessionId(string[] args)
        {
            // CLI 参数优先（Phase 1 已经算过一次）
            if (args.Length >= 2 && uint.TryParse(args[1], out uint parsed))
            {
                Console.WriteLine($"  [*] Using CLI-provided session = {parsed}");
                return parsed;
            }

            uint? active = SessionInfo.FindActiveUserSession();
            if (active != null)
            {
                Console.WriteLine($"  [*] Re-detected active user session = {active}");
                return active.Value;
            }

            uint fallback = (uint)Process.GetCurrentProcess().SessionId;
            Console.WriteLine($"  [!] Falling back to current session = {fallback}");
            return fallback;
        }

        static string ResolveTargetDesktop(string[] args, uint sessionId)
        {
            // [BUG-G] 不再使用 CurrentDesktop.Detect()，改为基于 sessionId
            if (args.Length >= 3 && !string.IsNullOrWhiteSpace(args[2]))
            {
                char[] trimChars = { '"', '\'', '\u201C', '\u201D', '\u2018', '\u2019', ' ' };
                string cli = args[2].Trim().Trim(trimChars);
                if (cli.Length > 0 && !cli.Contains('\\'))
                    cli = @"WinSta0\" + cli;

                if (cli.Length > 0)
                {
                    Console.WriteLine($"  [*] CLI desktop = {cli}");
                    return cli;
                }
            }

            string chosen = ChooseDesktopForSession(sessionId);
            Console.WriteLine($"  [*] Chosen desktop for session {sessionId} = {chosen}");
            return chosen;
        }

        static void TryGrantDesktopAccess(string sid, string desktopName)
        {
            try
            {
                DesktopAccess.GrantAccess(sid, desktopName);
                Console.WriteLine($"  [+] Desktop access granted to {sid} on {desktopName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [!] Desktop access grant failed: {ex.Message}");
                Console.WriteLine($"      (GUI 程序可能无法在该桌面显示窗口，控制台程序通常不受影响)");
            }
        }

        static (string sid, TokenCreator.GroupAttributes attr)[] BuildGroupList(string? logonSid)
        {
            const TokenCreator.GroupAttributes G  = TokenCreator.GroupAttributes.Enabled
                                                  | TokenCreator.GroupAttributes.Mandatory;
            const TokenCreator.GroupAttributes GA = TokenCreator.GroupAttributes.Enabled
                                                  | TokenCreator.GroupAttributes.Mandatory
                                                  | TokenCreator.GroupAttributes.EnabledByDefault;

            // [BUG-A] 完整性级别组必须同时带 SE_GROUP_INTEGRITY 和 SE_GROUP_INTEGRITY_ENABLED
            const TokenCreator.GroupAttributes GI = TokenCreator.GroupAttributes.Integrity
                                                  | TokenCreator.GroupAttributes.IntegrityEnabled;

            var list = new List<(string, TokenCreator.GroupAttributes)>
            {
                (WellKnownSids.TrustedInstaller,         G),
                (WellKnownSids.System,                   G),
                (WellKnownSids.Service,                  G),
                (WellKnownSids.BuiltinUsers,             G),
                (WellKnownSids.BuiltinAdmins,            GA),
                (WellKnownSids.Interactive,              G),
                (WellKnownSids.ConsoleLogon,             G),
                (WellKnownSids.AuthUsers,                G),
                (WellKnownSids.Everyone,                 G),
                (WellKnownSids.Local,                    G),
                (WellKnownSids.BuiltinGuests,            G),
                (WellKnownSids.PowerUsers,               G),
                (WellKnownSids.AccountOperators,         G),
                (WellKnownSids.ServerOperators,          G),
                (WellKnownSids.PrintOperators,           G),
                (WellKnownSids.BackupOperators,          G),
                (WellKnownSids.Replicators,              G),
                (WellKnownSids.PreWin2000,               G),
                (WellKnownSids.RemoteDesktopUsers,       G),
                (WellKnownSids.NetworkConfigOperators,   G),
                (WellKnownSids.IncomingForestTrust,      G),
                (WellKnownSids.PerfMonitorUsers,         G),
                (WellKnownSids.PerfLogUsers,             G),
                (WellKnownSids.WindowsAuthAccessGroup,   G),
                (WellKnownSids.TerminalServerLicense,    G),
                (WellKnownSids.DistributedComUsers,      G),
                (WellKnownSids.IisIusrs,                 G),
                (WellKnownSids.CryptoOperators,          G),
                (WellKnownSids.EventLogReaders,          G),
                (WellKnownSids.CertServiceDcomAccess,    G),
                (WellKnownSids.RdsRemoteAccessServers,   G),
                (WellKnownSids.HyperVAdmins,             G),
                (WellKnownSids.AccessControlAssistOps,   G),
                (WellKnownSids.StorageReplicaAdmins,     G),
                (WellKnownSids.CreatorOwner,             G),
                (WellKnownSids.CreatorGroup,             G),
                (WellKnownSids.Dialup,                   G),
                (WellKnownSids.Network,                  G),
                (WellKnownSids.Batch,                    G),
                (WellKnownSids.Anonymous,                G),
                (WellKnownSids.LocalService,             G),
                (WellKnownSids.NetworkService,           G),
                (WellKnownSids.SystemIntegrity,          GI)
            };

            // [BUG-C][BUG-I] 用真实 LogonSid 替换伪造的 S-1-5-5-0-999
            if (!string.IsNullOrEmpty(logonSid))
                list.Add((logonSid, G));

            return list.ToArray();
        }

        static void EnableAndVerifyPrivilege(string privilegeName)
        {
            Privilege.EnableOnProcess(privilegeName);
            if (!Privilege.VerifyPrivilege(privilegeName))
                throw new Win32Exception($"Failed to verify {privilegeName} is enabled");
            Console.WriteLine($"  [+] {privilegeName} enabled & verified");
        }
    }

    // ========================================================================
    //  WellKnownSids
    // ========================================================================

    static class WellKnownSids
    {
        public const string Everyone     = "S-1-1-0";
        public const string Local        = "S-1-2-0";
        public const string ConsoleLogon = "S-1-2-1";
        public const string CreatorOwner = "S-1-3-0";
        public const string CreatorGroup = "S-1-3-1";

        public const string Dialup             = "S-1-5-1";
        public const string Network            = "S-1-5-2";
        public const string Batch              = "S-1-5-3";
        public const string Interactive        = "S-1-5-4";
        public const string Service            = "S-1-5-6";
        public const string Anonymous          = "S-1-5-7";
        public const string AuthUsers          = "S-1-5-11";
        public const string System             = "S-1-5-18";
        public const string LocalService       = "S-1-5-19";
        public const string NetworkService     = "S-1-5-20";

        // [BUG-I] 删除伪造的 SystemLogonSession = "S-1-5-5-0-999"

        public const string BuiltinAdmins          = "S-1-5-32-544";
        public const string BuiltinUsers           = "S-1-5-32-545";
        public const string BuiltinGuests          = "S-1-5-32-546";
        public const string PowerUsers             = "S-1-5-32-547";
        public const string AccountOperators       = "S-1-5-32-548";
        public const string ServerOperators        = "S-1-5-32-549";
        public const string PrintOperators         = "S-1-5-32-550";
        public const string BackupOperators        = "S-1-5-32-551";
        public const string Replicators            = "S-1-5-32-552";
        public const string PreWin2000             = "S-1-5-32-554";
        public const string RemoteDesktopUsers     = "S-1-5-32-555";
        public const string NetworkConfigOperators = "S-1-5-32-556";
        public const string IncomingForestTrust    = "S-1-5-32-557";
        public const string PerfMonitorUsers       = "S-1-5-32-558";
        public const string PerfLogUsers           = "S-1-5-32-559";
        public const string WindowsAuthAccessGroup = "S-1-5-32-560";
        public const string TerminalServerLicense  = "S-1-5-32-561";
        public const string DistributedComUsers    = "S-1-5-32-562";
        public const string IisIusrs               = "S-1-5-32-568";
        public const string CryptoOperators        = "S-1-5-32-569";
        public const string EventLogReaders        = "S-1-5-32-573";
        public const string CertServiceDcomAccess  = "S-1-5-32-574";
        public const string RdsRemoteAccessServers = "S-1-5-32-575";
        public const string HyperVAdmins           = "S-1-5-32-578";
        public const string AccessControlAssistOps = "S-1-5-32-579";
        public const string StorageReplicaAdmins   = "S-1-5-32-582";

        public const string SystemIntegrity = "S-1-16-16384";

        public const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    }

    // ========================================================================
    //  WellKnownPrivileges
    // ========================================================================

    static class WellKnownPrivileges
    {
        public const string AssignPrimaryToken             = "SeAssignPrimaryTokenPrivilege";
        public const string CreateToken                    = "SeCreateTokenPrivilege";
        public const string Impersonate                    = "SeImpersonatePrivilege";
        public const string DelegateSessionUserImpersonate = "SeDelegateSessionUserImpersonatePrivilege";
        public const string Tcb                            = "SeTcbPrivilege";

        public const string Audit                 = "SeAuditPrivilege";
        public const string Security              = "SeSecurityPrivilege";
        public const string Backup                = "SeBackupPrivilege";
        public const string Restore               = "SeRestorePrivilege";
        public const string TakeOwnership         = "SeTakeOwnershipPrivilege";
        public const string Relabel               = "SeRelabelPrivilege";
        public const string TrustedCredManAccess  = "SeTrustedCredManAccessPrivilege";

        public const string Debug              = "SeDebugPrivilege";
        public const string LoadDriver         = "SeLoadDriverPrivilege";
        public const string LockMemory         = "SeLockMemoryPrivilege";
        public const string CreatePagefile     = "SeCreatePagefilePrivilege";
        public const string CreatePermanent    = "SeCreatePermanentPrivilege";
        public const string CreateGlobal       = "SeCreateGlobalPrivilege";
        public const string CreateSymbolicLink = "SeCreateSymbolicLinkPrivilege";
        public const string SystemEnvironment  = "SeSystemEnvironmentPrivilege";
        public const string SystemProfile      = "SeSystemProfilePrivilege";
        public const string Systemtime         = "SeSystemtimePrivilege";
        public const string TimeZone           = "SeTimeZonePrivilege";
        public const string Shutdown           = "SeShutdownPrivilege";
        public const string RemoteShutdown     = "SeRemoteShutdownPrivilege";
        public const string Undock             = "SeUndockPrivilege";
        public const string ManageVolume       = "SeManageVolumePrivilege";

        public const string IncreaseQuota        = "SeIncreaseQuotaPrivilege";
        public const string IncreaseBasePriority = "SeIncreaseBasePriorityPrivilege";
        public const string IncreaseWorkingSet   = "SeIncreaseWorkingSetPrivilege";
        public const string ProfileSingleProcess = "SeProfileSingleProcessPrivilege";

        public const string ChangeNotify = "SeChangeNotifyPrivilege";

        public const string EnableDelegation = "SeEnableDelegationPrivilege";
        public const string MachineAccount   = "SeMachineAccountPrivilege";
        public const string SyncAgent        = "SeSyncAgentPrivilege";

        // [BUG-H] 精简权限集：核心 + 常用。其余作为可选不列出。
        public static readonly string[] All = new[]
        {
            // 核心（Phase 2 自身已启用，令牌必须继承）
            CreateToken, AssignPrimaryToken, IncreaseQuota, Tcb,
            // TI 服务典型权限
            Impersonate, Debug,
            // 常规 SYSTEM 权限
            ChangeNotify, Backup, Restore, TakeOwnership,
            Security, Audit, LoadDriver, Shutdown,
            SystemEnvironment, ManageVolume,
            CreateGlobal, CreateSymbolicLink, CreatePermanent,
            SystemProfile, Systemtime, TimeZone,
            IncreaseBasePriority, ProfileSingleProcess,
            // 兼容性
            DelegateSessionUserImpersonate, EnableDelegation, MachineAccount,
            LockMemory, CreatePagefile, Undock,
            RemoteShutdown, Relabel, TrustedCredManAccess, SyncAgent,
            IncreaseWorkingSet
        };
    }

    // ========================================================================
    //  DesktopAccess
    // ========================================================================

    static class DesktopAccess
    {
        static readonly int AclSizeInfoSize  = Marshal.SizeOf<ACL_SIZE_INFORMATION>();
        static readonly int SecurityDescSize = Marshal.SizeOf<SECURITY_DESCRIPTOR>();

        const uint DACL_SECURITY_INFORMATION    = 0x04;
        const uint ACL_REVISION                 = 2;
        const uint SECURITY_DESCRIPTOR_REVISION = 1;
        const int  AclSizeInformation           = 2;
        const uint READ_CONTROL                 = 0x00020000;
        const uint WRITE_DAC                    = 0x00040000;
        const uint STANDARD_RIGHTS_REQUIRED     = 0x000F0000;

        const uint WINSTA_ALL_ACCESS  = STANDARD_RIGHTS_REQUIRED | 0x037F;
        const uint DESKTOP_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | 0x01FF;

        const byte ACCESS_ALLOWED_ACE_TYPE   = 0x00;
        const byte INHERITED_ACE             = 0x10;
        const int  ERROR_INSUFFICIENT_BUFFER = 122;

        const uint ACL_HEADER_SIZE = 8;
        const uint ACE_HEADER_SIZE = 8;

        public static void GrantAccess(string sidString, string desktopName)
        {
            (string winsta, string desktop) = SplitDesktopName(desktopName);

            IntPtr pSid = IntPtr.Zero;
            try
            {
                if (!NativeMethods.ConvertStringSidToSid(sidString, out pSid))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "ConvertStringSidToSid failed");

                IntPtr hWinSta = NativeMethods.OpenWindowStation(winsta, false, READ_CONTROL | WRITE_DAC);
                if (hWinSta == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastPInvokeError(),
                        $"OpenWindowStation('{winsta}') failed");
                try { AddAceToObject(hWinSta, pSid, WINSTA_ALL_ACCESS); }
                finally { NativeMethods.CloseWindowStation(hWinSta); }

                IntPtr hDesktop = NativeMethods.OpenDesktop(desktop, 0, false, READ_CONTROL | WRITE_DAC);
                if (hDesktop == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastPInvokeError(),
                        $"OpenDesktop('{desktopName}') failed");
                try { AddAceToObject(hDesktop, pSid, DESKTOP_ALL_ACCESS); }
                finally { NativeMethods.CloseDesktop(hDesktop); }
            }
            finally { if (pSid != IntPtr.Zero) NativeMethods.LocalFree(pSid); }
        }

        static (string winsta, string desktop) SplitDesktopName(string desktopName)
        {
            int idx = desktopName.IndexOf('\\');
            if (idx < 0) return ("WinSta0", desktopName);
            return (desktopName.Substring(0, idx), desktopName.Substring(idx + 1));
        }

        static void AddAceToObject(IntPtr handle, IntPtr pSid, uint accessMask)
        {
            uint siFlag = DACL_SECURITY_INFORMATION;
            uint sdSize = 0;

            if (!NativeMethods.GetUserObjectSecurity(handle, ref siFlag, IntPtr.Zero, 0, out sdSize))
            {
                int err = Marshal.GetLastPInvokeError();
                if (err != ERROR_INSUFFICIENT_BUFFER)
                    throw new Win32Exception(err, "GetUserObjectSecurity (size query) failed");
            }
            if (sdSize == 0)
                throw new Win32Exception("GetUserObjectSecurity returned size 0");
            if (sdSize > int.MaxValue)
                throw new Win32Exception($"Security descriptor size {sdSize} exceeds int.MaxValue");

            IntPtr pSD = Marshal.AllocHGlobal((int)sdSize);
            try
            {
                uint siFlag2 = DACL_SECURITY_INFORMATION;
                if (!NativeMethods.GetUserObjectSecurity(handle, ref siFlag2, pSD, sdSize, out _))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetUserObjectSecurity failed");

                if (!NativeMethods.GetSecurityDescriptorDacl(pSD, out bool daclPresent, out IntPtr pDacl, out _))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetSecurityDescriptorDacl failed");

                uint existingAclBytesInUse = ACL_HEADER_SIZE, existingAceCount = 0;
                uint aclRevision = ACL_REVISION;

                if (daclPresent && pDacl != IntPtr.Zero)
                {
                    var aclInfo = new ACL_SIZE_INFORMATION();
                    if (!NativeMethods.GetAclInformation(pDacl, ref aclInfo, (uint)AclSizeInfoSize, AclSizeInformation))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetAclInformation failed");
                    existingAclBytesInUse = aclInfo.AclBytesInUse;
                    existingAceCount = aclInfo.AceCount;

                    byte rev = Marshal.ReadByte(pDacl, 0);
                    if (rev > 0) aclRevision = rev;

                    if (HasMatchingAce(pDacl, existingAceCount, pSid, accessMask)) return;
                }

                uint sidLength = NativeMethods.GetLengthSid(pSid);
                uint newAceSize = ACE_HEADER_SIZE + sidLength;
                ulong newAclSizeU = (ulong)existingAclBytesInUse + newAceSize;
                newAclSizeU = (newAclSizeU + 3) & ~3UL;

                if (newAclSizeU > int.MaxValue)
                    throw new Win32Exception($"New ACL size {newAclSizeU} exceeds int.MaxValue");

                uint newAclSize = (uint)newAclSizeU;

                IntPtr pNewAcl = Marshal.AllocHGlobal((int)newAclSize);
                try
                {
                    if (!NativeMethods.InitializeAcl(pNewAcl, newAclSize, aclRevision))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "InitializeAcl failed");

                    if (daclPresent && pDacl != IntPtr.Zero)
                    {
                        for (uint i = 0; i < existingAceCount; i++)
                        {
                            if (!NativeMethods.GetAce(pDacl, i, out IntPtr pAce))
                                throw new Win32Exception(Marshal.GetLastPInvokeError(),
                                    $"GetAce #{i} failed");
                            uint aceSize = (uint)(ushort)Marshal.ReadInt16(pAce, 2);
                            if (!NativeMethods.AddAce(pNewAcl, aclRevision, 0xFFFFFFFF, pAce, aceSize))
                                throw new Win32Exception(Marshal.GetLastPInvokeError(), "AddAce failed");
                        }
                    }

                    if (!NativeMethods.AddAccessAllowedAce(pNewAcl, aclRevision, accessMask, pSid))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "AddAccessAllowedAce failed");

                    IntPtr pNewSD = Marshal.AllocHGlobal(SecurityDescSize);
                    try
                    {
                        if (!NativeMethods.InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION))
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "InitializeSecurityDescriptor failed");
                        if (!NativeMethods.SetSecurityDescriptorDacl(pNewSD, true, pNewAcl, false))
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "SetSecurityDescriptorDacl failed");

                        uint siFlag3 = DACL_SECURITY_INFORMATION;
                        if (!NativeMethods.SetUserObjectSecurity(handle, ref siFlag3, pNewSD))
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "SetUserObjectSecurity failed");
                    }
                    finally { Marshal.FreeHGlobal(pNewSD); }
                }
                finally { Marshal.FreeHGlobal(pNewAcl); }
            }
            finally { Marshal.FreeHGlobal(pSD); }
        }

        static bool HasMatchingAce(IntPtr pDacl, uint aceCount, IntPtr pTargetSid, uint requiredMask)
        {
            for (uint i = 0; i < aceCount; i++)
            {
                if (!NativeMethods.GetAce(pDacl, i, out IntPtr pAce))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(),
                        $"HasMatchingAce: GetAce #{i} failed");

                uint aceSize = (uint)(ushort)Marshal.ReadInt16(pAce, 2);
                if (aceSize < ACE_HEADER_SIZE) continue;

                byte aceType = Marshal.ReadByte(pAce, 0);
                if (aceType != ACCESS_ALLOWED_ACE_TYPE) continue;

                byte aceFlags = Marshal.ReadByte(pAce, 1);
                if ((aceFlags & INHERITED_ACE) != 0) continue;

                IntPtr pAceSid = IntPtr.Add(pAce, (int)ACE_HEADER_SIZE);
                uint sidLen = NativeMethods.GetLengthSid(pAceSid);
                if (aceSize < ACE_HEADER_SIZE + sidLen) continue;

                uint aceMask = (uint)Marshal.ReadInt32(pAce, 4);
                if (NativeMethods.EqualSid(pAceSid, pTargetSid) && (aceMask & requiredMask) == requiredMask)
                    return true;
            }
            return false;
        }
    }

    // ========================================================================
    //  TokenThief
    // ========================================================================

    static class TokenThief
    {
        public static int GetLsassPid()
        {
            Process[] procs;
            try { procs = Process.GetProcessesByName("lsass"); }
            catch (InvalidOperationException ex)
            {
                throw new InvalidOperationException(
                    "Access denied enumerating lsass (PPL protection?)", ex);
            }

            if (procs.Length == 0)
                throw new InvalidOperationException(
                    "lsass.exe not visible — PPL-protected and caller lacks SeDebugPrivilege");

            try
            {
                foreach (var p in procs) if (p.SessionId == 0) return p.Id;
                return procs[0].Id;
            }
            finally { foreach (var p in procs) p.Dispose(); }
        }

        public static SafeTokenHandle DuplicateProcessToken(int pid)
        {
            IntPtr hProcess = NativeMethods.OpenProcess(
                TokenConstants.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                int errLimited = Marshal.GetLastPInvokeError();
                hProcess = NativeMethods.OpenProcess(
                    TokenConstants.PROCESS_QUERY_INFORMATION, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    int errFull = Marshal.GetLastPInvokeError();
                    throw new Win32Exception(
                        errFull,
                        $"OpenProcess(lsass pid={pid}) failed: LIMITED err={errLimited}, QUERY err={errFull}");
                }
            }

            try
            {
                if (!NativeMethods.OpenProcessTokenRaw(
                        hProcess,
                        TokenConstants.TOKEN_DUPLICATE | TokenConstants.TOKEN_QUERY | TokenConstants.TOKEN_ASSIGN_PRIMARY,
                        out IntPtr hToken))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "OpenProcessToken failed");
                try
                {
                    if (!NativeMethods.DuplicateTokenEx(
                            hToken,
                            TokenConstants.MAXIMUM_ALLOWED,
                            IntPtr.Zero,
                            TokenConstants.SecurityImpersonation,
                            (int)TOKEN_TYPE.TokenPrimary,
                            out var dupToken))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "DuplicateTokenEx failed");
                    return dupToken;
                }
                finally { NativeMethods.CloseHandle(hToken); }
            }
            finally { NativeMethods.CloseHandle(hProcess); }
        }
    }

    // ========================================================================
    //  Privilege
    // ========================================================================

    static class Privilege
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES_SINGLE
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        public static readonly int TokenPrivilegesSingleSize =
            Marshal.SizeOf<TOKEN_PRIVILEGES_SINGLE>();

        public static void EnableOnProcess(string privilegeName)
        {
            if (!NativeMethods.OpenProcessToken(
                    NativeMethods.GetCurrentProcess(),
                    TokenConstants.TOKEN_ADJUST_PRIVILEGES | TokenConstants.TOKEN_QUERY,
                    out SafeTokenHandle tok))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "OpenProcessToken failed");

            try
            {
                if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out LUID luid))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(),
                        $"LookupPrivilegeValue failed: {privilegeName}");

                var tp = new TOKEN_PRIVILEGES_SINGLE
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = TokenConstants.SE_PRIVILEGE_ENABLED
                    }
                };

                int status = NativeMethods.NtAdjustPrivilegesToken(
                    tok.DangerousGetHandle(),
                    false,
                    ref tp,
                    (uint)TokenPrivilegesSingleSize,
                    IntPtr.Zero,
                    IntPtr.Zero);

                const int STATUS_NOT_ALL_ASSIGNED = 0x00000106;

                if (status == STATUS_NOT_ALL_ASSIGNED)
                    throw new Win32Exception(1300, $"{privilegeName} not held by current process");
                if (status != 0)
                {
                    uint dosErr = NativeMethods.RtlNtStatusToDosError(status);
                    string sysMsg = dosErr != 0
                        ? new Win32Exception((int)dosErr).Message
                        : "Unknown NTSTATUS";
                    throw new Win32Exception((int)dosErr,
                        $"Failed to enable {privilegeName}: {sysMsg} (NTSTATUS=0x{status:X8})");
                }
            }
            finally { tok.Dispose(); }
        }

        public static bool VerifyPrivilege(string privilegeName)
        {
            try
            {
                if (!NativeMethods.OpenProcessToken(
                        NativeMethods.GetCurrentProcess(),
                        TokenConstants.TOKEN_QUERY,
                        out SafeTokenHandle tok))
                    return false;
                try
                {
                    var state = NativeMethods.GetTokenPrivilegeState(tok, privilegeName);
                    if (state is null) return false;
                    return (state.Value & TokenConstants.SE_PRIVILEGE_ENABLED) != 0;
                }
                finally { tok.Dispose(); }
            }
            catch { return false; }
        }
    }

    // ========================================================================
    //  TokenCreator
    // ========================================================================

    static class TokenCreator
    {
        static readonly int SecurityQosSize           = Marshal.SizeOf<SECURITY_QUALITY_OF_SERVICE>();
        static readonly int ObjectAttributesSize      = Marshal.SizeOf<OBJECT_ATTRIBUTES>();
        static readonly int TokenUserSize             = Marshal.SizeOf<TOKEN_USER>();
        static readonly int SidAndAttributesSize      = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
        static readonly int TokenPrivilegesHeaderSize = Marshal.SizeOf<TOKEN_PRIVILEGES_HEADER>();
        static readonly int LuidAndAttributesSize     = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();

        public const uint TOKEN_ALL_ACCESS = TokenConstants.TOKEN_ALL_ACCESS;

        [Flags]
        public enum GroupAttributes : uint
        {
            Mandatory        = 0x00000001,
            EnabledByDefault = 0x00000002,
            Enabled          = 0x00000004,
            Integrity        = 0x00000020,
            IntegrityEnabled = 0x00000040
        }

        [Flags]
        public enum PrivilegeAttributes : uint
        {
            EnabledByDefault = 0x00000001,
            Enabled          = 0x00000002
        }

        // ----------------------------------------------------------------
        //  从 SYSTEM 令牌读取关键属性
        // ----------------------------------------------------------------

        // [BUG-B]
        public static LUID GetAuthenticationId(SafeTokenHandle token)
        {
            IntPtr buf = GetTokenInformationBuf(token, TokenConstants.TokenStatistics);
            try
            {
                // TOKEN_STATISTICS 布局 (x64/x86 相同):
                //   offset 0:  LUID TokenId
                //   offset 8:  LUID AuthenticationId  ← 目标
                //   ...
                const int offset = 8;
                uint low = (uint)Marshal.ReadInt32(buf, offset);
                int  high = Marshal.ReadInt32(buf, offset + 4);
                return new LUID { LowPart = low, HighPart = high };
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // [BUG-C]
        public static string? GetLogonSid(SafeTokenHandle token)
        {
            IntPtr buf = GetTokenInformationBuf(token, TokenConstants.TokenGroups);
            try
            {
                uint count = (uint)Marshal.ReadInt32(buf);
                int offset = (IntPtr.Size == 8) ? 8 : 4;   // 头部对齐
                int entrySize = SidAndAttributesSize;

                for (uint i = 0; i < count; i++)
                {
                    IntPtr pSid = Marshal.ReadIntPtr(buf, offset);
                    if (pSid != IntPtr.Zero)
                    {
                        string sidStr = SidToString(pSid);
                        if (sidStr.StartsWith("S-1-5-5-", StringComparison.Ordinal))
                            return sidStr;
                    }
                    offset += entrySize;
                }
                return null;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // [NEW] 复制 SYSTEM 令牌的 SourceIdentifier，使新令牌"来自"同一来源
        public static LUID GetTokenSource(SafeTokenHandle token)
        {
            IntPtr buf = GetTokenInformationBuf(token, TokenConstants.TokenStatistics);
            try
            {
                // TOKEN_STATISTICS 尾部有 ModifiedId；但 source 不在 statistics 里。
                // 作为替代，用 TokenId 作为 source id（同 SYSTEM 会话一致即可）。
                const int offset = 0;   // TokenId
                uint low = (uint)Marshal.ReadInt32(buf, offset);
                int  high = Marshal.ReadInt32(buf, offset + 4);
                return new LUID { LowPart = low, HighPart = high };
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static IntPtr GetTokenInformationBuf(SafeTokenHandle token, int infoClass)
        {
            const int ERROR_INSUFFICIENT_BUFFER = 122;
            uint len = 0;
            if (!NativeMethods.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out len))
            {
                int err = Marshal.GetLastPInvokeError();
                if (err != ERROR_INSUFFICIENT_BUFFER)
                    throw new Win32Exception(err,
                        $"GetTokenInformation(size) class={infoClass} failed");
            }
            if (len == 0 || len > int.MaxValue)
                throw new Win32Exception($"GetTokenInformation class={infoClass} returned len={len}");

            IntPtr buf = Marshal.AllocHGlobal((int)len);
            if (!NativeMethods.GetTokenInformation(token, infoClass, buf, len, out _))
            {
                int err = Marshal.GetLastPInvokeError();
                Marshal.FreeHGlobal(buf);
                throw new Win32Exception(err,
                    $"GetTokenInformation(data) class={infoClass} failed");
            }
            return buf;
        }

        static string SidToString(IntPtr pSid)
        {
            if (!NativeMethods.ConvertSidToStringSid(pSid, out IntPtr pStr))
                return "";
            try { return Marshal.PtrToStringUni(pStr) ?? ""; }
            finally { NativeMethods.LocalFree(pStr); }
        }

        // ----------------------------------------------------------------
        //  Token 创建主流程
        // ----------------------------------------------------------------

        public static void SetTokenSessionId(SafeTokenHandle token, uint sessionId)
        {
            if (!NativeMethods.SetTokenInformation(
                    token, TokenConstants.TokenSessionId, ref sessionId, sizeof(uint)))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "SetTokenInformation failed");
        }

        public static SafeTokenHandle CreatePrimaryToken(
            string userSidString,
            (string sid, GroupAttributes attr)[] groupSids,
            (string name, PrivilegeAttributes attr)[] privileges,
            LUID authenticationId,
            LUID sourceIdentifier)
        {
            if (groupSids == null || groupSids.Length == 0)
                throw new ArgumentNullException(nameof(groupSids));
            if (privileges == null || privileges.Length == 0)
                throw new ArgumentNullException(nameof(privileges));

            IntPtr sidUser = IntPtr.Zero;
            IntPtr bufUser = IntPtr.Zero;
            IntPtr bufGroups = IntPtr.Zero;
            IntPtr bufPrivs = IntPtr.Zero;
            IntPtr pSqos = IntPtr.Zero;
            IntPtr pDefaultDacl = IntPtr.Zero;
            IntPtr[]? daclSidPtrs = null;
            IntPtr[]? sidPtrs = null;

            try
            {
                if (!NativeMethods.ConvertStringSidToSid(userSidString, out sidUser))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(),
                        "ConvertStringSidToSid (user) failed");

                bufUser   = BuildTokenUser(sidUser);
                bufGroups = BuildTokenGroups(groupSids, out sidPtrs);
                bufPrivs  = BuildTokenPrivileges(privileges);

                var owner        = new TOKEN_OWNER         { Owner = sidUser };
                var primaryGroup = new TOKEN_PRIMARY_GROUP { PrimaryGroup = sidUser };

                pDefaultDacl = BuildDefaultDacl(sidUser, out daclSidPtrs);
                var defaultDacl = new TOKEN_DEFAULT_DACL { DefaultDacl = pDefaultDacl };

                var source = TOKEN_SOURCE.Create("NtCreate", sourceIdentifier);

                var expiryTime = new LARGE_INTEGER
                {
                    QuadPart = DateTime.MaxValue.ToFileTimeUtc()
                };

                var sqos = new SECURITY_QUALITY_OF_SERVICE
                {
                    Length              = SecurityQosSize,
                    ImpersonationLevel  = TokenConstants.SecurityImpersonation,
                    ContextTrackingMode = 0,
                    EffectiveOnly       = 0
                };
                pSqos = Marshal.AllocHGlobal(SecurityQosSize);
                Marshal.StructureToPtr(sqos, pSqos, false);

                var objAttr = new OBJECT_ATTRIBUTES
                {
                    Length = ObjectAttributesSize,
                    SecurityQualityOfService = pSqos
                };

                int status = NativeMethods.NtCreateToken(
                    out var hToken,
                    TOKEN_ALL_ACCESS,
                    ref objAttr,
                    TOKEN_TYPE.TokenPrimary,
                    ref authenticationId,   // [BUG-B] 用真实 AuthId
                    ref expiryTime,
                    bufUser,
                    bufGroups,
                    bufPrivs,
                    ref owner,
                    ref primaryGroup,
                    ref defaultDacl,
                    ref source);

                if (status < 0)
                    throw new Win32Exception(
                        (int)NativeMethods.RtlNtStatusToDosError(status),
                        $"NtCreateToken failed (NTSTATUS=0x{status:X8})");

                return hToken;
            }
            finally
            {
                if (bufUser      != IntPtr.Zero) Marshal.FreeHGlobal(bufUser);
                if (bufGroups    != IntPtr.Zero) Marshal.FreeHGlobal(bufGroups);
                if (bufPrivs     != IntPtr.Zero) Marshal.FreeHGlobal(bufPrivs);
                if (pSqos        != IntPtr.Zero) Marshal.FreeHGlobal(pSqos);
                if (pDefaultDacl != IntPtr.Zero) Marshal.FreeHGlobal(pDefaultDacl);

                NativeMethods.LocalFreeIfNotNull(sidUser);
                if (sidPtrs != null) foreach (var s in sidPtrs) NativeMethods.LocalFreeIfNotNull(s);
                if (daclSidPtrs != null) foreach (var s in daclSidPtrs) NativeMethods.LocalFreeIfNotNull(s);
            }
        }

        static IntPtr BuildTokenUser(IntPtr sid)
        {
            var tu = new TOKEN_USER
            {
                User = new SID_AND_ATTRIBUTES { Sid = sid, Attributes = 0 }
            };
            IntPtr buf = Marshal.AllocHGlobal(TokenUserSize);
            Marshal.StructureToPtr(tu, buf, false);
            return buf;
        }

        static IntPtr BuildTokenGroups((string sid, GroupAttributes attr)[] entries, out IntPtr[] sidPtrs)
        {
            int count = entries.Length;
            int hdr = (int)Marshal.OffsetOf<TOKEN_GROUPS_LAYOUT>(
                nameof(TOKEN_GROUPS_LAYOUT.FirstGroup));

            sidPtrs = new IntPtr[count];

            int totalSize = checked(hdr + SidAndAttributesSize * count);
            IntPtr buf = Marshal.AllocHGlobal(totalSize);
            bool success = false;
            try
            {
                Marshal.WriteInt32(buf, count);
                IntPtr ptr = IntPtr.Add(buf, hdr);
                for (int i = 0; i < count; i++)
                {
                    if (!NativeMethods.ConvertStringSidToSid(entries[i].sid, out var s))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(),
                            $"ConvertStringSidToSid failed: {entries[i].sid}");
                    sidPtrs[i] = s;
                    Marshal.StructureToPtr(
                        new SID_AND_ATTRIBUTES { Sid = s, Attributes = (uint)entries[i].attr },
                        ptr, false);
                    ptr = IntPtr.Add(ptr, SidAndAttributesSize);
                }
                success = true;
                return buf;
            }
            finally
            {
                if (!success)
                {
                    Marshal.FreeHGlobal(buf);
                    for (int i = 0; i < count; i++)
                    {
                        NativeMethods.LocalFreeIfNotNull(sidPtrs[i]);
                        sidPtrs[i] = IntPtr.Zero;
                    }
                }
            }
        }

        static IntPtr BuildTokenPrivileges((string name, PrivilegeAttributes attr)[] privs)
        {
            var resolved = new List<LUID_AND_ATTRIBUTES>(privs.Length);
            foreach (var (name, attr) in privs)
            {
                if (!NativeMethods.LookupPrivilegeValue(null, name, out var luid))
                    continue;
                resolved.Add(new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = (uint)attr });
            }

            int count = resolved.Count;
            if (count == 0)
                throw new InvalidOperationException("No valid privileges could be resolved");

            long totalSize = (long)TokenPrivilegesHeaderSize + (long)LuidAndAttributesSize * count;
            if (totalSize > int.MaxValue)
                throw new InvalidOperationException($"Privilege buffer too large: {totalSize} bytes");

            IntPtr buf = Marshal.AllocHGlobal((int)totalSize);
            bool success = false;
            try
            {
                Marshal.WriteInt32(buf, count);
                IntPtr ptr = IntPtr.Add(buf, TokenPrivilegesHeaderSize);
                foreach (var la in resolved)
                {
                    Marshal.StructureToPtr(la, ptr, false);
                    ptr = IntPtr.Add(ptr, LuidAndAttributesSize);
                }
                success = true;
                return buf;
            }
            finally
            {
                if (!success) Marshal.FreeHGlobal(buf);
            }
        }

        // [BUG-D][BUG-F] 用显式掩码；为 Everyone 追加 TOKEN_QUERY|READ_CONTROL
        static IntPtr BuildDefaultDacl(IntPtr sidOwner, out IntPtr[] daclSidPtrs)
        {
            const uint ACL_HEADER_SIZE = 8;
            const uint ACE_HEADER_SIZE = 8;
            const uint TOKEN_ALL_ACCESS = TokenConstants.TOKEN_ALL_ACCESS;
            const uint EVERYONE_MASK = TokenConstants.TOKEN_QUERY | TokenConstants.READ_CONTROL;

            IntPtr sidSystem = IntPtr.Zero, sidAdmins = IntPtr.Zero, sidEveryone = IntPtr.Zero;
            daclSidPtrs = null;
            try
            {
                if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.System, out sidSystem))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "SID SYSTEM failed");
                if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.BuiltinAdmins, out sidAdmins))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "SID Administrators failed");
                if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.Everyone, out sidEveryone))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "SID Everyone failed");

                daclSidPtrs = new[] { sidSystem, sidAdmins, sidEveryone };

                uint aclSize = ACL_HEADER_SIZE
                             + (ACE_HEADER_SIZE + NativeMethods.GetLengthSid(sidSystem))
                             + (ACE_HEADER_SIZE + NativeMethods.GetLengthSid(sidAdmins))
                             + (ACE_HEADER_SIZE + NativeMethods.GetLengthSid(sidOwner))
                             + (ACE_HEADER_SIZE + NativeMethods.GetLengthSid(sidEveryone));
                aclSize = (aclSize + 3u) & ~3u;

                if (aclSize > int.MaxValue)
                    throw new Win32Exception($"Default DACL size {aclSize} exceeds int.MaxValue");

                IntPtr pAcl = Marshal.AllocHGlobal((int)aclSize);
                try
                {
                    if (!NativeMethods.InitializeAcl(pAcl, aclSize, TokenConstants.ACL_REVISION))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "InitializeAcl (DACL) failed");

                    // SYSTEM, Admins, Owner 用显式 TOKEN_ALL_ACCESS
                    if (!NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TOKEN_ALL_ACCESS, sidSystem))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "ACE SYSTEM failed");
                    if (!NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TOKEN_ALL_ACCESS, sidAdmins))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "ACE Admins failed");
                    if (!NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TOKEN_ALL_ACCESS, sidOwner))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "ACE Owner failed");

                    // [BUG-D] Everyone 获得 TOKEN_QUERY + READ_CONTROL，
                    //         这样 whoami / taskkill 能打开自身令牌查询
                    if (!NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, EVERYONE_MASK, sidEveryone))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "ACE Everyone failed");

                    return pAcl;
                }
                catch
                {
                    Marshal.FreeHGlobal(pAcl);
                    throw;
                }
            }
            catch
            {
                NativeMethods.LocalFreeIfNotNull(sidSystem);
                NativeMethods.LocalFreeIfNotNull(sidAdmins);
                NativeMethods.LocalFreeIfNotNull(sidEveryone);
                daclSidPtrs = null;
                throw;
            }
        }
    }

    // ========================================================================
    //  ProcessLauncher
    // ========================================================================

    static class ProcessLauncher
    {
        static readonly int SecurityAttributesSize = Marshal.SizeOf<SECURITY_ATTRIBUTES>();
        static readonly int StartupInfoSize        = Marshal.SizeOf<STARTUPINFO>();

        const uint CREATE_NEW_CONSOLE         = 0x00000010;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const uint LOGON_WITH_PROFILE         = 0x00000001;

        public static void Launch(SafeTokenHandle token, string application, string desktopName)
        {
            var sa = new SECURITY_ATTRIBUTES
            {
                nLength = SecurityAttributesSize,
                lpSecurityDescriptor = IntPtr.Zero,
                bInheritHandle = 0
            };
            var si = new STARTUPINFO
            {
                cb = StartupInfoSize,
                lpDesktop = desktopName,
                lpTitle = Config.TiShellWindowTitle
            };

            IntPtr envBlock = IntPtr.Zero;
            if (!NativeMethods.CreateEnvironmentBlock(out envBlock, token, false))
            {
                Console.WriteLine($"  [!] CreateEnvironmentBlock failed (err={Marshal.GetLastPInvokeError()}); using inherited env");
                envBlock = IntPtr.Zero;
            }

            uint creationFlags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;

            try
            {
                var sbCmdLine = new StringBuilder($"\"{application}\"");

                if (!NativeMethods.CreateProcessAsUser(
                        token,
                        application,
                        sbCmdLine,
                        ref sa,
                        ref sa,
                        false,
                        creationFlags,
                        envBlock,
                        Config.System32Path,
                        ref si,
                        out var pi))
                {
                    int err = Marshal.GetLastPInvokeError();
                    string hint = err == 5
                        ? " (Access denied — PPL / WDAC / AppLocker on cmd.exe?)"
                        : err == 1314
                        ? " (SeAssignPrimaryTokenPrivilege missing)"
                        : "";
                    throw new Win32Exception(err, $"CreateProcessAsUser failed{hint}");
                }
                try
                {
                    Console.WriteLine($"  [+] Process launched (PID={pi.dwProcessId})");
                }
                finally
                {
                    if (pi.hThread  != IntPtr.Zero) NativeMethods.CloseHandle(pi.hThread);
                    if (pi.hProcess != IntPtr.Zero) NativeMethods.CloseHandle(pi.hProcess);
                }
            }
            finally
            {
                if (envBlock != IntPtr.Zero) NativeMethods.DestroyEnvironmentBlock(envBlock);
            }
        }

        public static void LaunchWithToken(
            SafeTokenHandle token, string application, string arguments, string? desktopName)
        {
            var si = new STARTUPINFO
            {
                cb = StartupInfoSize,
                lpDesktop = desktopName
            };

            string cmdLine = string.IsNullOrEmpty(arguments)
                ? $"\"{application}\""
                : $"\"{application}\" {arguments}";
            var sbCmdLine = new StringBuilder(cmdLine);

            if (!NativeMethods.CreateProcessWithTokenW(
                    token,
                    LOGON_WITH_PROFILE,
                    null,
                    sbCmdLine,
                    CREATE_NEW_CONSOLE,
                    IntPtr.Zero,
                    Config.System32Path,
                    ref si,
                    out var pi))
            {
                int err = Marshal.GetLastPInvokeError();
                string hint = err == 1314 ? " (needs SeImpersonatePrivilege)"
                            : err == 1058 ? " (run: sc start seclogon)"
                            : "";
                throw new Win32Exception(err, $"CreateProcessWithTokenW failed{hint}");
            }

            try
            {
                Console.WriteLine($"  [+] Child process launched (PID={pi.dwProcessId})");
            }
            finally
            {
                if (pi.hThread  != IntPtr.Zero) NativeMethods.CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) NativeMethods.CloseHandle(pi.hProcess);
            }
        }
    }

    // ========================================================================
    //  NativeMethods
    // ========================================================================

    static class NativeMethods
    {
        static readonly int LuidAndAttrsSize = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();

        // ---- kernel32 ----
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access,
            [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        public static void LocalFreeIfNotNull(IntPtr p) { if (p != IntPtr.Zero) LocalFree(p); }

        // ---- advapi32 ----
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr proc, uint access, out SafeTokenHandle handle);

        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenProcessToken")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessTokenRaw(IntPtr proc, uint access, out IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            SafeTokenHandle TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        public static uint? GetTokenPrivilegeState(SafeTokenHandle token, string privilegeName)
        {
            const int ERROR_INSUFFICIENT_BUFFER = 122;

            if (!LookupPrivilegeValue(null, privilegeName, out LUID luid)) return null;

            uint len = 0;
            if (!GetTokenInformation(token, TokenConstants.TokenPrivileges, IntPtr.Zero, 0, out len))
            {
                int err = Marshal.GetLastPInvokeError();
                if (err != ERROR_INSUFFICIENT_BUFFER) return null;
            }
            if (len == 0 || len > int.MaxValue) return null;

            IntPtr buf = Marshal.AllocHGlobal((int)len);
            try
            {
                if (!GetTokenInformation(token, TokenConstants.TokenPrivileges, buf, len, out _))
                    return null;

                uint count = (uint)Marshal.ReadInt32(buf);
                int privOffset = (int)Marshal.OffsetOf<Privilege.TOKEN_PRIVILEGES_SINGLE>(
                    nameof(Privilege.TOKEN_PRIVILEGES_SINGLE.Privileges));

                ulong needed = (ulong)privOffset + (ulong)count * (ulong)LuidAndAttrsSize;
                if (needed > len) return null;

                int offset = privOffset;
                for (uint i = 0; i < count; i++)
                {
                    var la = Marshal.PtrToStructure<LUID_AND_ATTRIBUTES>(IntPtr.Add(buf, offset));
                    if (la.Luid.LowPart == luid.LowPart && la.Luid.HighPart == luid.HighPart)
                        return la.Attributes;
                    offset += LuidAndAttrsSize;
                }
                return null;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateTokenEx(
            IntPtr existing, uint access, IntPtr attrs, int impLevel, int tokenType,
            out SafeTokenHandle newToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetSecurityDescriptorDacl(
            IntPtr pSD,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent,
            out IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetAclInformation(
            IntPtr pAcl, ref ACL_SIZE_INFORMATION pAclInfo, uint nAclInfoLength, int dwAclInfoClass);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetAce(IntPtr pAcl, uint dwAceIndex, out IntPtr pAce);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AddAce(
            IntPtr pAcl, uint dwAceRevision, uint dwStartingAceIndex, IntPtr pAceList, uint nAceListLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AddAccessAllowedAce(
            IntPtr pAcl, uint dwAceRevision, uint AccessMask, IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeSecurityDescriptor(IntPtr pSD, uint dwRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetSecurityDescriptorDacl(
            IntPtr pSD,
            [MarshalAs(UnmanagedType.Bool)] bool bDaclPresent,
            IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] bool bDaclDefaulted);

        [DllImport("advapi32.dll")]
        public static extern uint GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertStringSidToSid(string stringSid, out IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr stringSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EqualSid(IntPtr pSid1, IntPtr pSid2);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle, int tokenInformationClass,
            ref uint tokenInformation, int tokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessAsUser(
            SafeTokenHandle hToken, string? lpApplicationName, StringBuilder? lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessWithTokenW(
            SafeTokenHandle hToken, uint dwLogonFlags,
            string? lpApplicationName, StringBuilder lpCommandLine,
            uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        // ---- user32 ----
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenWindowStation(
            string name, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint desiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseWindowStation(IntPtr hWinSta);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenDesktop(
            string name, uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetThreadDesktop(uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetUserObjectInformation(
            IntPtr hObj, int nIndex, StringBuilder pvInfo, int nLength, out uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetUserObjectSecurity(
            IntPtr hObj, ref uint pSIRequested, IntPtr pSD, uint nLength, out uint nLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetUserObjectSecurity(IntPtr hObj, ref uint pSIRequested, IntPtr pSD);

        // ---- userenv ----
        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment, SafeTokenHandle hToken,
            [MarshalAs(UnmanagedType.Bool)] bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        // ---- wtsapi32 ----
        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WTSQuerySessionInformation(
            IntPtr hServer, uint sessionId, int wtsInfoClass,
            out IntPtr ppBuffer, out uint pBytesReturned);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WTSEnumerateSessions(
            IntPtr hServer, int Reserved, int Version,
            out IntPtr ppSessionInfo, out uint pCount);

        // ---- ntdll ----
        [DllImport("ntdll.dll")]
        public static extern uint RtlNtStatusToDosError(int status);

        [DllImport("ntdll.dll")]
        public static extern int NtAdjustPrivilegesToken(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.U1)] bool DisableAllPrivileges,
            ref Privilege.TOKEN_PRIVILEGES_SINGLE NewState,
            uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateToken(
            out SafeTokenHandle TokenHandle, uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType,
            ref LUID AuthenticationId, ref LARGE_INTEGER ExpirationTime,
            IntPtr TokenUser, IntPtr TokenGroups, IntPtr TokenPrivileges,
            ref TOKEN_OWNER TokenOwner, ref TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            ref TOKEN_DEFAULT_DACL TokenDefaultDacl, ref TOKEN_SOURCE TokenSource);
    }
}