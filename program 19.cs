// ============================================================================
//  Program.cs — NtCreateTokenFull v23 (Win11 LSA Integration & Bug-Fixed)
//
//  在 v22 基础上完成以下优化/修正，其他主流程逻辑保持不变：
//   1-18. (v22 的修复)
//   19. [新增] Windows 版本检测 (Win11+ vs Win10)
//   20. [新增] Win11+ 自动检测 LSA 特权授权状态
//   21. [新增] Win11+ 未授权时自动通过 LSA 授予所有特权并提示重启
//   22. [新增] Win11+ 已授权时直接运行 Phase 2，跳过 Phase 1
//   23. [修复] NtCreateToken 中 TokenUser 未正确封送的严重 bug (改为 ref 传递)
//   24. [修复] CreateTokenPrivilegesBuffer 中特权计数不正确的 bug
//   25. [修复] LSA 字符串和 SID 内存管理精确释放
// ============================================================================
#nullable enable

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
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
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

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
        public const byte ACCESS_ALLOWED_ACE_TYPE       = 0x00;
        public const byte INHERITED_ACE                 = 0x10;

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
        public static readonly string System32Path =
            Environment.GetFolderPath(Environment.SpecialFolder.System);

        public static readonly string CmdPath =
            Path.Combine(System32Path, "cmd.exe");

        public const string DefaultDesktop       = @"WinSta0\Default";
        public const string WinlogonDesktop      = @"WinSta0\Winlogon";
        public const string TiShellWindowTitle   = "TrustedInstaller Shell";
    }

    // ========================================================================
    //  SHARED STRUCTS
    // ========================================================================
    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES_HEADER
    {
        public uint PrivilegeCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LARGE_INTEGER
    {
        public long QuadPart;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct TOKEN_SOURCE
    {
        public const int MaxNameLength = 8;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxNameLength)]
        public string? SourceName;
        public LUID SourceIdentifier;

        public static TOKEN_SOURCE Create(string name, LUID id)
        {
            if (name is null) throw new ArgumentNullException(nameof(name));
            if (name.Length > MaxNameLength)
                throw new ArgumentException($"Token source name cannot exceed {MaxNameLength} ASCII characters: '{name}'", nameof(name));

            foreach (char ch in name)
            {
                if (ch > 127) throw new ArgumentException($"Token source name must be ASCII-only: '{name}'", nameof(name));
            }

            return new TOKEN_SOURCE { SourceName = name.PadRight(MaxNameLength, '\0'), SourceIdentifier = id };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ACL_SIZE_INFORMATION
    {
        public int AceCount;
        public int AclBytesInUse;
        public int AclBytesFree;
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
    struct SECURITY_DESCRIPTOR
    {
        public byte Revision;
        public byte Sbz1;
        public ushort Control;
        public IntPtr Owner;
        public IntPtr Group;
        public IntPtr Sacl;
        public IntPtr Dacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public WTSCONNECTSTATECLASS State;
    }

    enum WTSCONNECTSTATECLASS
    {
        WTSActive = 0,
        WTSConnected = 1,
        WTSConnectQuery = 2,
        WTSShadow = 3,
        WTSDisconnected = 4,
        WTSIdle = 5,
        WTSListen = 6,
        WTSReset = 7,
        WTSDown = 8,
        WTSInit = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_OWNER
    {
        public IntPtr Owner;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIMARY_GROUP
    {
        public IntPtr PrimaryGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_DEFAULT_DACL
    {
        public IntPtr DefaultDacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_GROUPS_LAYOUT
    {
        public int GroupCount;
        public SID_AND_ATTRIBUTES FirstGroup;
    }

    enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
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
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RTL_OSVERSIONINFOW
    {
        public uint dwOSVersionInfoSize;
        public uint dwMajorVersion;
        public uint dwMinorVersion;
        public uint dwBuildNumber;
        public uint dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string? szCSDVersion;
    }

    // ========================================================================
    //  INTEROP UTILITY
    // ========================================================================
    static class InteropUtility
    {
        public static int LastError => Marshal.GetLastWin32Error();

        public static Win32Exception NewError(string message)
            => new Win32Exception(Marshal.GetLastWin32Error(), message);

        public static Win32Exception NewError(int errorCode, string message)
            => new Win32Exception(errorCode, message);

        public static void FreeHGlobalIfNotNull(IntPtr p)
        {
            if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
        }

        public static void LocalFreeIfNotNull(IntPtr p)
        {
            if (p != IntPtr.Zero) NativeMethods.LocalFree(p);
        }

        public static void FreeLocalAll(IntPtr[]? ptrs)
        {
            if (ptrs is null) return;
            for (int i = 0; i < ptrs.Length; i++) LocalFreeIfNotNull(ptrs[i]);
        }

        public static uint Align4(uint value) => (value + 3u) & ~3u;
        public static ulong Align4(ulong value) => (value + 3ul) & ~3ul;

        public static LUID ReadLuid(IntPtr buffer, int offset)
        {
            uint low = (uint)Marshal.ReadInt32(buffer, offset);
            int high = Marshal.ReadInt32(buffer, offset + 4);
            return new LUID { LowPart = low, HighPart = high };
        }

        public static string? NormalizeDesktop(string? desktopName)
            => string.IsNullOrWhiteSpace(desktopName) ? null : desktopName.Trim();

        public static string Quote(string? value)
        {
            if (string.IsNullOrEmpty(value)) return "\"\"";
            var sb = new StringBuilder(value!.Length + 2);
            sb.Append('"');
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (c == '\\' || c == '"') sb.Append('\\');
                sb.Append(c);
            }
            sb.Append('"');
            return sb.ToString();
        }
    }

    // ========================================================================
    //  LAYOUT ASSERTIONS
    // ========================================================================
    static class LayoutAssertions
    {
        static bool s_verified;

        public static void Verify()
        {
            if (s_verified) return;
            lock (typeof(LayoutAssertions))
            {
                if (s_verified) return;
                bool is64 = IntPtr.Size == 8;

                AssertSize<LUID>("LUID", 8);
                AssertSize<LUID_AND_ATTRIBUTES>("LUID_AND_ATTRIBUTES", 12);
                AssertSize<TOKEN_PRIVILEGES_HEADER>("TOKEN_PRIVILEGES_HEADER", 4);
                AssertSize<Privilege.TOKEN_PRIVILEGES_SINGLE>("TOKEN_PRIVILEGES_SINGLE", 16);
                AssertSize<TOKEN_SOURCE>("TOKEN_SOURCE", 16);
                AssertSize<ACL_SIZE_INFORMATION>("ACL_SIZE_INFORMATION", 12);
                AssertSize<SECURITY_QUALITY_OF_SERVICE>("SECURITY_QUALITY_OF_SERVICE", 12);

                AssertOffset<TOKEN_SOURCE>("TOKEN_SOURCE", nameof(TOKEN_SOURCE.SourceIdentifier), 8);
                AssertOffset<LUID_AND_ATTRIBUTES>("LUID_AND_ATTRIBUTES", nameof(LUID_AND_ATTRIBUTES.Attributes), 8);
                AssertOffset<SID_AND_ATTRIBUTES>("SID_AND_ATTRIBUTES", nameof(SID_AND_ATTRIBUTES.Attributes), IntPtr.Size);
                AssertOffset<Privilege.TOKEN_PRIVILEGES_SINGLE>("TOKEN_PRIVILEGES_SINGLE", nameof(Privilege.TOKEN_PRIVILEGES_SINGLE.Privileges), 4);

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

                    AssertOffset<TOKEN_GROUPS_LAYOUT>("TOKEN_GROUPS_LAYOUT", nameof(TOKEN_GROUPS_LAYOUT.FirstGroup), 8);
                    AssertOffset<OBJECT_ATTRIBUTES>("OBJECT_ATTRIBUTES", nameof(OBJECT_ATTRIBUTES.SecurityQualityOfService), 40);
                }
                else
                {
                    AssertSize<OBJECT_ATTRIBUTES>("OBJECT_ATTRIBUTES", 24);
                    AssertSize<SECURITY_DESCRIPTOR>("SECURITY_DESCRIPTOR", 20);
                    AssertSize<SID_AND_ATTRIBUTES>("SID_AND_ATTRIBUTES", 8);
                    AssertSize<SECURITY_ATTRIBUTES>("SECURITY_ATTRIBUTES", 12);
                    AssertSize<PROCESS_INFORMATION>("PROCESS_INFORMATION", 16);
                    AssertSize<WTS_SESSION_INFO>("WTS_SESSION_INFO", 12);
                    AssertSize<TOKEN_USER>("TOKEN_USER", 8);
                    AssertSize<TOKEN_OWNER>("TOKEN_OWNER", 4);
                    AssertSize<TOKEN_PRIMARY_GROUP>("TOKEN_PRIMARY_GROUP", 4);
                    AssertSize<TOKEN_DEFAULT_DACL>("TOKEN_DEFAULT_DACL", 4);

                    AssertOffset<TOKEN_GROUPS_LAYOUT>("TOKEN_GROUPS_LAYOUT", nameof(TOKEN_GROUPS_LAYOUT.FirstGroup), 4);
                    AssertOffset<OBJECT_ATTRIBUTES>("OBJECT_ATTRIBUTES", nameof(OBJECT_ATTRIBUTES.SecurityQualityOfService), 20);
                }
                s_verified = true;
            }
        }

        static void AssertSize<T>(string name, int expected) where T : struct
        {
            int actual = Marshal.SizeOf<T>();
            if (actual != expected)
                throw new InvalidOperationException($"Layout mismatch: {name} size = {actual}, expected {expected}");
        }

        static void AssertOffset<T>(string typeName, string field, int expected) where T : struct
        {
            int actual = (int)Marshal.OffsetOf<T>(field);
            if (actual != expected)
                throw new InvalidOperationException($"Layout mismatch: {typeName}.{field} offset = {actual}, expected {expected}");
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
        const int WTSConnectState = 8;

        public static bool IsUserLoggedOn(uint sessionId)
        {
            IntPtr pBuf = IntPtr.Zero;
            try
            {
                if (!NativeMethods.WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTSUserName, out pBuf, out uint bytes))
                    return false;

                if (pBuf == IntPtr.Zero || bytes == 0) return false;
                string? user = Marshal.PtrToStringUni(pBuf);
                return !string.IsNullOrWhiteSpace(user);
            }
            finally
            {
                if (pBuf != IntPtr.Zero) NativeMethods.WTSFreeMemory(pBuf);
            }
        }

        public static uint? FindActiveUserSession()
        {
            IntPtr pSessions = IntPtr.Zero;
            uint? firstConnected = null;
            try
            {
                if (!NativeMethods.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out pSessions, out uint count))
                    return null;

                uint structSize = (uint)Marshal.SizeOf<WTS_SESSION_INFO>();
                uint offset = 0;

                for (uint i = 0; i < count; i++)
                {
                    if (offset > int.MaxValue) break;
                    IntPtr pItem = IntPtr.Add(pSessions, (int)offset);
                    var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(pItem);

                    if (si.SessionId == 0) continue;
                    if (!IsUserLoggedOn((uint)si.SessionId)) continue;

                    if (si.State == WTSCONNECTSTATECLASS.WTSActive) return (uint)si.SessionId;
                    if (si.State == WTSCONNECTSTATECLASS.WTSConnected && firstConnected == null)
                        firstConnected = (uint)si.SessionId;

                    offset += structSize;
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
            IntPtr h = NativeMethods.OpenWindowStation("WinSta0", false, TokenConstants.WINSTA_ENUMDESKTOPS);
            if (h == IntPtr.Zero) return false;
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
            "SeAssignPrimaryTokenPrivilege",
            "SeAuditPrivilege",
            "SeBackupPrivilege",
            "SeChangeNotifyPrivilege",
            "SeCreateGlobalPrivilege",
            "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege",
            "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege",
            "SeDebugPrivilege",
            "SeDelegateSessionUserImpersonatePrivilege",
            "SeEnableDelegationPrivilege",
            "SeImpersonatePrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege",
            "SeMachineAccountPrivilege",
            "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeRelabelPrivilege",
            "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege",
            "SeSecurityPrivilege",
            "SeShutdownPrivilege",
            "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeSystemProfilePrivilege",
            "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeTcbPrivilege",
            "SeTimeZonePrivilege",
            "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege"
        };

        public static bool IsWindows11OrHigher()
        {
            var osvi = new RTL_OSVERSIONINFOW { dwOSVersionInfoSize = (uint)Marshal.SizeOf<RTL_OSVERSIONINFOW>() };
            if (NativeMethods.RtlGetVersion(out osvi) == 0)
            {
                return osvi.dwMajorVersion > 10 || 
                       (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 22000);
            }
            return false;
        }

        public static bool AreRequiredPrivilegesGranted()
        {
            IntPtr policyHandle = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            IntPtr rightsPtr = IntPtr.Zero;

            try
            {
                var loa = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
                uint status = NativeMethods.LsaOpenPolicy(IntPtr.Zero, ref loa, LsaConstants.POLICY_ALL_ACCESS, out policyHandle);
                if (status != LsaConstants.STATUS_SUCCESS) return false;

                sid = GetBuiltinAdministratorsSid();
                
                IntPtr tempRightsPtr;
                uint rightsCount;
                status = NativeMethods.LsaEnumerateAccountRights(policyHandle, sid, out tempRightsPtr, out rightsCount);

                HashSet<string> existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (status == LsaConstants.STATUS_SUCCESS)
                {
                    rightsPtr = tempRightsPtr;
                    if (rightsPtr != IntPtr.Zero && rightsCount > 0)
                    {
                        int lusSize = Marshal.SizeOf<LSA_UNICODE_STRING>();
                        for (uint i = 0; i < rightsCount; i++)
                        {
                            IntPtr lusPtr = IntPtr.Add(rightsPtr, (int)i * lusSize);
                            var lus = Marshal.PtrToStructure<LSA_UNICODE_STRING>(lusPtr);
                            if (lus.Buffer != IntPtr.Zero)
                            {
                                string priv = Marshal.PtrToStringUni(lus.Buffer, lus.Length / 2);
                                if (!string.IsNullOrEmpty(priv)) existing.Add(priv);
                            }
                        }
                    }
                    if (rightsPtr != IntPtr.Zero)
                    {
                        NativeMethods.LsaFreeMemory(rightsPtr);
                        rightsPtr = IntPtr.Zero;
                    }
                }
                else if (status != LsaConstants.STATUS_OBJECT_NAME_NOT_FOUND && status != LsaConstants.STATUS_NO_MORE_ENTRIES)
                {
                    return false;
                }

                foreach (var priv in WellKnownPrivileges.All)
                {
                    if (!existing.Contains(priv)) return false;
                }
                return true;
            }
            finally
            {
                if (policyHandle != IntPtr.Zero) NativeMethods.LsaClose(policyHandle);
                if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
                if (rightsPtr != IntPtr.Zero) NativeMethods.LsaFreeMemory(rightsPtr);
            }
        }

        public static bool GrantPrivileges()
        {
            IntPtr policyHandle = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            IntPtr rightsPtr = IntPtr.Zero;

            try
            {
                var loa = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
                uint status = NativeMethods.LsaOpenPolicy(IntPtr.Zero, ref loa, LsaConstants.POLICY_ALL_ACCESS, out policyHandle);
                if (status != LsaConstants.STATUS_SUCCESS)
                {
                    Console.WriteLine($"[-] LsaOpenPolicy failed: 0x{status:X8}");
                    return false;
                }

                sid = GetBuiltinAdministratorsSid();
                
                IntPtr tempRightsPtr;
                uint rightsCount;
                status = NativeMethods.LsaEnumerateAccountRights(policyHandle, sid, out tempRightsPtr, out rightsCount);

                HashSet<string> existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (status == LsaConstants.STATUS_SUCCESS)
                {
                    rightsPtr = tempRightsPtr;
                    if (rightsPtr != IntPtr.Zero && rightsCount > 0)
                    {
                        int lusSize = Marshal.SizeOf<LSA_UNICODE_STRING>();
                        for (uint i = 0; i < rightsCount; i++)
                        {
                            IntPtr lusPtr = IntPtr.Add(rightsPtr, (int)i * lusSize);
                            var lus = Marshal.PtrToStructure<LSA_UNICODE_STRING>(lusPtr);
                            if (lus.Buffer != IntPtr.Zero)
                            {
                                string priv = Marshal.PtrToStringUni(lus.Buffer, lus.Length / 2);
                                if (!string.IsNullOrEmpty(priv)) existing.Add(priv);
                            }
                        }
                    }
                    if (rightsPtr != IntPtr.Zero)
                    {
                        NativeMethods.LsaFreeMemory(rightsPtr);
                        rightsPtr = IntPtr.Zero;
                    }
                }
                else if (status != LsaConstants.STATUS_OBJECT_NAME_NOT_FOUND && status != LsaConstants.STATUS_NO_MORE_ENTRIES)
                {
                    Console.WriteLine($"[-] LsaEnumerateAccountRights failed: 0x{status:X8}");
                    return false;
                }

                List<string> toAdd = new List<string>();
                foreach (string priv in AllLsaPrivileges)
                {
                    if (!existing.Contains(priv))
                    {
                        toAdd.Add(priv);
                    }
                }

                if (toAdd.Count == 0)
                {
                    Console.WriteLine("[*] All privileges are already granted.");
                    return true;
                }

                Console.WriteLine($"[*] Granting {toAdd.Count} privileges...");

                var rights = new LSA_UNICODE_STRING[toAdd.Count];
                try
                {
                    for (int i = 0; i < toAdd.Count; i++)
                    {
                        rights[i] = InitLsaString(toAdd[i]);
                    }
                    status = NativeMethods.LsaAddAccountRights(policyHandle, sid, rights, (uint)rights.Length);
                }
                finally
                {
                    for (int i = 0; i < rights.Length; i++)
                    {
                        if (rights[i].Buffer != IntPtr.Zero) Marshal.FreeHGlobal(rights[i].Buffer);
                    }
                }

                if (status == LsaConstants.STATUS_SUCCESS)
                {
                    Console.WriteLine("[+] All privileges granted successfully.");
                    return true;
                }
                else
                {
                    Console.WriteLine($"[!] Bulk grant failed (0x{status:X8}), trying individual grants...");
                    
                    int added = 0;
                    int failed = 0;
                    foreach (string priv in toAdd)
                    {
                        var singleRight = new LSA_UNICODE_STRING[1];
                        singleRight[0] = InitLsaString(priv);
                        try
                        {
                            uint addStatus = NativeMethods.LsaAddAccountRights(policyHandle, sid, singleRight, 1);
                            if (addStatus == LsaConstants.STATUS_SUCCESS)
                            {
                                added++;
                            }
                            else
                            {
                                Console.WriteLine($"  [-] Failed to grant {priv}: 0x{addStatus:X8}");
                                failed++;
                            }
                        }
                        finally
                        {
                            if (singleRight[0].Buffer != IntPtr.Zero) Marshal.FreeHGlobal(singleRight[0].Buffer);
                        }
                    }

                    Console.WriteLine($"[*] Individual grants: {added} succeeded, {failed} failed.");
                    return failed == 0;
                }
            }
            finally
            {
                if (policyHandle != IntPtr.Zero) NativeMethods.LsaClose(policyHandle);
                if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
                if (rightsPtr != IntPtr.Zero) NativeMethods.LsaFreeMemory(rightsPtr);
            }
        }

        public static bool RebootSystem()
        {
            try
            {
                Privilege.EnableAndVerify("SeShutdownPrivilege");
            }
            catch
            {
                Console.WriteLine("[-] Failed to enable SeShutdownPrivilege.");
                return false;
            }

            uint reason = LsaConstants.SHTDN_REASON_MAJOR_APPLICATION
                        | LsaConstants.SHTDN_REASON_MINOR_MAINTENANCE
                        | LsaConstants.SHTDN_REASON_FLAG_PLANNED;

            if (!NativeMethods.ExitWindowsEx(LsaConstants.EWX_REBOOT | LsaConstants.EWX_FORCEIFHUNG, reason))
            {
                Console.WriteLine($"[-] ExitWindowsEx failed: {Marshal.GetLastWin32Error()}");
                return false;
            }

            return true;
        }

        static LSA_UNICODE_STRING InitLsaString(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            byte[] bytes = Encoding.Unicode.GetBytes(value);
            if (bytes.Length > ushort.MaxValue - 2)
                throw new ArgumentException("String too long", nameof(value));

            return new LSA_UNICODE_STRING
            {
                Length = (ushort)bytes.Length,
                MaximumLength = (ushort)(bytes.Length + 2),
                Buffer = Marshal.StringToHGlobalUni(value)
            };
        }

        static IntPtr GetBuiltinAdministratorsSid()
        {
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            IntPtr p = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, p, sidBytes.Length);
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

            if (!IsPhase2(args))
                PauseIfInteractive();
        }

        static bool IsPhase2(string[] args)
            => args.Length > 0 && string.Equals(args[0].Trim(), "--phase2", StringComparison.OrdinalIgnoreCase);

        static void TrySetUtf8Output()
        {
            try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        }

        static void RunMain(string[] args)
        {
            try { LayoutAssertions.Verify(); }
            catch (Exception ex)
            {
                Exception real = UnwrapTypeInit(ex);
                Console.WriteLine($"[-] Fatal: CLR layout assertion failed: {real.Message}");
                return;
            }

            try
            {
                string arg = args.Length > 0 ? args[0].Trim() : string.Empty;

                if (IsPhase2(args))
                {
                    ExecutePhase2Logic(args);
                }
                else if (string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase) || arg == "-h" || arg == "/?")
                {
                    ShowUsage();
                }
                else if (arg.Length == 0)
                {
                    if (!IsAdministrator())
                    {
                        Console.WriteLine("[-] ERROR: This program requires administrator privileges.");
                        return;
                    }

                    bool isWin11Plus = LsaUtility.IsWindows11OrHigher();
                    Console.WriteLine($"[*] Detected OS: {(isWin11Plus ? "Windows 11 or higher" : "Windows 10 or below")}");

                    if (isWin11Plus)
                    {
                        if (LsaUtility.AreRequiredPrivilegesGranted())
                        {
                            Console.WriteLine("[*] All required privileges are already granted. Running Phase 2 directly...");
                            ExecutePhase2Logic(new string[] { "--phase2" });
                        }
                        else
                        {
                            Console.WriteLine("[*] Required privileges not granted. Granting via LSA...");
                            if (LsaUtility.GrantPrivileges())
                            {
                                Console.WriteLine("[+] Privileges granted successfully.");
                                Console.WriteLine("[*] A reboot is required for the changes to take effect.");
                                Console.Write("[*] Reboot now? (y/N): ");
                                string? answer = Console.ReadLine();
                                if (string.Equals(answer?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                                {
                                    if (LsaUtility.RebootSystem())
                                    {
                                        Console.WriteLine("[*] Rebooting...");
                                    }
                                    else
                                    {
                                        Console.WriteLine("[-] Reboot failed. Please reboot manually.");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[*] Please reboot manually and run the program again.");
                                }
                            }
                            else
                            {
                                Console.WriteLine("[-] Failed to grant privileges. Falling back to old flow...");
                                Phase1_LaunchChildProcess();
                            }
                        }
                    }
                    else
                    {
                        Phase1_LaunchChildProcess();
                    }
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
            }
        }

        static Exception UnwrapTypeInit(Exception ex)
            => (ex is TypeInitializationException tie && tie.InnerException != null) ? tie.InnerException : ex;

        static void PauseIfInteractive()
        {
            try { if (!Console.IsInputRedirected) Console.ReadKey(intercept: true); } catch { }
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
            Console.WriteLine("NtCreateToken - TrustedInstaller Token Creator (v23 optimized)");
            Console.WriteLine("Usage: NtCreateTokenFull.exe [OPTIONS]");
            Console.WriteLine("  (none)                                Launch SYSTEM child and create TI token");
            Console.WriteLine("  --phase2 [sessionId] [desktopPath]    Execute as SYSTEM (internal use only)");
        }

        static uint GetCurrentSessionId()
        {
            using var proc = Process.GetCurrentProcess();
            return (uint)proc.SessionId;
        }

        static void Phase1_LaunchChildProcess()
        {
            Console.WriteLine("[*] Phase 1: Launching SYSTEM child process...");
            EnableAndVerifyPrivilege(WellKnownPrivileges.Debug);
            EnableAndVerifyPrivilege(WellKnownPrivileges.Impersonate);
            EnableAndVerifyPrivilege(WellKnownPrivileges.IncreaseQuota);
            EnableAndVerifyPrivilege(WellKnownPrivileges.AssignPrimaryToken);

            using SafeTokenHandle sysToken = GetSystemToken();
            uint currentSession = GetCurrentSessionId();
            string desktop = SessionInfo.HasInteractiveDesktop() ? Config.DefaultDesktop : Config.WinlogonDesktop;

            string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? Config.CmdPath;
            string args = $"--phase2 {currentSession} \"{desktop}\"";

            Console.WriteLine($"[*] Launching Phase 2: {args}");
            ProcessLauncher.LaunchWithToken(sysToken, exePath, args, desktop);
            Console.WriteLine("[+] Phase 1 complete. Child process should now be creating the TI token.");
        }

        static SafeTokenHandle GetSystemToken()
        {
            Process? systemProc = null;
            try
            {
                foreach (var p in Process.GetProcessesByName("winlogon"))
                {
                    if (p.SessionId == GetCurrentSessionId()) { systemProc = p; break; }
                }
                if (systemProc == null) throw new Exception("Cannot find winlogon.exe in current session.");

                IntPtr hProc = NativeMethods.OpenProcess(TokenConstants.PROCESS_QUERY_INFORMATION, false, systemProc.Id);
                if (hProc == IntPtr.Zero) throw InteropUtility.NewError("OpenProcess winlogon failed");

                try
                {
                    if (!NativeMethods.OpenProcessTokenRaw(hProc, TokenConstants.TOKEN_DUPLICATE | TokenConstants.TOKEN_QUERY, out IntPtr hTok))
                        throw InteropUtility.NewError("OpenProcessToken winlogon failed");

                    if (!NativeMethods.DuplicateTokenEx(hTok, TokenConstants.MAXIMUM_ALLOWED, IntPtr.Zero, TokenConstants.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary, out SafeTokenHandle dupTok))
                        throw InteropUtility.NewError("DuplicateTokenEx failed");

                    return dupTok;
                }
                finally { NativeMethods.CloseHandle(hProc); }
            }
            finally { systemProc?.Dispose(); }
        }

        static void ExecutePhase2Logic(string[] args)
        {
            Console.WriteLine("\n=== Phase 2: Creating TrustedInstaller Token ===");
            EnableAndVerifyPrivilege(WellKnownPrivileges.CreateToken);
            EnableAndVerifyPrivilege(WellKnownPrivileges.AssignPrimaryToken);
            EnableAndVerifyPrivilege(WellKnownPrivileges.IncreaseQuota);
            EnableAndVerifyPrivilege(WellKnownPrivileges.Tcb);

            uint targetSessionId = ResolveTargetSessionId(args);
            string desktopName = ResolveTargetDesktop(args, targetSessionId);

            using SafeTokenHandle currentToken = OpenCurrentProcessToken();
            TokenCreator.GetAuthenticationIdAndTokenId(currentToken, out LUID authId, out LUID sourceId);
            Console.WriteLine($"  [*] Using AuthID: 0x{authId.LowPart:X}, SourceID: 0x{sourceId.LowPart:X}");

            string? logonSid = TokenCreator.GetLogonSid(currentToken);
            var groups = BuildGroupList(logonSid);

            var validPrivileges = new List<(string name, TokenCreator.PrivilegeAttributes attr)>();
            var skippedPrivileges = new List<string>();
            var seenPrivileges = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var name in WellKnownPrivileges.All)
            {
                if (!seenPrivileges.Add(name)) continue;
                if (NativeMethods.LookupPrivilegeValue(null, name, out _))
                    validPrivileges.Add((name, TokenCreator.PrivilegeAttributes.Enabled | TokenCreator.PrivilegeAttributes.EnabledByDefault));
                else
                    skippedPrivileges.Add(name);
            }

            if (skippedPrivileges.Count > 0)
                Console.WriteLine($"  [!] Skipped {skippedPrivileges.Count} unavailable privilege(s).");

            using var newToken = TokenCreator.CreatePrimaryToken(WellKnownSids.TrustedInstaller, groups, validPrivileges.ToArray(), authId, sourceId);
            Console.WriteLine($"  [+] Token created, handle: 0x{newToken.DangerousGetHandle():X}");

            TokenCreator.SetTokenSessionId(newToken, targetSessionId);
            Console.WriteLine($"  [+] Token Session ID set to {targetSessionId}");

            TryGrantDesktopAccess(WellKnownSids.TrustedInstaller, desktopName);

            Console.WriteLine($"\n  [*] Launching cmd.exe as TrustedInstaller on {desktopName}...");
            ProcessLauncher.Launch(newToken, Config.CmdPath, desktopName);
            Console.WriteLine("\n=== SUCCESS! New cmd.exe running as TrustedInstaller ===");
        }

        static SafeTokenHandle OpenCurrentProcessToken()
        {
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TokenConstants.TOKEN_QUERY, out SafeTokenHandle tok))
                throw InteropUtility.NewError("OpenProcessToken (current process) failed");
            return tok;
        }

        static uint ResolveTargetSessionId(string[] args)
        {
            if (args.Length >= 2 && uint.TryParse(args[1], out uint parsed)) return parsed;
            uint? active = SessionInfo.FindActiveUserSession();
            return active ?? GetCurrentSessionId();
        }

        static string ResolveTargetDesktop(string[] args, uint sessionId)
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
            try
            {
                DesktopAccess.GrantAccess(sid, desktopName);
                Console.WriteLine($"  [+] Desktop access granted to {sid} on {desktopName}");
            }
            catch (Exception ex) { Console.WriteLine($"  [!] Desktop access grant failed: {ex.Message}"); }
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

    // ========================================================================
    //  WellKnownSids & Privileges
    // ========================================================================
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
    //  DesktopAccess
    // ========================================================================
    static class DesktopAccess
    {
        static readonly int AclSizeInfoSize  = Marshal.SizeOf<ACL_SIZE_INFORMATION>();
        static readonly int SecurityDescSize = Marshal.SizeOf<SECURITY_DESCRIPTOR>();

        public static void GrantAccess(string sidString, string desktopName)
        {
            (string winsta, string desktop) = SplitDesktopName(desktopName);
            IntPtr pSid = IntPtr.Zero;
            try
            {
                if (!NativeMethods.ConvertStringSidToSid(sidString, out pSid)) throw InteropUtility.NewError("ConvertStringSidToSid failed");

                IntPtr hWinSta = NativeMethods.OpenWindowStation(winsta, false, TokenConstants.READ_CONTROL | TokenConstants.WRITE_DAC);
                if (hWinSta == IntPtr.Zero) throw InteropUtility.NewError($"OpenWindowStation('{winsta}') failed");
                try { AddAceToObject(hWinSta, pSid, TokenConstants.WINSTA_ALL_ACCESS); } finally { NativeMethods.CloseWindowStation(hWinSta); }

                IntPtr hDesktop = NativeMethods.OpenDesktop(desktop, 0, false, TokenConstants.READ_CONTROL | TokenConstants.WRITE_DAC);
                if (hDesktop == IntPtr.Zero) throw InteropUtility.NewError($"OpenDesktop('{desktop}') failed");
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

        static void AddAceToObject(IntPtr handle, IntPtr pSid, uint accessMask)
        {
            uint siFlag2 = TokenConstants.DACL_SECURITY_INFORMATION;
            IntPtr pSD = Marshal.AllocHGlobal(SecurityDescSize);
            try
            {
                if (!NativeMethods.GetUserObjectSecurity(handle, ref siFlag2, pSD, (uint)SecurityDescSize, out uint sdSize))
                    throw InteropUtility.NewError("GetUserObjectSecurity failed");

                if (!NativeMethods.GetSecurityDescriptorDacl(pSD, out bool daclPresent, out IntPtr pDacl, out _))
                    throw InteropUtility.NewError("GetSecurityDescriptorDacl failed");

                uint existingAclBytesInUse = TokenConstants.ACL_HEADER_SIZE;
                uint existingAceCount = 0;
                uint aclRevision = TokenConstants.ACL_REVISION;

                if (daclPresent && pDacl != IntPtr.Zero)
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
                uint newAclSize = (uint)InteropUtility.Align4((ulong)existingAclBytesInUse + alignedNewAceSize);

                IntPtr pNewAcl = Marshal.AllocHGlobal((int)newAclSize);
                try
                {
                    if (!NativeMethods.InitializeAcl(pNewAcl, newAclSize, aclRevision)) throw InteropUtility.NewError("InitializeAcl failed");

                    if (daclPresent && pDacl != IntPtr.Zero)
                    {
                        for (uint i = 0; i < existingAceCount; i++)
                        {
                            if (!NativeMethods.GetAce(pDacl, i, out IntPtr pExistingAce)) throw InteropUtility.NewError("GetAce failed");
                            if (!NativeMethods.AddAce(pNewAcl, aclRevision, uint.MaxValue, pExistingAce, GetAceSize(pExistingAce)))
                                throw InteropUtility.NewError("AddAce (copy) failed");
                        }
                    }

                    if (!NativeMethods.AddAccessAllowedAce(pNewAcl, aclRevision, accessMask, pSid)) throw InteropUtility.NewError("AddAccessAllowedAce failed");

                    var sd = new SECURITY_DESCRIPTOR();
                    if (!NativeMethods.InitializeSecurityDescriptor(pSD, TokenConstants.SECURITY_DESCRIPTOR_REVISION)) throw InteropUtility.NewError("InitializeSecurityDescriptor failed");
                    if (!NativeMethods.SetSecurityDescriptorDacl(pSD, true, pNewAcl, false)) throw InteropUtility.NewError("SetSecurityDescriptorDacl failed");
                    if (!NativeMethods.SetUserObjectSecurity(handle, ref siFlag2, pSD)) throw InteropUtility.NewError("SetUserObjectSecurity failed");
                }
                finally { Marshal.FreeHGlobal(pNewAcl); }
            }
            finally { Marshal.FreeHGlobal(pSD); }
        }

        static uint GetAceSize(IntPtr pAce)
        {
            return (uint)Marshal.ReadInt16(pAce, 2);
        }

        static bool HasMatchingAce(IntPtr pAcl, uint aceCount, IntPtr pSid, uint accessMask)
        {
            for (uint i = 0; i < aceCount; i++)
            {
                if (!NativeMethods.GetAce(pAcl, i, out IntPtr pAce)) continue;
                IntPtr aceSid = IntPtr.Add(pAce, 8);
                uint aceMask = (uint)Marshal.ReadInt32(pAce, 4);
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
        public struct TOKEN_PRIVILEGES_SINGLE
        {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        static readonly int TokenPrivilegesSingleSize = Marshal.SizeOf<TOKEN_PRIVILEGES_SINGLE>();

        public static void EnableAndVerify(string privilegeName)
        {
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TokenConstants.TOKEN_ADJUST_PRIVILEGES | TokenConstants.TOKEN_QUERY, out SafeTokenHandle tok))
                throw InteropUtility.NewError("OpenProcessToken failed");
            try { AdjustSinglePrivilege(tok, privilegeName); } finally { tok.Dispose(); }
        }

        static void AdjustSinglePrivilege(SafeTokenHandle tok, string privilegeName)
        {
            if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out LUID luid))
                throw InteropUtility.NewError($"LookupPrivilegeValue failed: {privilegeName}");

            var tp = new TOKEN_PRIVILEGES_SINGLE
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = TokenConstants.SE_PRIVILEGE_ENABLED }
            };

            int status = NativeMethods.NtAdjustPrivilegesToken(tok.DangerousGetHandle(), false, ref tp, (uint)TokenPrivilegesSingleSize, IntPtr.Zero, IntPtr.Zero);
            if (status == 0x00000106) throw new Win32Exception(1300, $"{privilegeName} not held");
            if (status != 0) throw new Win32Exception($"Failed to enable {privilegeName} (0x{status:X8})");
        }
    }

    // ========================================================================
    //  TokenCreator
    // ========================================================================
    static class TokenCreator
    {
        static readonly long MaxExpirationFileTime = new DateTime(DateTime.MaxValue.Ticks, DateTimeKind.Utc).ToFileTimeUtc();
        static readonly int SecurityQosSize           = Marshal.SizeOf<SECURITY_QUALITY_OF_SERVICE>();
        static readonly int ObjectAttributesSize      = Marshal.SizeOf<OBJECT_ATTRIBUTES>();
        static readonly int TokenUserSize             = Marshal.SizeOf<TOKEN_USER>();
        static readonly int SidAndAttributesSize      = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
        static readonly int TokenPrivilegesHeaderSize = Marshal.SizeOf<TOKEN_PRIVILEGES_HEADER>();
        static readonly int LuidAndAttributesSize     = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
        static readonly int TokenGroupsArrayOffset    = (int)Marshal.OffsetOf<TOKEN_GROUPS_LAYOUT>(nameof(TOKEN_GROUPS_LAYOUT.FirstGroup));

        [Flags]
        public enum GroupAttributes : uint
        {
            None = 0, Mandatory = 0x01, EnabledByDefault = 0x02, Enabled = 0x04, Owner = 0x08,
            UseForDenyOnly = 0x10, Integrity = 0x20, IntegrityEnabled = 0x40, Resource = 0x20000000, LogonId = 0xC0000000
        }

        [Flags]
        public enum PrivilegeAttributes : uint { None = 0, EnabledByDefault = 0x01, Enabled = 0x02 }

        public static void GetAuthenticationIdAndTokenId(SafeTokenHandle token, out LUID authenticationId, out LUID tokenId)
        {
            authenticationId = default;
            tokenId = default;

            IntPtr sourceBuf = IntPtr.Zero;
            try
            {
                sourceBuf = GetTokenInformationBuf(token, TokenConstants.TokenSource, out uint sourceLen);
                if (sourceLen >= 16) tokenId = InteropUtility.ReadLuid(sourceBuf, 8);
            }
            catch { }
            finally { if (sourceBuf != IntPtr.Zero) Marshal.FreeHGlobal(sourceBuf); }

            IntPtr statsBuf = GetTokenInformationBuf(token, TokenConstants.TokenStatistics, out uint statsLen);
            try
            {
                if (statsLen >= 16)
                {
                    authenticationId = InteropUtility.ReadLuid(statsBuf, 8);
                    if (tokenId.LowPart == 0 && tokenId.HighPart == 0)
                        tokenId = InteropUtility.ReadLuid(statsBuf, 0);
                }
            }
            finally { if (statsBuf != IntPtr.Zero) Marshal.FreeHGlobal(statsBuf); }
        }

        public static string? GetLogonSid(SafeTokenHandle token)
        {
            IntPtr buf = GetTokenInformationBuf(token, TokenConstants.TokenGroups, out uint len);
            try
            {
                int count = Marshal.ReadInt32(buf, 0);
                int offset = TokenGroupsArrayOffset;
                for (int i = 0; i < count; i++)
                {
                    var sa = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(IntPtr.Add(buf, offset));
                    if ((sa.Attributes & (uint)GroupAttributes.LogonId) == (uint)GroupAttributes.LogonId)
                    {
                        if (NativeMethods.ConvertSidToStringSid(sa.Sid, out IntPtr strSid))
                        {
                            string? res = Marshal.PtrToStringUni(strSid);
                            NativeMethods.LocalFree(strSid);
                            return res;
                        }
                    }
                    offset += SidAndAttributesSize;
                }
                return null;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static void SetTokenSessionId(SafeTokenHandle token, uint sessionId)
        {
            if (!NativeMethods.SetTokenInformation(token, TokenConstants.TokenSessionId, ref sessionId, 4))
                throw InteropUtility.NewError("SetTokenInformation SessionId failed");
        }

        static IntPtr CreateTokenGroupsBuffer((string sid, GroupAttributes attributes)[] entries, out IntPtr[] sidPtrs)
        {
            sidPtrs = Array.Empty<IntPtr>();
            int count = entries.Length;
            long totalSize = (long)TokenGroupsArrayOffset + ((long)SidAndAttributesSize * count);
            IntPtr buf = Marshal.AllocHGlobal((int)totalSize);
            sidPtrs = new IntPtr[count];
            bool success = false;

            try
            {
                Marshal.WriteInt32(buf, 0, count);
                IntPtr ptr = IntPtr.Add(buf, TokenGroupsArrayOffset);
                for (int i = 0; i < count; i++)
                {
                    if (!NativeMethods.ConvertStringSidToSid(entries[i].sid, out IntPtr pSid))
                        throw InteropUtility.NewError($"ConvertStringSidToSid failed: {entries[i].sid}");
                    
                    sidPtrs[i] = pSid;
                    Marshal.StructureToPtr(new SID_AND_ATTRIBUTES { Sid = pSid, Attributes = (uint)entries[i].attributes }, ptr, false);
                    ptr = IntPtr.Add(ptr, SidAndAttributesSize);
                }
                success = true;
                return buf;
            }
            finally
            {
                if (!success)
                {
                    foreach (var p in sidPtrs) InteropUtility.LocalFreeIfNotNull(p);
                    Marshal.FreeHGlobal(buf);
                    sidPtrs = Array.Empty<IntPtr>();
                }
            }
        }

        static IntPtr CreateTokenPrivilegesBuffer((string name, PrivilegeAttributes attr)[] privs)
        {
            int count = privs.Length;
            long totalSize = TokenPrivilegesHeaderSize + ((long)LuidAndAttributesSize * count);
            IntPtr buf = Marshal.AllocHGlobal((int)totalSize);
            bool success = false;
            try
            {
                int actualCount = 0;
                IntPtr ptr = IntPtr.Add(buf, TokenPrivilegesHeaderSize);
                foreach (var p in privs)
                {
                    if (NativeMethods.LookupPrivilegeValue(null, p.name, out LUID luid))
                    {
                        Marshal.StructureToPtr(new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = (uint)p.attr }, ptr, false);
                        ptr = IntPtr.Add(ptr, LuidAndAttributesSize);
                        actualCount++;
                    }
                }
                Marshal.WriteInt32(buf, 0, actualCount);
                success = true;
                return buf;
            }
            finally { if (!success) Marshal.FreeHGlobal(buf); }
        }

        static IntPtr BuildDefaultDacl(IntPtr sidOwner, out IntPtr[] daclSidPtrs)
        {
            daclSidPtrs = new IntPtr[3];
            if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.System, out daclSidPtrs[0])) throw InteropUtility.NewError("SID System");
            if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.BuiltinAdmins, out daclSidPtrs[1])) throw InteropUtility.NewError("SID Admins");
            if (!NativeMethods.ConvertStringSidToSid(WellKnownSids.Everyone, out daclSidPtrs[2])) throw InteropUtility.NewError("SID Everyone");

            ulong aclSize = TokenConstants.ACL_HEADER_SIZE +
                            InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + NativeMethods.GetLengthSid(daclSidPtrs[0])) +
                            InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + NativeMethods.GetLengthSid(daclSidPtrs[1])) +
                            InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + NativeMethods.GetLengthSid(sidOwner)) +
                            InteropUtility.Align4(TokenConstants.ACCESS_ALLOWED_ACE_FIXED_SIZE + NativeMethods.GetLengthSid(daclSidPtrs[2]));

            IntPtr pAcl = Marshal.AllocHGlobal((int)aclSize);
            try
            {
                NativeMethods.InitializeAcl(pAcl, (uint)aclSize, TokenConstants.ACL_REVISION);
                NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TokenConstants.TOKEN_ALL_ACCESS, daclSidPtrs[0]);
                NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TokenConstants.TOKEN_ALL_ACCESS, daclSidPtrs[1]);
                NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TokenConstants.TOKEN_ALL_ACCESS, sidOwner);
                NativeMethods.AddAccessAllowedAce(pAcl, TokenConstants.ACL_REVISION, TokenConstants.TOKEN_QUERY | TokenConstants.READ_CONTROL, daclSidPtrs[2]);
                return pAcl;
            }
            catch { Marshal.FreeHGlobal(pAcl); throw; }
        }

        public static SafeTokenHandle CreatePrimaryToken(
            string userSid,
            (string sid, GroupAttributes attr)[] groups,
            (string name, PrivilegeAttributes attr)[] privs,
            LUID authId,
            LUID sourceId)
        {
            IntPtr pUserSid = IntPtr.Zero;
            IntPtr pGroups = IntPtr.Zero;
            IntPtr[] groupSidPtrs = Array.Empty<IntPtr>();
            IntPtr pPrivs = IntPtr.Zero;
            IntPtr pDacl = IntPtr.Zero;
            IntPtr[] daclSidPtrs = Array.Empty<IntPtr>();
            IntPtr pSqos = IntPtr.Zero;
            IntPtr pObjAttrs = IntPtr.Zero;

            try
            {
                if (!NativeMethods.ConvertStringSidToSid(userSid, out pUserSid)) throw InteropUtility.NewError("User SID");

                pGroups = CreateTokenGroupsBuffer(groups, out groupSidPtrs);
                pPrivs = CreateTokenPrivilegesBuffer(privs);
                pDacl = BuildDefaultDacl(pUserSid, out daclSidPtrs);

                var sqos = new SECURITY_QUALITY_OF_SERVICE
                {
                    Length = SecurityQosSize,
                    ImpersonationLevel = TokenConstants.SecurityImpersonation,
                    ContextTrackingMode = 1,
                    EffectiveOnly = 0
                };
                pSqos = Marshal.AllocHGlobal(SecurityQosSize);
                Marshal.StructureToPtr(sqos, pSqos, false);

                var objAttrs = new OBJECT_ATTRIBUTES
                {
                    Length = ObjectAttributesSize,
                    SecurityQualityOfService = pSqos
                };
                pObjAttrs = Marshal.AllocHGlobal(ObjectAttributesSize);
                Marshal.StructureToPtr(objAttrs, pObjAttrs, false);

                var tokenUser = new TOKEN_USER { User = new SID_AND_ATTRIBUTES { Sid = pUserSid, Attributes = 0 } };
                var tokenOwner = new TOKEN_OWNER { Owner = pUserSid };
                var tokenPrimaryGroup = new TOKEN_PRIMARY_GROUP { PrimaryGroup = pUserSid };
                var tokenDefaultDacl = new TOKEN_DEFAULT_DACL { DefaultDacl = pDacl };
                var tokenSource = TOKEN_SOURCE.Create("User32", sourceId);
                var expiration = new LARGE_INTEGER { QuadPart = MaxExpirationFileTime };

                int status = NativeMethods.NtCreateToken(
                    out SafeTokenHandle newToken,
                    TokenConstants.TOKEN_ALL_ACCESS,
                    ref objAttrs,
                    TOKEN_TYPE.TokenPrimary,
                    ref authId,
                    ref expiration,
                    ref tokenUser,
                    pGroups,
                    pPrivs,
                    ref tokenOwner,
                    ref tokenPrimaryGroup,
                    ref tokenDefaultDacl,
                    ref tokenSource);

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
                if (pGroups != IntPtr.Zero) Marshal.FreeHGlobal(pGroups);
                foreach (var ptr in groupSidPtrs) InteropUtility.LocalFreeIfNotNull(ptr);
                if (pPrivs != IntPtr.Zero) Marshal.FreeHGlobal(pPrivs);
                if (pDacl != IntPtr.Zero) Marshal.FreeHGlobal(pDacl);
                foreach (var ptr in daclSidPtrs) InteropUtility.LocalFreeIfNotNull(ptr);
                InteropUtility.FreeHGlobalIfNotNull(pSqos);
                InteropUtility.FreeHGlobalIfNotNull(pObjAttrs);
            }
        }

        static IntPtr GetTokenInformationBuf(SafeTokenHandle token, int infoClass, out uint length)
        {
            length = 0;
            if (!NativeMethods.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out length))
            {
                int err = InteropUtility.LastError;
                if (err != TokenConstants.ERROR_INSUFFICIENT_BUFFER) throw InteropUtility.NewError(err, "GetTokenInformation size");
            }
            IntPtr buf = Marshal.AllocHGlobal((int)length);
            if (!NativeMethods.GetTokenInformation(token, infoClass, buf, length, out _))
            {
                Marshal.FreeHGlobal(buf);
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
        static readonly int SecurityAttributesSize = Marshal.SizeOf<SECURITY_ATTRIBUTES>();
        static readonly int StartupInfoSize        = Marshal.SizeOf<STARTUPINFO>();

        public static void Launch(SafeTokenHandle token, string application, string desktopName)
        {
            var sa = new SECURITY_ATTRIBUTES { nLength = SecurityAttributesSize, bInheritHandle = 0 };
            
            IntPtr pDesktop = IntPtr.Zero;
            IntPtr pTitle = IntPtr.Zero;
            try
            {
                string? normDesktop = InteropUtility.NormalizeDesktop(desktopName);
                if (!string.IsNullOrEmpty(normDesktop)) pDesktop = Marshal.StringToHGlobalUni(normDesktop);
                pTitle = Marshal.StringToHGlobalUni(Config.TiShellWindowTitle);

                var si = new STARTUPINFO
                {
                    cb = StartupInfoSize,
                    lpDesktop = pDesktop,
                    lpTitle = pTitle,
                    dwFlags = TokenConstants.STARTF_USESHOWWINDOW,
                    wShowWindow = 1
                };

                var sbCmdLine = new StringBuilder(InteropUtility.Quote(application));
                if (!NativeMethods.CreateProcessAsUser(token, application, sbCmdLine, ref sa, ref sa, false, 0x00000010, IntPtr.Zero, Config.System32Path, ref si, out var pi))
                    throw InteropUtility.NewError("CreateProcessAsUser failed");

                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);
            }
            finally
            {
                if (pDesktop != IntPtr.Zero) Marshal.FreeHGlobal(pDesktop);
                if (pTitle != IntPtr.Zero) Marshal.FreeHGlobal(pTitle);
            }
        }

        public static void LaunchWithToken(SafeTokenHandle token, string application, string arguments, string? desktopName)
        {
            IntPtr pDesktop = IntPtr.Zero;
            try
            {
                string? normDesktop = InteropUtility.NormalizeDesktop(desktopName);
                if (!string.IsNullOrEmpty(normDesktop)) pDesktop = Marshal.StringToHGlobalUni(normDesktop);

                var si = new STARTUPINFO { cb = StartupInfoSize, lpDesktop = pDesktop, dwFlags = TokenConstants.STARTF_USESHOWWINDOW, wShowWindow = 1 };
                string cmdLine = $"{InteropUtility.Quote(application)} {arguments.Trim()}";
                var sbCmdLine = new StringBuilder(cmdLine);

                if (!NativeMethods.CreateProcessWithTokenW(token, 0x00000001, null, sbCmdLine, 0x00000010, IntPtr.Zero, Config.System32Path, ref si, out var pi))
                    throw InteropUtility.NewError("CreateProcessWithTokenW failed");

                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);
            }
            finally { if (pDesktop != IntPtr.Zero) Marshal.FreeHGlobal(pDesktop); }
        }
    }

    // ========================================================================
    //  NativeMethods
    // ========================================================================
    static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr proc, uint access, out SafeTokenHandle handle);
        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenProcessToken")] public static extern bool OpenProcessTokenRaw(IntPtr proc, uint access, out IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeValueW")] public static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetTokenInformation(SafeTokenHandle TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attrs, int impLevel, int tokenType, out SafeTokenHandle newToken);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetSecurityDescriptorDacl(IntPtr pSD, out bool bDaclPresent, out IntPtr pDacl, out bool bDaclDefaulted);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetAclInformation(IntPtr pAcl, ref ACL_SIZE_INFORMATION pAclInfo, uint nAclInfoLength, int dwAclInfoClass);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetAce(IntPtr pAcl, uint dwAceIndex, out IntPtr pAce);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool AddAce(IntPtr pAcl, uint dwAceRevision, uint dwStartingAceIndex, IntPtr pAceList, uint nAceListLength);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool AddAccessAllowedAce(IntPtr pAcl, uint dwAceRevision, uint AccessMask, IntPtr pSid);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool InitializeSecurityDescriptor(IntPtr pSD, uint dwRevision);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool SetSecurityDescriptorDacl(IntPtr pSD, bool bDaclPresent, IntPtr pDacl, bool bDaclDefaulted);
        [DllImport("advapi32.dll")] public static extern uint GetLengthSid(IntPtr pSid);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ConvertStringSidToSidW")] public static extern bool ConvertStringSidToSid(string stringSid, out IntPtr pSid);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ConvertSidToStringSidW")] public static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr stringSid);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool EqualSid(IntPtr pSid1, IntPtr pSid2);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool SetTokenInformation(SafeTokenHandle tokenHandle, int tokenInformationClass, ref uint tokenInformation, int tokenInformationLength);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessAsUserW")] public static extern bool CreateProcessAsUser(SafeTokenHandle hToken, string? lpApplicationName, StringBuilder? lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessWithTokenW")] public static extern bool CreateProcessWithTokenW(SafeTokenHandle hToken, uint dwLogonFlags, string? lpApplicationName, StringBuilder lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenWindowStationW")] public static extern IntPtr OpenWindowStation(string name, bool inherit, uint desiredAccess);
        [DllImport("user32.dll", SetLastError = true)] public static extern bool CloseWindowStation(IntPtr hWinSta);
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenDesktopW")] public static extern IntPtr OpenDesktop(string name, uint flags, bool inherit, uint access);
        [DllImport("user32.dll", SetLastError = true)] public static extern bool CloseDesktop(IntPtr hDesktop);
        [DllImport("user32.dll", SetLastError = true)] public static extern bool GetUserObjectSecurity(IntPtr hObj, ref uint pSIRequested, IntPtr pSD, uint nLength, out uint nLengthNeeded);
        [DllImport("user32.dll", SetLastError = true)] public static extern bool SetUserObjectSecurity(IntPtr hObj, ref uint pSIRequested, IntPtr pSD);
        [DllImport("user32.dll", SetLastError = true)] public static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WTSQuerySessionInformationW")] public static extern bool WTSQuerySessionInformation(IntPtr hServer, uint sessionId, int wtsInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);
        [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr pMemory);
        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WTSEnumerateSessionsW")] public static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr ppSessionInfo, out uint pCount);

        [DllImport("ntdll.dll")] public static extern uint RtlNtStatusToDosError(int status);
        [DllImport("ntdll.dll")] public static extern int NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref Privilege.TOKEN_PRIVILEGES_SINGLE NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
        [DllImport("ntdll.dll", SetLastError = true)] public static extern int RtlGetVersion(out RTL_OSVERSIONINFOW lpVersionInformation);
        
        [DllImport("ntdll.dll")]
        public static extern int NtCreateToken(
            out SafeTokenHandle TokenHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            TOKEN_TYPE TokenType,
            ref LUID AuthenticationId,
            ref LARGE_INTEGER ExpirationTime,
            ref TOKEN_USER TokenUser,
            IntPtr TokenGroups,
            IntPtr TokenPrivileges,
            ref TOKEN_OWNER TokenOwner,
            ref TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            ref TOKEN_DEFAULT_DACL TokenDefaultDacl,
            ref TOKEN_SOURCE TokenSource);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaOpenPolicy(
            IntPtr SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaEnumerateAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            out IntPtr UserRights,
            out uint CountOfRights);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32.dll")]
        public static extern uint LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaFreeMemory(IntPtr buffer);
    }
}