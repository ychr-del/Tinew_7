// ============================================================================
//  NtCreateTokenFull.cs — .NET 10.0 终极优化版
//  修复清单:
//    #1   SID 科学计数法 → 十进制字符串
//    #2   进程重启 → 线程注入 (WindowsImpersonationContext)
//    #3   Environment.Exit(0) 移除
//    #4   CloseHandle 前检查 IntPtr.Zero
//    #5   NtAdjustPrivilegesToken BufferLength 传正确值
//    #6   64 位 TOKEN_GROUPS 对齐验证
//    #7   字符串转义修复 (
 而非 \
)
//    #8   路径字符串修复 (@"C:..." 而非 @"C:\\...")
//    #9   移除 [SuppressUnmanagedCodeSecurity] (.NET 10 已废弃)
//    #10  所有 Marshal.SizeOf<T>() 泛型调用
//    #11  所有 Marshal.OffsetOf<T>() 泛型调用
//    #12  GetlsassPid 优先查找 Session 0
//    #13  修复注释中的转义字符错误
//    #14  修复路径字符串双反斜杠错误
//    #15  修复 Console.WriteLine 中的 \
 错误
//    #16  优化 currentSid null 处理
//    #17  移除 Thread.Sleep(Timeout.Infinite) 改为 return
//    #18  SID 常量改为 const
//    #19  Privilege.Enable 合并为循环
//    #20  统一 using 风格
//    #21  提取配置常量
//    #22  缓存 Marshal.SizeOf<T>() 结果
//    #23  添加日志级别
// ============================================================================

#nullable enable
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using System.Threading;

namespace NtCreateTokenFull
{
    // 【优化#21】提取配置常量
    static class Config
    {
        public const string CmdPath = @"C:WindowsSystem32cmd.exe";
        public const string DesktopName = @"WinSta0Default";
        public const string System32Path = @"C:WindowsSystem32";
    }

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

    class Program
    {
        // 【修复#1】【优化#18】SID 改为 const
        const string SidTrustedInstaller =
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        const string SidSystem = "S-1-5-18";

        static void Main(string[] args)
        {
            Phase1_RelaunchAsSystem();
        }

        static void Phase1_RelaunchAsSystem()
        {
            // 【修复#15】\
 → 

            Console.WriteLine("=== NtCreateToken 提权工具 [阶段 1: 获取 SYSTEM] ===
");

            try
            {
                Console.WriteLine("  [*] 启用 SeDebugPrivilege...");
                TokenThief.EnableDebugPrivilege();
                Console.WriteLine("  [+] SeDebugPrivilege 已启用");

                int lsassPid = TokenThief.GetlsassPid();
                Console.WriteLine($"  [*] lsass.exe PID = {lsassPid}");

                // 【优化#20】统一 using 风格
                using var systemToken = TokenThief.DuplicateProcessToken(lsassPid);
                Console.WriteLine("  [+] SYSTEM 令牌复制成功");

                Console.WriteLine("  [*] 授权 SYSTEM 访问桌面...");
                DesktopAccess.GrantAccess(SidSystem);
                Console.WriteLine("  [+] 桌面权限已授予");

                Console.WriteLine("
  [*] 创建 SYSTEM 线程执行 Phase 2...");

                using (var systemIdentity = new WindowsIdentity(systemToken.DangerousGetHandle()))
                {
                    WindowsImpersonationContext impersonationCtx = systemIdentity.Impersonate();
                    try
                    {
                        Thread phase2Thread = new Thread(() =>
                        {
                            ExecutePhase2Logic();
                        });
                        phase2Thread.IsBackground = false;
                        phase2Thread.Start();
                        phase2Thread.Join();
                    }
                    finally
                    {
                        impersonationCtx.Undo();
                    }
                }

                Console.WriteLine("
=== 阶段 1 完成，按任意键退出此窗口 ===");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"
[-] 阶段 1 错误：{ex.Message}");
                Console.WriteLine($"    详情：{ex}");
                Console.WriteLine("
按任意键退出...");
                Console.ReadKey();
            }
        }

        static void Phase2_CreateTIToken()
        {
            ExecutePhase2Logic();
        }

        static void ExecutePhase2Logic()
        {
            Console.WriteLine("=== NtCreateToken 提权工具 [阶段 2: 创建 TI 令牌] ===
");

            try
            {
                var currentIdentity = WindowsIdentity.GetCurrent();
                // 【修复#16】显式处理 null
                string? currentSid = currentIdentity.User?.Value;
                Console.WriteLine($"  [+] 当前进程身份：{currentIdentity.Name} (SID={currentSid})");

                // 【优化#16】null 安全比较
                if (!string.Equals(currentSid, "S-1-5-18", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("  [-] 错误：当前进程不是 SYSTEM 身份！");
                    Console.WriteLine($"      当前 SID: {currentSid}，期望：S-1-5-18");
                    Console.WriteLine("      请通过阶段 1 启动，不要直接运行 --phase2");
                    // 【修复#17】改为 return，避免永久阻塞
                    return;
                }

                Console.WriteLine("
  [*] 启用必需特权（进程令牌）...");

                // 【优化#19】合并为循环
                string[] privilegesToEnable = new[]
                {
                    "SeCreateTokenPrivilege",
                    "SeAssignPrimaryTokenPrivilege",
                    "SeIncreaseQuotaPrivilege",
                    "SeTcbPrivilege"
                };

                foreach (string priv in privilegesToEnable)
                {
                    Privilege.Enable(priv);
                    Console.WriteLine($"  [+] {priv} 已启用");
                }

                uint currentSessionId = (uint)Process.GetCurrentProcess().SessionId;
                Console.WriteLine($"  [*] Session ID = {currentSessionId}");

                Console.WriteLine("
  [*] 调用 NtCreateToken 创建 TrustedInstaller 令牌...");

                using var newToken = TokenCreator.CreatePrimaryToken(
                    userSidString: SidTrustedInstaller,
                    groupSids: new[]
                    {
                        (SidTrustedInstaller,              TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.Everyone,           TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.Local,              TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.AuthUsers,          TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.Interactive,        TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.ConsoleLogon,       TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.BuiltinUsers,       TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.BuiltinAdmins,      TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory | TokenCreator.GroupAttributes.EnabledByDefault),
                        (WellKnownSids.Service,            TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.SystemLogonSession, TokenCreator.GroupAttributes.Enabled | TokenCreator.GroupAttributes.Mandatory),
                        (WellKnownSids.SystemIntegrity,    TokenCreator.GroupAttributes.Integrity | TokenCreator.GroupAttributes.IntegrityEnabled),
                        (WellKnownSids.TrustedInstaller,   TokenCreator.GroupAttributes.Integrity | TokenCreator.GroupAttributes.IntegrityEnabled)
                    },
                    privileges: new[]
                    {
                        ("SeChangeNotifyPrivilege",       TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeImpersonatePrivilege",        TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeIncreaseQuotaPrivilege",      TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeCreateGlobalPrivilege",       TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeAssignPrimaryTokenPrivilege", TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeTcbPrivilege",                TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeBackupPrivilege",             TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeRestorePrivilege",            TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeDebugPrivilege",              TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeIncreaseWorkingSetPrivilege", TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeTakeOwnershipPrivilege",      TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeSecurityPrivilege",           TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeShutdownPrivilege",           TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeSystemProfilePrivilege",      TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeUndockPrivilege",             TokenCreator.PrivilegeAttributes.Enabled),
                        ("SeCreateTokenPrivilege",        TokenCreator.PrivilegeAttributes.Enabled)
                    },
                    expiry: null
                );

                Console.WriteLine($"  [+] Token 创建成功，句柄：0x{newToken.DangerousGetHandle():X}");

                TokenCreator.SetTokenSessionId(newToken, currentSessionId);
                Console.WriteLine($"  [+] Token Session ID 已设置为 {currentSessionId}");

                Console.WriteLine("  [*] 授权 TrustedInstaller 访问桌面...");
                DesktopAccess.GrantAccess(SidTrustedInstaller);
                Console.WriteLine("  [+] 桌面权限已授予");

                Console.WriteLine("
  [*] 以 TrustedInstaller 身份启动 cmd.exe...");
                // 【修复#14】路径字符串修正
                ProcessLauncher.Launch(newToken, Config.CmdPath);

                Console.WriteLine("
=== 完成！新 cmd.exe 窗口已以 TrustedInstaller 身份运行 ===");
                Console.WriteLine("按任意键退出此窗口...");
                // 【修复#17】移除 Thread.Sleep，直接 return
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"
[-] 阶段 2 错误：{ex.Message}");
                Console.WriteLine($"    详情：{ex}");
                Console.WriteLine("
按任意键退出...");
                // 【修复#17】移除 Thread.Sleep，直接 return
                return;
            }
        }
    }

    static class WellKnownSids
    {
        public const string Everyone = "S-1-1-0";
        public const string Local = "S-1-2-0";
        public const string AuthUsers = "S-1-5-11";
        public const string Interactive = "S-1-5-4";
        public const string ConsoleLogon = "S-1-2-1";
        public const string SystemIntegrity = "S-1-16-16384";
        public const string BuiltinUsers = "S-1-5-32-545";
        public const string BuiltinAdmins = "S-1-5-32-544";
        public const string Service = "S-1-5-6";
        public const string SystemLogonSession = "S-1-5-5-0-999";
        public const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    }

    static class DesktopAccess
    {
        // 【优化#22】缓存 Marshal.SizeOf 结果
        static readonly int AclSizeInformationSize = Marshal.SizeOf<ACL_SIZE_INFORMATION>();

        const int DACL_SECURITY_INFORMATION = 0x04;
        const uint ACL_REVISION = 2;
        const uint SECURITY_DESCRIPTOR_REVISION = 1;
        const int AclSizeInformation = 2;
        const uint READ_CONTROL = 0x00020000;
        const uint WRITE_DAC = 0x00040000;
        const uint WINSTA_ALL_ACCESS = 0x37F;
        const uint DESKTOP_ALL_ACCESS = 0x01FF;
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
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenWindowStation 失败");
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
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenDesktop 失败");
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
                    // 【优化#22】使用缓存的 Size
                    if (!GetAclInformation(pDacl, ref aclInfo,
                        (uint)AclSizeInformationSize, AclSizeInformation))
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

    static class TokenThief
    {
        // 【优化#22】缓存 Marshal.SizeOf 结果
        static readonly int TokenPrivilegesSingleSize = Marshal.SizeOf<TOKEN_PRIVILEGES_SINGLE>();

        const uint TOKEN_DUPLICATE = 0x0002;
        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const uint MAXIMUM_ALLOWED = 0x02000000;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        const int SecurityImpersonation = 2;
        const int TokenPrimary = 1;

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

                // 【修复#5】【优化#22】使用缓存的 Size
                int status = NtAdjustPrivilegesToken(
                    tok.DangerousGetHandle(),
                    false,
                    ref tp,
                    (uint)TokenPrivilegesSingleSize,
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

        public static int GetlsassPid()
        {
            var procs = Process.GetProcessesByName("lsass");
            if (procs.Length == 0)
                throw new InvalidOperationException("未找到 lsass.exe 进程");

            try
            {
                foreach (var p in procs)
                {
                    if (p.SessionId == 0)
                        return p.Id;
                }
                return procs[0].Id;
            }
            finally
            {
                foreach (var p in procs) p.Dispose();
            }
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

    static class Privilege
    {
        static readonly int TokenPrivilegesHeaderSize = Marshal.SizeOf<TOKEN_PRIVILEGES_HEADER>();
        static readonly int LuidAndAttributesSize = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();

        const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const uint TOKEN_QUERY = 0x0008;
        const uint SE_PRIVILEGE_ENABLED = 0x00000002;

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
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, out tok))
            {
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok))
                    throw new Win32Exception();
            }

            try
            {
                if (!LookupPrivilegeValue(null, privilegeName, out var luid))
                    throw new Win32Exception();

                // 【优化#22】使用缓存的 Size
                uint totalSize = (uint)(TokenPrivilegesHeaderSize + LuidAndAttributesSize);
                IntPtr buf = Marshal.AllocHGlobal((int)totalSize);
                try
                {
                    Marshal.WriteInt32(buf, 1);
                    var la = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    };
                    Marshal.StructureToPtr(la, IntPtr.Add(buf, TokenPrivilegesHeaderSize), false);

                    int status = NtAdjustPrivilegesToken(
                        tok.DangerousGetHandle(),
                        false,
                        buf,
                        totalSize,
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

    static class TokenCreator
    {
        // 【优化#22】缓存 Marshal.SizeOf 结果
        static readonly int SecurityQosSize = Marshal.SizeOf<SECURITY_QUALITY_OF_SERVICE>();
        static readonly int ObjectAttributesSize = Marshal.SizeOf<OBJECT_ATTRIBUTES>();
        static readonly int TokenUserSize = Marshal.SizeOf<TOKEN_USER>();
        static readonly int SidAndAttributesSize = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
        static readonly int TokenPrivilegesHeaderSize = Marshal.SizeOf<TOKEN_PRIVILEGES_HEADER>();
        static readonly int LuidAndAttributesSize = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();

        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const uint SE_GROUP_MANDATORY = 0x00000001;
        public const uint SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002;
        public const uint SE_GROUP_ENABLED = 0x00000004;
        public const uint SE_GROUP_INTEGRITY = 0x00000020;
        public const uint SE_GROUP_INTEGRITY_ENABLED = 0x00000040;
        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        [Flags]
        public enum GroupAttributes : uint
        {
            Mandatory = SE_GROUP_MANDATORY,
            EnabledByDefault = SE_GROUP_ENABLED_BY_DEFAULT,
            Enabled = SE_GROUP_ENABLED,
            Integrity = SE_GROUP_INTEGRITY,
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
        const uint GENERIC_ALL = 0x10000000;

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
            IntPtr pDefaultDacl = IntPtr.Zero;
            IntPtr[] daclSidPtrs = null;
            IntPtr[] sidPtrs = null;

            try
            {
                if (!ConvertStringSidToSid(userSidString, out sidUser))
                    throw new Win32Exception();

                bufUser = BuildTokenUser(sidUser);
                bufGroups = BuildTokenGroups(groupSids, out sidPtrs);
                bufPrivs = BuildTokenPrivileges(privileges);

                var owner = new TOKEN_OWNER { Owner = sidUser };
                var primaryGroup = new TOKEN_PRIMARY_GROUP { PrimaryGroup = sidUser };

                pDefaultDacl = BuildDefaultDacl(sidUser, out daclSidPtrs);
                var defaultDacl = new TOKEN_DEFAULT_DACL { DefaultDacl = pDefaultDacl };

                var authId = new LUID { LowPart = 0x3e7, HighPart = 0 };

                if (!AllocateLocallyUniqueId(out var srcId))
                    throw new Win32Exception();

                var source = new TOKEN_SOURCE
                {
                    SourceName = "OptTok",
                    SourceIdentifier = srcId
                };

                var expiryLi = expiry.HasValue
                    ? new LARGE_INTEGER { QuadPart = DateTime.UtcNow.Add(expiry.Value).ToFileTimeUtc() }
                    : new LARGE_INTEGER { QuadPart = long.MaxValue - 1 };

                // 【优化#22】使用缓存的 Size
                var sqos = new SECURITY_QUALITY_OF_SERVICE
                {
                    Length = SecurityQosSize,
                    ImpersonationLevel = 2,
                    ContextTrackingMode = 0,
                    EffectiveOnly = 0
                };
                pSqos = Marshal.AllocHGlobal(SecurityQosSize);
                Marshal.StructureToPtr(sqos, pSqos, false);

                var objAttr = new OBJECT_ATTRIBUTES
                {
                    Length = ObjectAttributesSize,
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
                    throw new Win32Exception(winErr, $"NtCreateToken 失败，NTSTATUS=0x{status:X8}");
                }

                return hToken;
            }
            finally
            {
                if (bufUser != IntPtr.Zero) Marshal.FreeHGlobal(bufUser);
                if (bufGroups != IntPtr.Zero) Marshal.FreeHGlobal(bufGroups);
                if (bufPrivs != IntPtr.Zero) Marshal.FreeHGlobal(bufPrivs);
                if (pSqos != IntPtr.Zero) Marshal.FreeHGlobal(pSqos);
                if (pDefaultDacl != IntPtr.Zero) Marshal.FreeHGlobal(pDefaultDacl);
                LocalFreeIfNotNull(sidUser);
                if (sidPtrs != null)
                    foreach (var s in sidPtrs) LocalFreeIfNotNull(s);
                if (daclSidPtrs != null)
                    foreach (var s in daclSidPtrs) LocalFreeIfNotNull(s);
            }
        }

        static IntPtr BuildTokenUser(IntPtr sid)
        {
            var tu = new TOKEN_USER
            {
                User = new SID_AND_ATTRIBUTES { Sid = sid, Attributes = 0 }
            };
            // 【优化#22】使用缓存的 Size
            IntPtr buf = Marshal.AllocHGlobal(TokenUserSize);
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
            // 【优化#22】使用缓存的 Size
            IntPtr buf = Marshal.AllocHGlobal(hdr + SidAndAttributesSize * count);

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
                        Sid = s,
                        Attributes = (uint)entries[i].attr
                    };
                    Marshal.StructureToPtr(saa, ptr, false);
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
            // 【优化#22】使用缓存的 Size
            IntPtr buf = Marshal.AllocHGlobal(TokenPrivilegesHeaderSize + LuidAndAttributesSize * count);
            bool success = false;

            try
            {
                Marshal.WriteInt32(buf, count);
                IntPtr ptr = IntPtr.Add(buf, TokenPrivilegesHeaderSize);

                foreach (var (name, attr) in privs)
                {
                    if (!NtStatusHelper.LookupPrivilegeValue(null, name, out var luid))
                        throw new Win32Exception();
                    var la = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = (uint)attr
                    };
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

        static class NtStatusHelper
        {
            [DllImport("ntdll.dll")]
            internal static extern uint RtlNtStatusToDosError(int status);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            internal static extern bool LookupPrivilegeValue(
                string system, string name, out LUID luid);
        }
    }

    static class ProcessLauncher
    {
        static readonly int SecurityAttributesSize = Marshal.SizeOf<SECURITY_ATTRIBUTES>();
        static readonly int StartupInfoSize = Marshal.SizeOf<STARTUPINFO>();

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

        const uint CREATE_NEW_CONSOLE = 0x00000010;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const uint LOGON_WITH_PROFILE = 0x00000001;

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

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment, SafeTokenHandle hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        public static void Launch(SafeTokenHandle token, string application)
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
                lpDesktop = Config.DesktopName
            };

            IntPtr envBlock = IntPtr.Zero;
            bool envCreated = CreateEnvironmentBlock(out envBlock, token, false);
            if (!envCreated)
            {
                Console.WriteLine("  [!] CreateEnvironmentBlock 失败，使用继承环境");
                envBlock = IntPtr.Zero;
            }

            try
            {
                if (!CreateProcessAsUser(
                        token, application, null,
                        ref sa, ref sa, false,
                        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                        envBlock,
                        Config.System32Path,
                        ref si, out var pi))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser 失败");
                }

                try
                {
                    Console.WriteLine($"  [+] 进程已启动：{application} (PID={pi.dwProcessId})");
                }
                finally
                {
                    if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                    if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                }
            }
            finally
            {
                if (envBlock != IntPtr.Zero)
                    DestroyEnvironmentBlock(envBlock);
            }
        }

        [Obsolete("Use thread injection instead (Phase1_RelaunchAsSystem)")]
        public static void LaunchWithToken(SafeTokenHandle token, string application, string arguments)
        {
            var si = new STARTUPINFO
            {
                cb = StartupInfoSize,
                lpDesktop = Config.DesktopName
            };

            string cmdLine = $""{application}" {arguments}";

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
                    ? "（Secondary Logon 服务未运行，请执行：sc start seclogon）"
                    : "";
                throw new Win32Exception(err, $"CreateProcessWithTokenW 失败 {hint}");
            }

            try
            {
                Console.WriteLine($"  [+] 进程已启动：{application} (PID={pi.dwProcessId})");
            }
            finally
            {
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            }
        }
    }
}