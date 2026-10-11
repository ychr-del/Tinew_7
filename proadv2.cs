// ============================================================================
//  proadv2.cs — proadv.cs / pproadv1.cs 的第三轮深度审查产物
//  在前两轮 [P1]-[P7]、[Q1]-[Q6] 修复的基础上，本轮新增 [R1]-[R5] 修复；
//  Win11+ 预检/授权/重启/跳过 Phase 1 的流程与 Win10 v15 原逻辑均保持不变。
// ----------------------------------------------------------------------------
//  第三轮深度审查（proadv2）新发现并修复的问题：
//  [R1] GrantAndCheck 异常路径资源泄漏：policyHandle/sid 在 try/finally 之前被
//       TryOpenPolicyAndEnumerateExisting 赋值后，若随后 Console.WriteLine 等
//       托管代码抛异常，将绕过 finally 导致 LSA 句柄与 SID 内存永不释放。
//       现改为"先取局部副本，立即进入 try，再赋给正式变量"，使 finally 覆盖
//       从获取成功起的全部路径。
//  [R2] RebootNow 语义 bug：ExitWindowsEx 是异步的——返回 true 仅表示关机请求
//       已被接受，系统随即终止本进程。调用方在其返回 true 后打印的提示必然丢失。
//       现改为成功时不再返回（环境允许则直接 Environment.Exit(0)），失败才返回
//       false 供调用方提示手动重启；两处调用点同步去掉对返回值 true 的后续处理。
//  [R3] Privilege.EnableOnProcess 错误码残留误判：NativeMethods.AdjustToken-
//       Privileges(string 重载) 内部 LookupPrivilegeValue 成功后可能把 LastError
//       残留为非零；原实现在该包装调用之后才 SetLastPInvokeError(0)，顺序颠倒，
//       会把残留值当成本次错误抛出 Win32Exception。现将清零移到调用之前。
//  [R4] GetMissingPrivileges 冗余 LsaClose：TryOpenPolicyAndEnumerateExisting 已
//       把写权限句柄交回却立即关闭，属无谓开销且易误导维护者。现以 discard 丢弃
//       （所有权语义不变：不使用的句柄在此显式回收）。
//  [R5] --grant-privileges 交互分支缺失：非 -y 模式下授权成功后从不询问重启，
//       与无参数 Win11 分支行为不一致。现补上 y/N 询问（EOF 按默认 N 处理）。
// ----------------------------------------------------------------------------
//  前两轮（pproadv1）修复清单（保留于本文件）：
//  [P1] CS0051 编译错误：public 方法 AdjustTokenPrivileges 的参数类型
//       ADJUSTABLE_SINGLE_TOKEN_PRIVILEGES 可访问性低于方法本身 → 改为 public。
//       （proadv.cs 原文件无法通过 dotnet build，本版本已验证可编译。）
//  [P2] GrantAndCheck 返回值运算符优先级 bug：
//       "failed == 0 && added > 0 || toAdd.Count == 0" 在"批量添加成功但 added==0"
//       等边界下判定不稳；改为显式括号并按"无失败项"返回，且授权后重新枚举 LSA
//       做闭环校验（verify-after-write），确认所有目标特权确实写入策略。
//  [P3] Main / --grant-privileges 入口增加 -y / --yes 非交互参数（与原授权程序
//       对齐），便于自动化场景跳过 y/N 询问；同时避免 Console.ReadLine 在非交互
//       输入流下抛异常或读到 EOF。
//  [P4] PrivilegeGranter.GetMissingPrivileges 与 GrantAndCheck 中约 90 行完全
//       重复的"LsaOpenPolicy + 枚举现有特权"代码抽取为共用私有方法
//       EnumerateExistingRights，消除重复、统一错误处理。
//  [P5] InitLsaString 原先用 Marshal.StringToHGlobalUni 分配 Buffer，却按
//       Encoding.Unicode 字节数计算 Length —— 语义正确但易被误读为 ANSI；
//       补充注释并复用同一次编码结果，保证 MaximumLength 溢出检查与实际分配一致。
//  [P6] ExitWindowsEx 前确保 stdout 已刷新且给出最后提示的顺序优化：先打印
//       "正在重启..."再 Flush，防止关机竞态导致提示丢失。
//  其余逻辑与 proadv.cs 完全一致。
// ----------------------------------------------------------------------------
//  proadv.cs — .NET 10.0 ADVANCED VERSION (v16-adv, 基于 Program.cs v15)
//  除下述新增逻辑外，其余代码与 Program.cs (v15) 完全一致：
//  1) 程序启动后先执行 Windows 版本检查：
//     - Win11 及以上 (build >= 22000)：
//       a. 先用 LSA 逻辑检查内置 Administrators (S-1-5-32-544) 是否已被授权
//          全部高危特权（与 GrantAdminPrivileges 相同的判定逻辑）；
//       b. 若尚未授权 → 提示用户需要先授权，用户同意后执行 LSA 批量授权
//          （SeCreateToken / SeTcb / SeImpersonate 等几乎全部特权），
//          完成后提示用户重启系统生效并退出本次运行；
//       c. 若已授权 → 跳过 Phase 1，直接在本进程内执行 Phase 2
//          （Windows 的"用户权利指派"策略变更在系统启动时写入令牌，
//           故授权后必须重启；重启后再运行本程序即可直达 Phase 2）。
//     - Win10 及以下：保持 v15 原有逻辑不变（Phase 1 窃取 lsass SYSTEM
//       令牌 → 启动 SYSTEM 子进程 → Phase 2 NtCreateToken）。
//  2) --phase2 / --grant-privileges / --check-privileges 分支不做版本门禁，
//     行为与 v15 相同（便于子进程与手动调用）。
// ============================================================================

#nullable enable
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace NtCreateTokenFull
{
    // ========================================================================
    //  CONSTANTS
    // ========================================================================

    static class TokenConstants
    {
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint MAXIMUM_ALLOWED = 0x02000000;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        public const int SecurityImpersonation = 2;

        // pproadv1 第二轮审查 [Q4]：删除未被引用的 TokenUser/TokenGroups 常量（死代码），
        // 保留实际使用的 TokenPrivileges(3) 与 TokenSessionId(12)。
        public const int TokenPrivileges = 3;
        public const int TokenSessionId = 12;
    }

    static class Config
    {
        public static readonly string System32Path =
            Environment.GetFolderPath(Environment.SpecialFolder.System);

        public static readonly string CmdPath =
            Path.Combine(System32Path, "cmd.exe");

        public const string DefaultDesktop = @"WinSta0\Default";
        public const string WinlogonDesktop = @"WinSta0\Winlogon";

        public const string TiShellWindowTitle = "TrustedInstaller Shell";
    }

    // ========================================================================
    //  SHARED STRUCTS
    // ========================================================================

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    // proadv 新增：RtlGetVersion 使用的版本信息结构体
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct OSVERSIONINFOEXW
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public ushort wServicePackMajor;
        public ushort wServicePackMinor;
        public ushort wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    // pproadv1 第二轮深度审查 [Q1]：原 proadv.cs/pproadv1 第一版中的
    //   struct TOKEN_PRIVILEGES { uint; [MarshalAs(Struct)] LUID_AND_ATTRIBUTES_PACKED; }
    // 在沙箱 dotnet build 中已无任何引用（死代码），且其 Pack=8 声明会使
    // Marshal.SizeOf 返回 16（而非 Win32 TOKEN_PRIVILEGES 单特权布局的 12 字节），
    // 一旦被复用会把错误的 BufferLength 传给 AdjustTokenPrivileges。
    // 现删除该死结构，统一使用 NativeMethods.ADJUSTABLE_SINGLE_TOKEN_PRIVILEGES
    // （Sequential 默认对齐 => 恰好 12 字节，与 Windows 解析方式一致）。
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES_HEADER { public uint PrivilegeCount; }

    [StructLayout(LayoutKind.Sequential)]
    struct LARGE_INTEGER { public long QuadPart; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct TOKEN_SOURCE
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string SourceName;
        public LUID SourceIdentifier;
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

    [StructLayout(LayoutKind.Sequential)]
    struct WTS_SESSION_INFO
    {
        public uint SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    // ========================================================================
    //  SafeTokenHandle
    // ========================================================================

    sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeTokenHandle() : base(true) { }
        protected override bool ReleaseHandle()
        {
            try { return NativeMethods.CloseHandle(handle); }
            catch { return false; }
        }
    }

    // ========================================================================
    //  CurrentDesktop
    // ========================================================================

    static class CurrentDesktop
    {
        const int UOI_NAME = 2;

        public static string Detect()
        {
            string winsta = ReadObjectName(NativeMethods.GetProcessWindowStation(), "WinSta0");
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
        const int WTSUserName = 5;
        const int WTSConnectState = 8;

        const int WTSActive = 0;
        const int WTSConnected = 1;
        const int WTSDisconnected = 4;

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

        public static int? GetConnectState(uint sessionId)
        {
            IntPtr pBuf = IntPtr.Zero;
            try
            {
                if (!NativeMethods.WTSQuerySessionInformation(
                        IntPtr.Zero, sessionId, WTSConnectState, out pBuf, out uint bytes))
                    return null;
                if (pBuf == IntPtr.Zero || bytes < 4) return null;
                return Marshal.ReadInt32(pBuf);
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
                    IntPtr pItem = IntPtr.Add(pSessions, (int)(i * (uint)structSize));
                    var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(pItem);

                    if (si.SessionId == 0) continue;
                    if (!IsUserLoggedOn(si.SessionId)) continue;

                    if (si.State == WTSActive)
                        return si.SessionId;
                    if (si.State == WTSConnected && firstConnected == null)
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

        public static string PickDesktopName(uint sessionId)
        {
            int? state = GetConnectState(sessionId);
            if (state == WTSDisconnected)
                return Config.DefaultDesktop;

            return IsUserLoggedOn(sessionId)
                ? Config.DefaultDesktop
                : Config.WinlogonDesktop;
        }

        public static bool HasInteractiveDesktop()
        {
            IntPtr h = NativeMethods.OpenWindowStation("WinSta0", false, 0x0001);
            if (h == IntPtr.Zero) return false;
            NativeMethods.CloseWindowStation(h);
            return true;
        }
    }

    // ========================================================================
    //  PROGRAM
    // ========================================================================

    class Program
    {
        // proadv 新增：Windows 11 的最低内核 build 号
        const int Win11MinBuild = 22000;

        static void Main(string[] args)
        {
            try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { /* ignore */ }

            // pproadv1 新增 [P3]：-y / --yes 非交互确认（与原授权程序 assumeYes 对齐）
            bool autoYes = Array.Exists(args, a =>
                string.Equals(a, "-y", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(a, "--yes", StringComparison.OrdinalIgnoreCase));

            try
            {
                string arg = args.Length > 0 ? args[0].Trim() : "";

                // pproadv1 第二轮审查 [Q5]：--phase2 必须保持为第一个分支（v15 原语义）。
                // 上一版编辑误删了该分支，导致 Win10 Phase1 启动的子进程 "--phase2 ..."
                // 会落入 "Unknown argument" 而使整个流程失效。现恢复。
                if (string.Equals(arg, "--phase2", StringComparison.OrdinalIgnoreCase))
                {
                    ExecutePhase2Logic(args);
                }
                else if (string.Equals(arg, "--grant-privileges", StringComparison.OrdinalIgnoreCase))
                {
                    // proadv 新增（可选入口）：手动执行 LSA 授权流程
                    // pproadv1 第二轮审查 [Q6]：原实现不校验管理员权限；GrantAndCheck 内部
                    // LsaOpenPolicy(POLICY_ALL_ACCESS) 失败时只打印一句错误，用户难以定位根因。
                    // 这里前置显式检查并给出清晰提示（与无参数分支的 IsAdministrator 门禁一致）。
                    if (!IsAdministrator())
                    {
                        Console.WriteLine("[-] ERROR: --grant-privileges 需要以管理员身份运行（LsaOpenPolicy 需要策略写入权限）。");
                        return;
                    }

                    bool ok = PrivilegeGranter.GrantAndCheck(missingOnly: false);
                    // pproadv1 [P3]：非交互模式（-y/--yes）下授权成功后直接自动重启。
                    // proadv2 [R5]：补齐交互式分支——原实现非 -y 时授权成功后从不询问
                    // 重启，与无参数 Win11 分支行为不一致；现同样给出 y/N 询问。
                    if (ok)
                    {
                        if (autoYes)
                        {
                            Console.WriteLine("[*] -y 指定：授权成功，立即重启以生效。");
                            // proadv2 [R2]：RebootNow 成功即退出进程，返回仅代表失败。
                            PrivilegeGranter.RebootNow();
                            Console.WriteLine("[-] 自动重启失败，请手动重启。");
                        }
                        else
                        {
                            Console.WriteLine("\n[*] 授权完成。特权变更需要重启系统后才能写入进程令牌。");
                            Console.Write("是否立即重启计算机？(y/N) ");
                            Console.Out.Flush();
                            string? reboot = SafeReadLine();
                            if (string.Equals(reboot?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                            {
                                PrivilegeGranter.RebootNow();
                                Console.WriteLine("[-] 自动重启失败，请手动重启。");
                            }
                            else
                            {
                                Console.WriteLine("[*] 已跳过自动重启，请手动重启系统。");
                            }
                        }
                    }
                }
                else if (string.Equals(arg, "--check-privileges", StringComparison.OrdinalIgnoreCase))
                {
                    // proadv 新增（可选入口）：仅检查授权状态，不做修改
                    PrivilegeGranter.CheckOnly();
                }
                else if (string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase) || arg == "-h" || arg == "/?")
                {
                    ShowUsage();
                }
                else if (arg == "")
                {
                    if (!IsAdministrator())
                    {
                        Console.WriteLine("[-] ERROR: This program requires administrator privileges.");
                        Console.WriteLine("    Please right-click and 'Run as administrator'.");
                        Console.WriteLine("\nPress any key to exit...");
                        PauseIfInteractive();
                        return;
                    }

                    // ===================== proadv 新增：启动时先做 Windows 版本检查 =====================
                    int build = GetWindowsBuildNumber();
                    Console.WriteLine($"[*] Windows kernel build detected: {build}");

                    if (build >= Win11MinBuild)
                    {
                        Console.WriteLine("[*] Windows 11 or above detected. Running privilege pre-check...");

                        var (missing, checkOk) = PrivilegeGranter.GetMissingPrivileges();

                        if (!checkOk)
                        {
                            Console.WriteLine("[-] 无法读取 LSA 策略中的特权授权状态（枚举失败）。");
                            Console.WriteLine("    请尝试以管理员身份重新运行。");
                            PauseIfInteractive();
                            return;
                        }

                        if (missing.Count > 0)
                        {
                            // 尚未完全授权 → 提示用户需要先授权
                            Console.WriteLine($"[!] 检测到内置 Administrators 还缺少 {missing.Count} 项特权授权。");
                            Console.WriteLine("    在 Windows 11+ 上直接窃取 lsass 令牌不可行，需要先完成授权。");
                            Console.Write("\n是否立即执行授权？(y/N) ");
                            Console.Out.Flush();
                            // pproadv1 [P3]：-y/--yes 或输入被重定向且无数据时，避免阻塞/EOF 异常
                            string? answer = autoYes ? "y" : SafeReadLine();

                            if (string.Equals(answer?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                            {
                                bool ok = PrivilegeGranter.GrantAndCheck(missingOnly: true);
                                if (ok)
                                {
                                    Console.WriteLine("\n[*] 授权完成。特权变更需要重启系统后才能写入进程令牌。");
                                    Console.Write("是否立即重启计算机？(y/N) ");
                                    Console.Out.Flush();
                                    // pproadv1 [P3]：同上，安全读取；默认仍为不重启（N）
                                    string? reboot = autoYes ? "y" : SafeReadLine();
                                    if (string.Equals(reboot?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                                    {
                                        // proadv2 [R2]：RebootNow 成功即退出进程（ExitWindowsEx
                                        // 是异步的，返回 true 后系统随即终止本进程，任何后续输出
                                        // 都会丢失）；因此走到返回值处必然代表失败。
                                        PrivilegeGranter.RebootNow();
                                        Console.WriteLine("[-] 自动重启失败，请手动重启。");
                                    }
                                    else
                                    {
                                        Console.WriteLine("[*] 已跳过自动重启，请手动重启系统。");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[-] 授权过程存在失败项，请查看上方输出。");
                                }
                            }
                            else
                            {
                                Console.WriteLine("[*] 用户拒绝授权，程序退出。");
                            }

                            Console.WriteLine("\n[*] 请在重启后再次运行本程序（将自动跳过 Phase 1 直接执行 Phase 2）。");
                            PauseIfInteractive();
                            return;
                        }
                        else
                        {
                            // 已授权 → 跳过 Phase 1，直接在本进程内执行 Phase 2
                            Console.WriteLine("[+] 特权授权检查通过：所有必需特权均已授予 BUILTIN\\Administrators。");
                            Console.WriteLine("[*] Windows 11+ 快速路径：跳过 Phase 1，直接执行 Phase 2...");
                            ExecutePhase2Logic(new string[] { "--phase2" });
                        }
                    }
                    else
                    {
                        // Win10 及以下：完全保持 v15 原有逻辑
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
                Console.WriteLine($"\n[-] Fatal error: {ex.Message}");
                Console.WriteLine($"    Details: {ex}");
                Console.WriteLine("\nPress any key to exit...");
                PauseIfInteractive();
            }
        }

        // proadv 新增：获取 Windows 内核 build 号（RtlGetVersion，不受 manifest 兼容性垫片影响）
        static int GetWindowsBuildNumber()
        {
            var osver = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf<OSVERSIONINFOEXW>() };
            // pproadv1 第二轮审查 [Q2]：必须同时校验返回值 == STATUS_SUCCESS(0)
            // 且 dwOSVersionInfoSize 被回填为 sizeof(OSVERSIONINFOEXW)。
            // 若结构体布局/尺寸与系统版本不匹配，RtlGetVersion 会返回
            // STATUS_INVALID_INFO_CLASS 且不填充任何字段，此时 dwBuildNumber
            // 保持默认值 0 —— 原实现会把 0 当作合法 build 号而误走 Win10 分支。
            if (NativeMethods.RtlGetVersion(ref osver) == 0
                && osver.dwOSVersionInfoSize == Marshal.SizeOf<OSVERSIONINFOEXW>()
                && osver.dwBuildNumber > 0)
                return osver.dwBuildNumber;

            // 回退：Environment.OSVersion（可能被 manifest 垫片降级）
            try
            {
                int b = Environment.OSVersion.Version.Build;
                if (b > 0) return b;
            }
            catch { /* ignore */ }

            // pproadv1 [Q2]：两条路径都失败时不再静默返回 0（会被误判为 Win10），
            // 而是明确报警，让调用方仍能按保守路径继续但用户知情。
            Console.WriteLine("[!] WARNING: 无法可靠检测 Windows 版本号，按 Win10 及以下流程处理。");
            return 0;
        }

        static void PauseIfInteractive()
        {
            try
            {
                if (!Console.IsInputRedirected)
                    Console.ReadKey(intercept: true);
            }
            catch { /* ignore */ }
        }

        // pproadv1 新增 [P3]：安全读取一行。输入被重定向且已 EOF 时返回 null
        // （调用方按"未同意"处理），避免在无人值守/管道场景下行为不确定。
        static string? SafeReadLine()
        {
            try { return Console.ReadLine(); }
            catch { return null; }
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
            Console.WriteLine("NtCreateToken - TrustedInstaller Token Creator (v16-adv / proadv)");
            Console.WriteLine("====================================================");
            Console.WriteLine("Usage: NtCreateTokenFull.exe [OPTIONS]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  (none)                                Launch SYSTEM child and create TI token");
            Console.WriteLine("  --phase2 [sessionId] [desktopPath]    Execute as SYSTEM (internal use only)");
            Console.WriteLine("  --grant-privileges                    Grant all privileges to BUILTIN\\Administrators via LSA");
            Console.WriteLine("  --check-privileges                    Check LSA privilege grant status only (no changes)");
            Console.WriteLine("  --help                                Show this help message");
            Console.WriteLine();
            Console.WriteLine("Desktop path examples: WinSta0\\Default, WinSta0\\Winlogon");
            Console.WriteLine();
            Console.WriteLine("Requirements:");
            Console.WriteLine("  - Administrator privileges");
            Console.WriteLine("  - Windows 10/11 with Desktop Experience");
            Console.WriteLine("  - .NET 10.0 runtime");
            Console.WriteLine();
            Console.WriteLine("proadv behavior:");
            Console.WriteLine("  - Windows 11+ (build >= 22000): check LSA grants first; if missing, prompt");
            Console.WriteLine("    user to authorize (reboot required afterwards); if already granted,");
            Console.WriteLine("    skip Phase 1 and run Phase 2 directly in-process.");
            Console.WriteLine("  - Windows 10 or below: original v15 flow (Phase 1 -> SYSTEM child -> Phase 2).");
        }

        static void Phase1_LaunchChildProcess()
        {
            Console.WriteLine("=== NtCreateToken [Phase 1: Launch SYSTEM Child] ===\n");
            try
            {
                if (!SessionInfo.HasInteractiveDesktop())
                {
                    Console.WriteLine("  [-] ERROR: No interactive desktop detected.");
                    Console.WriteLine("      This program requires Windows with Desktop Experience");
                    Console.WriteLine("      (Server Core / Nano Server / WinPE are not supported).");
                    throw new InvalidOperationException("No interactive desktop");
                }

                Console.WriteLine("  [*] Enabling SeDebugPrivilege...");
                Privilege.EnableOnProcess("SeDebugPrivilege");
                Console.WriteLine("  [+] SeDebugPrivilege enabled");

                Console.WriteLine("  [*] Enabling SeImpersonatePrivilege...");
                Privilege.EnableOnProcess("SeImpersonatePrivilege");
                Console.WriteLine("  [+] SeImpersonatePrivilege enabled");

                // v15：恢复为仅从 lsass 复制 SYSTEM token
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

                int? connectState = SessionInfo.GetConnectState(activeSession.Value);
                if (connectState == 4)
                {
                    Console.WriteLine($"  [!] Target session {activeSession} is DISCONNECTED (RDP without console).");
                    Console.WriteLine($"      Window will only be visible after the user reconnects.");
                }

                string desktopPath = CurrentDesktop.Detect();
                Console.WriteLine($"  [*] Current desktop detected = {desktopPath}");

                if (string.Equals(desktopPath, Config.DefaultDesktop, StringComparison.OrdinalIgnoreCase)
                    && !SessionInfo.IsUserLoggedOn(activeSession.Value))
                {
                    Console.WriteLine("  [!] No logged-on user; overriding to Winlogon desktop");
                    desktopPath = Config.WinlogonDesktop;
                }

                Console.WriteLine("  [*] Granting SYSTEM desktop access (best-effort)...");
                TryGrantDesktopAccess(WellKnownSids.System, desktopPath);

                Console.WriteLine("\n  [*] Launching SYSTEM child process...");
                ProcessLauncher.LaunchWithToken(
                    systemToken,
                    exePath,
                    $"--phase2 {activeSession.Value} \"{desktopPath}\"",
                    desktopPath);

                Console.WriteLine("\n=== Phase 1 complete. Child process launched. ===");
                Console.WriteLine("Press any key to exit this window...");
                PauseIfInteractive();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[-] Phase 1 Error: {ex.Message}");
                Console.WriteLine($"    Details: {ex}");
                Console.WriteLine("\nPress any key to exit...");
                PauseIfInteractive();
            }
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
            try
            {
                var currentIdentity = WindowsIdentity.GetCurrent();
                string? currentSid = currentIdentity.User?.Value;
                Console.WriteLine($"  [+] Current identity: {currentIdentity.Name} (SID={currentSid})");

                // proadv 修改：移除 v15 的硬性 SYSTEM 检查（原 throw "Phase 2 must run as SYSTEM"），
                // 改为下方的"特权可用性"判定。SYSTEM 子进程路径（Win10）行为不变；
                // Win11+ 快速路径下已授权的管理员进程凭令牌中的特权放行。
                Console.WriteLine("\n  [*] Enabling required privileges (process token)...");

                // proadv 新增：Windows 11+ 快速路径下 Phase 2 直接运行在（已授权的）管理员进程中，
                // 而非 SYSTEM 子进程。若所需特权已通过 LSA 授权写入本进程令牌，则放行；
                // 否则维持 v15 原有的 "Phase 2 must run as SYSTEM" 检查。
                if (!string.Equals(currentSid, WellKnownSids.System, StringComparison.OrdinalIgnoreCase))
                {
                    bool allPrivilegesAvailable = true;
                    foreach (var privName in new[]
                    {
                        WellKnownPrivileges.CreateToken,
                        WellKnownPrivileges.AssignPrimaryToken,
                        WellKnownPrivileges.IncreaseQuota,
                        WellKnownPrivileges.Tcb
                    })
                    {
                        try
                        {
                            Privilege.EnableOnProcess(privName);
                            if (!Privilege.VerifyPrivilege(privName))
                            {
                                allPrivilegesAvailable = false;
                                break;
                            }
                        }
                        catch { allPrivilegesAvailable = false; break; }
                    }

                    if (allPrivilegesAvailable)
                    {
                        Console.WriteLine("  [!] Not SYSTEM, but all required privileges are held and enabled.");
                        Console.WriteLine("      Accepted via Windows 11+ authorized-admin fast path (proadv).");
                    }
                    else
                    {
                        throw new InvalidOperationException(
                            "Phase 2 must run as SYSTEM (or as an Administrator whose token already holds " +
                            "SeCreateToken/SeAssignPrimaryToken/SeIncreaseQuota/SeTcb after the post-grant reboot)");
                    }
                }

                EnableAndVerifyPrivilege(WellKnownPrivileges.CreateToken);
                EnableAndVerifyPrivilege(WellKnownPrivileges.AssignPrimaryToken);
                EnableAndVerifyPrivilege(WellKnownPrivileges.IncreaseQuota);
                EnableAndVerifyPrivilege(WellKnownPrivileges.Tcb);

                uint targetSessionId = ResolveTargetSessionId(args);
                string desktopName = ResolveTargetDesktop(args, targetSessionId);

                Console.WriteLine($"  [*] Target session ID = {targetSessionId}");
                Console.WriteLine($"  [*] Target desktop     = {desktopName}");

                Console.WriteLine("\n  [*] Calling NtCreateToken to create TrustedInstaller token...");

                var groups = BuildGroupList();

                var validPrivileges = new List<(string name, TokenCreator.PrivilegeAttributes attr)>();
                var skippedPrivileges = new List<string>();
                foreach (var name in WellKnownPrivileges.All)
                {
                    if (NativeMethods.LookupPrivilegeValue(null, name, out _))
                        validPrivileges.Add((name, TokenCreator.PrivilegeAttributes.Enabled));
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
                    TimeSpan.FromDays(30));

                Console.WriteLine($"  [+] Token created, handle: 0x{newToken.DangerousGetHandle():X}");
                TokenCreator.SetTokenSessionId(newToken, targetSessionId);
                Console.WriteLine($"  [+] Token Session ID set to {targetSessionId}");

                Console.WriteLine($"  [*] Granting TrustedInstaller desktop access (best-effort)...");
                TryGrantDesktopAccess(WellKnownSids.TrustedInstaller, desktopName);

                Console.WriteLine($"\n  [*] Launching cmd.exe as TrustedInstaller on {desktopName}...");
                ProcessLauncher.Launch(newToken, Config.CmdPath, desktopName);

                Console.WriteLine("\n=== SUCCESS! New cmd.exe running as TrustedInstaller ===");
                PauseIfInteractive();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[-] Phase 2 Error: {ex.Message}");
                Console.WriteLine($"    Details: {ex}");
                throw;
            }
        }

        static uint ResolveTargetSessionId(string[] args)
        {
            uint? active = SessionInfo.FindActiveUserSession();
            if (active != null)
            {
                Console.WriteLine($"  [*] Re-detected active user session = {active}");
                return active.Value;
            }

            if (args.Length >= 2 && uint.TryParse(args[1], out uint parsed))
            {
                Console.WriteLine($"  [*] No active session; using CLI-provided = {parsed}");
                return parsed;
            }

            uint fallback = (uint)Process.GetCurrentProcess().SessionId;
            Console.WriteLine($"  [!] Falling back to current session = {fallback}");
            return fallback;
        }

        static string ResolveTargetDesktop(string[] args, uint sessionId)
        {
            string self = CurrentDesktop.Detect();
            Console.WriteLine($"  [*] Self desktop = {self}");

            if (args.Length >= 3 && !string.IsNullOrWhiteSpace(args[2]))
            {
                string cli = args[2].Trim().Trim('"');
                if (!cli.Contains('\\'))
                    cli = @"WinSta0\" + cli;
                if (!string.Equals(cli, self, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"  [*] CLI override desktop = {cli}");
                    return cli;
                }
            }

            return self;
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
                Console.WriteLine($"  [!] Desktop access grant failed (non-fatal): {ex.Message}");
            }
        }

        static (string sid, TokenCreator.GroupAttributes attr)[] BuildGroupList()
        {
            const TokenCreator.GroupAttributes G = TokenCreator.GroupAttributes.Enabled
                                                  | TokenCreator.GroupAttributes.Mandatory;
            const TokenCreator.GroupAttributes GA = TokenCreator.GroupAttributes.Enabled
                                                  | TokenCreator.GroupAttributes.Mandatory
                                                  | TokenCreator.GroupAttributes.EnabledByDefault;
            const TokenCreator.GroupAttributes GI = TokenCreator.GroupAttributes.Integrity
                                                  | TokenCreator.GroupAttributes.IntegrityEnabled;

            return new (string sid, TokenCreator.GroupAttributes attr)[]
            {
                (WellKnownSids.TrustedInstaller,         G),
                (WellKnownSids.ExtraServiceSid1,         G),
                (WellKnownSids.ExtraServiceSid2,         G),

                (WellKnownSids.BuiltinAdmins,            GA),
                (WellKnownSids.BuiltinUsers,             G),
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

                (WellKnownSids.Everyone,                 G),
                (WellKnownSids.Local,                    G),
                (WellKnownSids.ConsoleLogon,             G),
                (WellKnownSids.CreatorOwner,             G),
                (WellKnownSids.CreatorGroup,             G),
                (WellKnownSids.Dialup,                   G),
                (WellKnownSids.Network,                  G),
                (WellKnownSids.Batch,                    G),
                (WellKnownSids.Interactive,              G),
                (WellKnownSids.Service,                  G),
                (WellKnownSids.Anonymous,                G),
                (WellKnownSids.AuthenticatedUsers,       G),
                (WellKnownSids.System,                   G),
                (WellKnownSids.LocalService,             G),
                (WellKnownSids.NetworkService,           G),

                (WellKnownSids.SystemIntegrity,          GI)
            };
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
        public const string Everyone = "S-1-1-0";
        public const string Local = "S-1-2-0";
        public const string ConsoleLogon = "S-1-2-1";
        public const string CreatorOwner = "S-1-3-0";
        public const string CreatorGroup = "S-1-3-1";

        public const string Dialup = "S-1-5-1";
        public const string Network = "S-1-5-2";
        public const string Batch = "S-1-5-3";
        public const string Interactive = "S-1-5-4";
        public const string Service = "S-1-5-6";
        public const string Anonymous = "S-1-5-7";
        public const string AuthenticatedUsers = "S-1-5-11";
        public const string System = "S-1-5-18";
        public const string LocalService = "S-1-5-19";
        public const string NetworkService = "S-1-5-20";

        public const string BuiltinAdmins = "S-1-5-32-544";
        public const string BuiltinUsers = "S-1-5-32-545";
        public const string BuiltinGuests = "S-1-5-32-546";
        public const string PowerUsers = "S-1-5-32-547";
        public const string AccountOperators = "S-1-5-32-548";
        public const string ServerOperators = "S-1-5-32-549";
        public const string PrintOperators = "S-1-5-32-550";
        public const string BackupOperators = "S-1-5-32-551";
        public const string Replicators = "S-1-5-32-552";
        public const string PreWin2000 = "S-1-5-32-554";
        public const string RemoteDesktopUsers = "S-1-5-32-555";
        public const string NetworkConfigOperators = "S-1-5-32-556";
        public const string IncomingForestTrust = "S-1-5-32-557";
        public const string PerfMonitorUsers = "S-1-5-32-558";
        public const string PerfLogUsers = "S-1-5-32-559";
        public const string WindowsAuthAccessGroup = "S-1-5-32-560";
        public const string TerminalServerLicense = "S-1-5-32-561";
        public const string DistributedComUsers = "S-1-5-32-562";
        public const string IisIusrs = "S-1-5-32-568";
        public const string CryptoOperators = "S-1-5-32-569";
        public const string EventLogReaders = "S-1-5-32-573";
        public const string CertServiceDcomAccess = "S-1-5-32-574";
        public const string RdsRemoteAccessServers = "S-1-5-32-575";
        public const string HyperVAdmins = "S-1-5-32-578";
        public const string AccessControlAssistOps = "S-1-5-32-579";
        public const string StorageReplicaAdmins = "S-1-5-32-582";

        public const string SystemIntegrity = "S-1-16-16384";

        public const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

        public const string ExtraServiceSid1 = "S-1-5-80-3750560858-172214265-3889451188-1914796615-4100997547";
        public const string ExtraServiceSid2 = "S-1-5-80-1913148863-3492436636-2911772495-3404688170-1100133290";
    }

    // ========================================================================
    //  WellKnownPrivileges
    // ========================================================================

    static class WellKnownPrivileges
    {
        public const string AssignPrimaryToken = "SeAssignPrimaryTokenPrivilege";
        public const string CreateToken = "SeCreateTokenPrivilege";
        public const string Impersonate = "SeImpersonatePrivilege";
        public const string DelegateSessionUserImpersonate = "SeDelegateSessionUserImpersonatePrivilege";
        public const string Tcb = "SeTcbPrivilege";

        public const string Audit = "SeAuditPrivilege";
        public const string Security = "SeSecurityPrivilege";
        public const string Backup = "SeBackupPrivilege";
        public const string Restore = "SeRestorePrivilege";
        public const string TakeOwnership = "SeTakeOwnershipPrivilege";
        public const string Relabel = "SeRelabelPrivilege";
        public const string TrustedCredManAccess = "SeTrustedCredManAccessPrivilege";

        public const string Debug = "SeDebugPrivilege";
        public const string LoadDriver = "SeLoadDriverPrivilege";
        public const string LockMemory = "SeLockMemoryPrivilege";
        public const string CreatePagefile = "SeCreatePagefilePrivilege";
        public const string CreatePermanent = "SeCreatePermanentPrivilege";
        public const string CreateGlobal = "SeCreateGlobalPrivilege";
        public const string CreateSymbolicLink = "SeCreateSymbolicLinkPrivilege";
        public const string SystemEnvironment = "SeSystemEnvironmentPrivilege";
        public const string SystemProfile = "SeSystemProfilePrivilege";
        public const string Systemtime = "SeSystemtimePrivilege";
        public const string TimeZone = "SeTimeZonePrivilege";
        public const string Shutdown = "SeShutdownPrivilege";
        public const string RemoteShutdown = "SeRemoteShutdownPrivilege";
        public const string Undock = "SeUndockPrivilege";
        public const string ManageVolume = "SeManageVolumePrivilege";

        public const string IncreaseQuota = "SeIncreaseQuotaPrivilege";
        public const string IncreaseBasePriority = "SeIncreaseBasePriorityPrivilege";
        public const string IncreaseWorkingSet = "SeIncreaseWorkingSetPrivilege";
        public const string ProfileSingleProcess = "SeProfileSingleProcessPrivilege";

        public const string ChangeNotify = "SeChangeNotifyPrivilege";

        public const string EnableDelegation = "SeEnableDelegationPrivilege";
        public const string MachineAccount = "SeMachineAccountPrivilege";
        public const string SyncAgent = "SeSyncAgentPrivilege";

        public static readonly string[] All = new[]
        {
            AssignPrimaryToken, CreateToken, Impersonate, DelegateSessionUserImpersonate, Tcb,
            Audit, Security, Backup, Restore, TakeOwnership, Relabel, TrustedCredManAccess,
            Debug, LoadDriver, LockMemory, CreatePagefile, CreatePermanent, CreateGlobal,
            CreateSymbolicLink, SystemEnvironment, SystemProfile, Systemtime, TimeZone,
            Shutdown, RemoteShutdown, Undock, ManageVolume,
            IncreaseQuota, IncreaseBasePriority, IncreaseWorkingSet, ProfileSingleProcess,
            ChangeNotify,
            EnableDelegation, MachineAccount, SyncAgent
        };
    }

    // ========================================================================
    //  PrivilegeGranter — proadv 新增（LSA "用户权利指派"授权 / 检查 / 重启）
    //  核心逻辑与用户提供的一次性授权程序一致：
    //  - LsaOpenPolicy + LsaEnumerateAccountRights 检查 BUILTIN\Administrators
    //    (S-1-5-32-544) 已拥有的特权；
    //  - LsaAddAccountRights 批量添加缺失特权，失败则逐个回退定位问题；
    //  - EnablePrivilege(SeShutdownPrivilege) + ExitWindowsEx 执行重启。
    //  仅新增/修改本类与 Main/Phase2 中的必要分支，其余 v15 逻辑保持不变。
    // ========================================================================

    static class PrivilegeGranter
    {
        // LSA 策略访问权限
        const uint POLICY_ALL_ACCESS = 0x000F0FFF;

        // NTSTATUS
        const uint STATUS_SUCCESS               = 0x00000000;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
        const uint STATUS_NO_MORE_ENTRIES       = 0x8000001A;

        // 关机/重启标志与原因
        const uint EWX_REBOOT      = 0x00000002;
        const uint EWX_FORCEIFHUNG = 0x00000010;
        const uint SHTDN_REASON_MAJOR_APPLICATION = 0x00040000;
        const uint SHTDN_REASON_MINOR_MAINTENANCE = 0x00000001;
        const uint SHTDN_REASON_FLAG_PLANNED      = 0x80000000;

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
            public int    Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint   Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint LsaOpenPolicy(
            IntPtr SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint LsaEnumerateAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            out IntPtr UserRights,
            out uint CountOfRights);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32.dll")]
        static extern uint LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint LsaFreeMemory(IntPtr buffer);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

        // ---------- 全部要授予的特权（与原授权程序一致，按字母顺序，去重）----------
        static readonly string[] AllPrivileges = new string[]
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

        static LSA_UNICODE_STRING InitLsaString(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            // pproadv1 说明 [P5]：Buffer 用 Marshal.StringToHGlobalUni（UTF-16）分配，
            // Length/MaximumLength 按 Encoding.Unicode 字节数计算 —— 两者语义一致
            // （每个 UTF-16 字符 2 字节），此处复用同一次编码结果做溢出检查，
            // 避免"检查用的字节数"与"实际分配的字节数"来源不同而产生歧义。
            byte[] bytes = Encoding.Unicode.GetBytes(value);
            if (bytes.Length > ushort.MaxValue - 2)
                throw new ArgumentException("字符串过长，无法转换为 LSA_UNICODE_STRING。", nameof(value));

            return new LSA_UNICODE_STRING
            {
                Length        = (ushort)bytes.Length,
                MaximumLength = (ushort)(bytes.Length + 2),
                Buffer        = Marshal.StringToHGlobalUni(value)
            };
        }

        static void FreeLsaString(LSA_UNICODE_STRING lus)
        {
            if (lus.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(lus.Buffer);
        }

        /// <summary>
        /// 获取内置 Administrators 组 SID 的本地内存指针。调用方负责释放。
        /// </summary>
        static IntPtr GetBuiltinAdministratorsSid()
        {
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            IntPtr p = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, p, sidBytes.Length);
            return p;
        }

        /// <summary>
        /// pproadv1 新增 [P4]：共用私有方法 —— 打开 LSA 策略并枚举
        /// BUILTIN\Administrators 现有特权集合。
        /// 原 proadv.cs 中 GetMissingPrivileges 与 GrantAndCheck 各自内联了
        /// 约 90 行完全相同的"LsaOpenPolicy + LsaEnumerateAccountRights"代码，
        /// 此处抽取复用；错误处理语义与原实现一致：
        ///  - 返回 false 表示检查失败（LsaOpenPolicy/枚举出错）；
        ///  - OBJECT_NAME_NOT_FOUND / NO_MORE_ENTRIES 视为空集合（非错误）。
        /// policyHandle / adminSid 以 out 形式返回给调用方继续使用时，
        /// 所有权随之转移，由调用方负责 LsaClose / FreeHGlobal。
        /// </summary>
        static bool TryOpenPolicyAndEnumerateExisting(
            out IntPtr policyHandle,
            out IntPtr adminSid,
            out HashSet<string> existing,
            out string? error)
        {
            policyHandle = IntPtr.Zero;
            adminSid     = IntPtr.Zero;
            existing     = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            error        = null;

            LSA_OBJECT_ATTRIBUTES loa = new LSA_OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>()
            };

            uint status = LsaOpenPolicy(IntPtr.Zero, ref loa, POLICY_ALL_ACCESS, out policyHandle);
            if (status != STATUS_SUCCESS)
            {
                error = "LsaOpenPolicy 失败: 0x" + status.ToString("X8")
                        + " (Win32=" + LsaNtStatusToWinError(status) + ")";
                policyHandle = IntPtr.Zero;
                return false;
            }

            adminSid = GetBuiltinAdministratorsSid();

            // 关键：用临时变量接 out，只有成功才接管指针所有权，
            // 避免对未定义指针调用 LsaFreeMemory（沿用 proadv.cs 的修复写法）。
            IntPtr tempRightsPtr;
            uint   rightsCount;
            status = LsaEnumerateAccountRights(policyHandle, adminSid, out tempRightsPtr, out rightsCount);

            if (status == STATUS_SUCCESS)
            {
                try
                {
                    if (tempRightsPtr != IntPtr.Zero && rightsCount > 0)
                    {
                        int lusSize = Marshal.SizeOf<LSA_UNICODE_STRING>();
                        for (uint i = 0; i < rightsCount; i++)
                        {
                            IntPtr lusPtr = IntPtr.Add(tempRightsPtr, (int)i * lusSize);
                            LSA_UNICODE_STRING lus = Marshal.PtrToStructure<LSA_UNICODE_STRING>(lusPtr);

                            if (lus.Buffer == IntPtr.Zero) continue;

                            string priv = Marshal.PtrToStringUni(lus.Buffer, lus.Length / 2);
                            if (!string.IsNullOrEmpty(priv))
                                existing.Add(priv);
                        }
                    }
                }
                finally
                {
                    if (tempRightsPtr != IntPtr.Zero)
                        LsaFreeMemory(tempRightsPtr);
                }
                return true;
            }
            if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_NO_MORE_ENTRIES)
            {
                // 空集合，什么都不做（与原实现一致）
                return true;
            }

            error = "LsaEnumerateAccountRights 失败: 0x" + status.ToString("X8")
                    + " (Win32=" + LsaNtStatusToWinError(status) + ")";
            // 失败路径：回收本函数分配的资源，调用方无需再释放
            Marshal.FreeHGlobal(adminSid); adminSid = IntPtr.Zero;
            LsaClose(policyHandle);        policyHandle = IntPtr.Zero;
            return false;
        }

        /// <summary>
        /// 用相同于授权程序的逻辑，枚举 BUILTIN\Administrators 在 LSA 策略中缺少的特权。
        /// 返回 (缺失列表, 枚举是否成功)。
        /// </summary>
        public static (List<string> missing, bool checkOk) GetMissingPrivileges()
        {
            var missing = new List<string>();

            // pproadv1 [P4]：改用共用的 EnumerateExistingRights 抽取逻辑
            if (!TryOpenPolicyAndEnumerateExisting(
                    out IntPtr policyHandle, out IntPtr adminSid,
                    out var existing, out string? error))
            {
                Console.WriteLine("  " + error);
                return (missing, false);
            }

            // proadv2 [R4]：本函数只需要"现有特权集合"，不使用写权限句柄/SID。
            // TryOpenPolicyAndEnumerateExisting 的成功路径所有权语义是"由调用方
            // 负责释放"——因此这里必须显式回收（直接丢弃会泄漏 LSA 句柄与 SID 内存），
            // 仅调整释放顺序为"先关句柄后还内存"并更新注释澄清语义；行为等价。
            LsaClose(policyHandle);
            Marshal.FreeHGlobal(adminSid);

            foreach (string priv in AllPrivileges)
                if (!existing.Contains(priv))
                    missing.Add(priv);

            return (missing, true);
        }

        /// <summary>
        /// 一次性批量添加特权。返回原始 NTSTATUS。
        /// </summary>
        static uint TryAddRightsBulk(IntPtr policyHandle, IntPtr sid, List<string> privileges)
        {
            var rights = new LSA_UNICODE_STRING[privileges.Count];
            try
            {
                for (int i = 0; i < privileges.Count; i++)
                    rights[i] = InitLsaString(privileges[i]);
                return LsaAddAccountRights(policyHandle, sid, rights, (uint)rights.Length);
            }
            finally
            {
                for (int i = 0; i < rights.Length; i++)
                    FreeLsaString(rights[i]);
            }
        }

        /// <summary>
        /// 添加单个特权，返回原始 NTSTATUS。
        /// </summary>
        static uint TryAddRightSingle(IntPtr policyHandle, IntPtr sid, string privilege)
        {
            var rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege);
            try
            {
                return LsaAddAccountRights(policyHandle, sid, rights, 1);
            }
            finally
            {
                FreeLsaString(rights[0]);
            }
        }

        /// <summary>
        /// 执行 LSA 授权流程（与原授权程序相同的批量+逐个回退逻辑）。
        /// missingOnly=true 时只添加当前缺失项；false 时先枚举再添加缺失项（结果相同，
        /// 因为目标即"全部拥有"）。返回是否全部添加成功。
        /// </summary>
        public static bool GrantAndCheck(bool missingOnly)
        {
            Console.WriteLine("============================================================");
            Console.WriteLine(" 警告：本操作会把几乎所有高危特权授予内置 Administrators 组。");
            Console.WriteLine(" 这等价于让任何管理员进程获得接近 SYSTEM 的能力。");
            Console.WriteLine(" 仅限隔离测试环境使用，切勿在生产机器运行。");
            Console.WriteLine("============================================================");
            Console.WriteLine();

            // pproadv1 [P4]：枚举现有特权改用共用方法（原约 60 行内联代码删除）
            // proadv2 [R1]：原写法在 try/finally 之前就把 out 直接写进 policyHandle/sid，
            // 若紧接着的托管代码（如 Console.WriteLine）抛异常，finally 尚未进入作用域，
            // LSA 句柄与 SID 内存将永久泄漏。现先取局部副本，进入 try 后再赋给正式变量，
            // 使 finally 覆盖"获取成功之后"的全部路径（正常返回 / return false / 异常）。
            if (!TryOpenPolicyAndEnumerateExisting(
                    out IntPtr newPolicyHandle, out IntPtr newSid,
                    out var existing, out string? error))
            {
                Console.WriteLine(error);
                return false;
            }

            IntPtr policyHandle = IntPtr.Zero;
            IntPtr sid          = IntPtr.Zero;
            try
            {
                // 自此刻起 finally 对句柄/SID 的释放覆盖所有后续路径；
                // 若赋值语句本身（纯指针拷贝，不会抛）之外发生任何异常均已受保护。
                policyHandle = newPolicyHandle;
                sid          = newSid;

                Console.WriteLine("目标: BUILTIN\\Administrators (S-1-5-32-544)");
                Console.WriteLine();
                Console.WriteLine("当前已拥有 " + existing.Count + " 个特权。");
                Console.WriteLine();

                var toAdd = new List<string>();
                foreach (string priv in AllPrivileges)
                {
                    if (existing.Contains(priv))
                        Console.WriteLine("  [已有] " + priv);
                    else
                    {
                        Console.WriteLine("  [缺失] " + priv);
                        toAdd.Add(priv);
                    }
                }
                Console.WriteLine();

                _ = missingOnly; // 目标状态一致：补齐所有缺失项

                if (toAdd.Count == 0)
                {
                    Console.WriteLine("所有目标特权已存在，无需操作。");
                    return true;
                }

                Console.WriteLine("准备添加 " + toAdd.Count + " 个特权...");
                Console.WriteLine();

                int added  = 0;
                int failed = 0;

                uint bulkStatus = TryAddRightsBulk(policyHandle, sid, toAdd);
                if (bulkStatus == STATUS_SUCCESS)
                {
                    foreach (string priv in toAdd)
                        Console.WriteLine("  [成功] " + priv);
                    added = toAdd.Count;
                }
                else
                {
                    Console.WriteLine("  [批量失败 0x" + bulkStatus.ToString("X8")
                                      + " (Win32=" + LsaNtStatusToWinError(bulkStatus)
                                      + ")，回退逐个尝试以定位问题]");
                    Console.WriteLine();

                    foreach (string priv in toAdd)
                    {
                        uint addStatus = TryAddRightSingle(policyHandle, sid, priv);
                        if (addStatus == STATUS_SUCCESS)
                        {
                            Console.WriteLine("  [成功] " + priv);
                            added++;
                        }
                        else
                        {
                            Console.WriteLine("  [失败] " + priv
                                              + "  0x" + addStatus.ToString("X8")
                                              + " (Win32=" + LsaNtStatusToWinError(addStatus) + ")");
                            failed++;
                        }
                    }
                }

                Console.WriteLine();
                Console.WriteLine("添加完成：成功 " + added + " 个，失败 " + failed + " 个。");

                // pproadv1 修复 [P2]：原写法
                //   return failed == 0 && added > 0 || toAdd.Count == 0;
                // 依赖 && / || 优先级（实际语义为 (failed==0 && added>0) || toAdd.Count==0），
                // 可读性差且边界不稳（toAdd.Count==0 分支在上方已提前返回，属死条件）。
                // 改为显式括号 + 授权后闭环校验（verify-after-write）：
                // 重新枚举 LSA 策略，确认所有目标特权确实写入，才判定成功。
                if (failed != 0)
                    return false;

                var (stillMissing, verifyOk) = GetMissingPrivileges();
                if (!verifyOk)
                {
                    Console.WriteLine("[!] 添加调用全部返回成功，但写后校验时无法重新读取 LSA 策略；按成功处理，请重启后再次用 --check-privileges 确认。");
                    return true;
                }
                if (stillMissing.Count != 0)
                {
                    Console.WriteLine("[!] 写后校验发现仍有 " + stillMissing.Count + " 项未生效：");
                    foreach (var m in stillMissing) Console.WriteLine("    - " + m);
                    return false;
                }

                Console.WriteLine("[+] 写后校验通过：所有目标特权均已写入 LSA 策略。");
                return true;
            }
            finally
            {
                if (policyHandle != IntPtr.Zero) LsaClose(policyHandle);
                if (sid          != IntPtr.Zero) Marshal.FreeHGlobal(sid);
            }
        }

        /// <summary>
        /// 仅检查授权状态（不修改），用于 --check-privileges。
        /// </summary>
        public static void CheckOnly()
        {
            var (missing, ok) = GetMissingPrivileges();
            if (!ok)
            {
                Console.WriteLine("[-] 检查失败（见上方错误）。");
                return;
            }
            if (missing.Count == 0)
                Console.WriteLine("[+] 授权状态完好：所有目标特权均已授予 BUILTIN\\Administrators。");
            else
            {
                Console.WriteLine($"[!] 缺少 {missing.Count} 项特权：");
                foreach (var m in missing) Console.WriteLine("    - " + m);
            }
        }

        /// <summary>
        /// 启用 SeShutdownPrivilege 并调用 ExitWindowsEx 重启（与原授权程序的重启逻辑一致）。
        /// </summary>
        public static bool RebootNow()
        {
            try
            {
                Privilege.EnableOnProcess("SeShutdownPrivilege");
            }
            catch (Exception ex)
            {
                Console.WriteLine("警告：无法启用 SeShutdownPrivilege：" + ex.Message);
            }

            uint reason = SHTDN_REASON_MAJOR_APPLICATION
                        | SHTDN_REASON_MINOR_MAINTENANCE
                        | SHTDN_REASON_FLAG_PLANNED;

            // pproadv1 [P6]：先打印最终提示再 Flush，避免 ExitWindowsEx 触发关机后
            // stdout 缓冲区内容丢失（原实现只 Flush 不给任何"正在重启"提示）。
            Console.WriteLine("[*] 正在重启计算机...");
            Console.Out.Flush();

            if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCEIFHUNG, reason))
            {
                Console.WriteLine("ExitWindowsEx 失败: " + Marshal.GetLastPInvokeError());
                return false;
            }

            // proadv2 [R2]：ExitWindowsEx 是异步的——返回 true 仅表示重启请求已被
            // 系统接受，随后本进程即被终止。原实现此时 return true，调用方在返回值
            // 之后打印的任何提示都会因进程被杀而丢失（输出竞态）。现改为成功路径上
            // 不再向调用方交还控制权：直接 Flush 后 Environment.Exit(0)，让语义与
            // 实际行为一致（"返回 false == 重启失败"）。
            Console.Out.Flush();
            try { System.Threading.Thread.Sleep(1500); } catch { /* ignore */ }
            Environment.Exit(0);
            return false; // 不可达：Environment.Exit 已终止进程（仅为满足编译器返回值检查）
        }
    }

    // ========================================================================
    //  DesktopAccess
    // ========================================================================

    static class DesktopAccess
    {
        static readonly int AclSizeInformationSize = Marshal.SizeOf<ACL_SIZE_INFORMATION>();
        const int DACL_SECURITY_INFORMATION = 0x04;
        const uint DEFAULT_ACL_REVISION = 2;
        const uint SECURITY_DESCRIPTOR_REVISION = 1;
        const int AclSizeInformation = 2;
        const uint READ_CONTROL = 0x00020000;
        const uint WRITE_DAC = 0x00040000;
        const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        const uint WINSTA_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | 0x037F;
        const uint DESKTOP_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | 0x01FF;

        const byte ACCESS_ALLOWED_ACE_TYPE = 0x00;
        const byte INHERITED_ACE = 0x10;
        const int ERROR_INSUFFICIENT_BUFFER = 122;

        const int SECURITY_DESCRIPTOR_ALLOC_SIZE = 32;

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
                        $"OpenDesktop('{desktop}') failed");
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
            int siFlag = DACL_SECURITY_INFORMATION;
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
                int siFlag2 = DACL_SECURITY_INFORMATION;
                if (!NativeMethods.GetUserObjectSecurity(handle, ref siFlag2, pSD, sdSize, out _))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetUserObjectSecurity failed");

                if (!NativeMethods.GetSecurityDescriptorDacl(pSD, out bool daclPresent, out IntPtr pDacl, out _))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetSecurityDescriptorDacl failed");

                uint existingAclBytesInUse = 8, existingAceCount = 0;
                uint aclRevision = DEFAULT_ACL_REVISION;

                if (daclPresent && pDacl != IntPtr.Zero)
                {
                    var aclInfo = new ACL_SIZE_INFORMATION();
                    if (!NativeMethods.GetAclInformation(pDacl, ref aclInfo, (uint)AclSizeInformationSize, AclSizeInformation))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetAclInformation failed");
                    existingAclBytesInUse = aclInfo.AclBytesInUse;
                    existingAceCount = aclInfo.AceCount;

                    byte rev = Marshal.ReadByte(pDacl, 0);
                    if (rev > 0) aclRevision = rev;

                    if (HasMatchingAce(pDacl, existingAceCount, pSid, accessMask)) return;
                }

                uint sidLength = NativeMethods.GetLengthSid(pSid);
                uint newAceSize = 8 + sidLength;
                uint newAclSize = existingAclBytesInUse + newAceSize;
                newAclSize = (newAclSize + 3u) & ~3u;

                if (newAclSize > int.MaxValue)
                    throw new Win32Exception($"New ACL size {newAclSize} exceeds int.MaxValue");

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
                                throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetAce failed");
                            uint aceSize = (uint)(ushort)Marshal.ReadInt16(pAce, 2);
                            if (!NativeMethods.AddAce(pNewAcl, aclRevision, 0xFFFFFFFF, pAce, aceSize))
                                throw new Win32Exception(Marshal.GetLastPInvokeError(), "AddAce failed");
                        }
                    }

                    if (!NativeMethods.AddAccessAllowedAce(pNewAcl, aclRevision, accessMask, pSid))
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "AddAccessAllowedAce failed");

                    IntPtr pNewSD = Marshal.AllocHGlobal(SECURITY_DESCRIPTOR_ALLOC_SIZE);
                    try
                    {
                        if (!NativeMethods.InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION))
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "InitializeSecurityDescriptor failed");
                        if (!NativeMethods.SetSecurityDescriptorDacl(pNewSD, true, pNewAcl, false))
                            throw new Win32Exception(Marshal.GetLastPInvokeError(), "SetSecurityDescriptorDacl failed");
                        int siFlag3 = DACL_SECURITY_INFORMATION;
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
                if (!NativeMethods.GetAce(pDacl, i, out IntPtr pAce)) continue;

                uint aceSize = (uint)(ushort)Marshal.ReadInt16(pAce, 2);
                if (aceSize < 8) continue;

                byte aceType = Marshal.ReadByte(pAce, 0);
                if (aceType != ACCESS_ALLOWED_ACE_TYPE) continue;

                byte aceFlags = Marshal.ReadByte(pAce, 1);
                if ((aceFlags & INHERITED_ACE) != 0) continue;

                IntPtr pAceSid = IntPtr.Add(pAce, 8);
                uint sidLen = NativeMethods.GetLengthSid(pAceSid);
                if (aceSize < 8u + sidLen) continue;

                uint aceMask = (uint)Marshal.ReadInt32(pAce, 4);
                if (NativeMethods.EqualSid(pAceSid, pTargetSid) && (aceMask & requiredMask) == requiredMask)
                    return true;
            }
            return false;
        }
    }

    // ========================================================================
    //  TokenThief  — v15：恢复为仅从 lsass 复制 SYSTEM token
    // ========================================================================

    static class TokenThief
    {
        public static int GetLsassPid()
        {
            var procs = Process.GetProcessesByName("lsass");
            if (procs.Length == 0) throw new InvalidOperationException("lsass.exe not found");
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
        const int ERROR_NOT_ALL_ASSIGNED = 1300;

        public static void EnableOnProcess(string privilegeName)
        {
            if (!NativeMethods.OpenProcessToken(
                    NativeMethods.GetCurrentProcess(),
                    TokenConstants.TOKEN_ADJUST_PRIVILEGES | TokenConstants.TOKEN_QUERY,
                    out SafeTokenHandle tok))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "OpenProcessToken failed");

            try
            {
                // proadv2 [R3]：清零必须紧贴真正的 AdjustTokenPrivileges P/Invoke。
                // 原实现把 SetLastPInvokeError(0) 放在包装重载之外，而重载内部先调用
                // LookupPrivilegeValue —— 其成功后 LastError 可能残留非零值；随后真正的
                // AdjustTokenPrivileges P/Invoke 成功时并不改写 LastError（仅失败或
                // ERROR_NOT_ALL_ASSIGNED 时才写），导致调用方读到的可能是上一次无关
                // API 的残留错误码。现把清零下移到包装器内、紧邻底层 P/Invoke 之前。
                if (!NativeMethods.AdjustTokenPrivileges(
                        tok, false, privilegeName, TokenConstants.SE_PRIVILEGE_ENABLED))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to enable {privilegeName}");

                int err = Marshal.GetLastPInvokeError();
                if (err == ERROR_NOT_ALL_ASSIGNED)
                    throw new Win32Exception(err, $"{privilegeName} not held by current process");
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
        static readonly int SecurityQosSize = Marshal.SizeOf<SECURITY_QUALITY_OF_SERVICE>();
        static readonly int ObjectAttributesSize = Marshal.SizeOf<OBJECT_ATTRIBUTES>();
        static readonly int TokenUserSize = Marshal.SizeOf<TOKEN_USER>();
        static readonly int SidAndAttributesSize = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
        static readonly int TokenPrivilegesHeaderSize = Marshal.SizeOf<TOKEN_PRIVILEGES_HEADER>();
        static readonly int LuidAndAttributesSize = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
        static readonly int LargeIntegerSize = Marshal.SizeOf<LARGE_INTEGER>();

        public const uint TOKEN_ALL_ACCESS = 0xF01FF;

        [Flags]
        public enum GroupAttributes : uint
        {
            Mandatory = 1,
            EnabledByDefault = 2,
            Enabled = 4,
            Integrity = 0x20,
            IntegrityEnabled = 0x40
        }

        [Flags]
        public enum PrivilegeAttributes : uint { Enabled = 2 }

        const uint ACL_REVISION = 2;
        const uint GENERIC_ALL = 0x10000000;

        public static void SetTokenSessionId(SafeTokenHandle token, uint sessionId)
        {
            if (!NativeMethods.SetTokenInformation(token, TokenConstants.TokenSessionId, ref sessionId, sizeof(uint)))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "SetTokenInformation failed");
        }

        public static SafeTokenHandle CreatePrimaryToken(
            string userSidString,
            (string sid, GroupAttributes attr)[] groupSids,
            (string name, PrivilegeAttributes attr)[] privileges,
            TimeSpan? expiry)
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
            IntPtr pExpiry = IntPtr.Zero;
            IntPtr[]? daclSidPtrs = null;
            IntPtr[]? sidPtrs = null;

            try
            {
                if (!NativeMethods.ConvertStringSidToSid(userSidString, out sidUser))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "ConvertStringSidToSid (user) failed");

                bufUser = BuildTokenUser(sidUser);
                bufGroups = BuildTokenGroups(groupSids, out sidPtrs);
                bufPrivs = BuildTokenPrivileges(privileges);

                var owner = new TOKEN_OWNER { Owner = sidUser };
                var primaryGroup = new TOKEN_PRIMARY_GROUP { PrimaryGroup = sidUser };

                pDefaultDacl = BuildDefaultDacl(sidUser, out daclSidPtrs);
                var defaultDacl = new TOKEN_DEFAULT_DACL { DefaultDacl = pDefaultDacl };

                var authId = new LUID { LowPart = 0x3e7, HighPart = 0 };

                if (!NativeMethods.AllocateLocallyUniqueId(out var srcId))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "AllocateLocallyUniqueId failed");

                var source = new TOKEN_SOURCE { SourceName = "OptTok", SourceIdentifier = srcId };

                if (expiry.HasValue)
                {
                    var li = new LARGE_INTEGER
                    {
                        QuadPart = DateTime.UtcNow.Add(expiry.Value).ToFileTimeUtc()
                    };
                    pExpiry = Marshal.AllocHGlobal(LargeIntegerSize);
                    Marshal.StructureToPtr(li, pExpiry, false);
                }

                var sqos = new SECURITY_QUALITY_OF_SERVICE
                {
                    Length = SecurityQosSize,
                    ImpersonationLevel = TokenConstants.SecurityImpersonation,
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

                int status = NativeMethods.NtCreateToken(
                    out var hToken,
                    TOKEN_ALL_ACCESS,
                    ref objAttr,
                    TOKEN_TYPE.TokenPrimary,
                    ref authId,
                    pExpiry,
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
                if (bufUser != IntPtr.Zero) Marshal.FreeHGlobal(bufUser);
                if (bufGroups != IntPtr.Zero) Marshal.FreeHGlobal(bufGroups);
                if (bufPrivs != IntPtr.Zero) Marshal.FreeHGlobal(bufPrivs);
                if (pSqos != IntPtr.Zero) Marshal.FreeHGlobal(pSqos);
                if (pDefaultDacl != IntPtr.Zero) Marshal.FreeHGlobal(pDefaultDacl);
                if (pExpiry != IntPtr.Zero) Marshal.FreeHGlobal(pExpiry);

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
            int hdr = (int)Marshal.OffsetOf<TOKEN_GROUPS_LAYOUT>(nameof(TOKEN_GROUPS_LAYOUT.FirstGroup));
            IntPtr buf = Marshal.AllocHGlobal(hdr + SidAndAttributesSize * count);
            sidPtrs = new IntPtr[count];
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

        static IntPtr BuildDefaultDacl(IntPtr sidOwner, out IntPtr[] daclSidPtrs)
        {
            IntPtr sidSystem = IntPtr.Zero, sidAdmins = IntPtr.Zero;
            // pproadv1 修复 [P7]：out 参数类型为非可空 IntPtr[]，null 会触发 CS8625；
            // 改为空数组（语义等价：调用方只遍历/释放其中的 SID 指针）。
            daclSidPtrs = System.Array.Empty<IntPtr>();
            if (!NativeMethods.ConvertStringSidToSid("S-1-5-18", out sidSystem))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "ConvertStringSidToSid SYSTEM failed");
            if (!NativeMethods.ConvertStringSidToSid("S-1-5-32-544", out sidAdmins))
            {
                NativeMethods.LocalFree(sidSystem);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "ConvertStringSidToSid Administrators failed");
            }
            daclSidPtrs = new[] { sidSystem, sidAdmins };

            uint aclSize = 8
                         + (8 + NativeMethods.GetLengthSid(sidSystem))
                         + (8 + NativeMethods.GetLengthSid(sidAdmins))
                         + (8 + NativeMethods.GetLengthSid(sidOwner));
            aclSize = (aclSize + 3u) & ~3u;

            if (aclSize > int.MaxValue)
                throw new Win32Exception($"Default DACL size {aclSize} exceeds int.MaxValue");

            IntPtr pAcl = Marshal.AllocHGlobal((int)aclSize);
            try
            {
                if (!NativeMethods.InitializeAcl(pAcl, aclSize, ACL_REVISION))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "InitializeAcl (DACL) failed");
                if (!NativeMethods.AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, sidSystem))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "AddAccessAllowedAce SYSTEM failed");
                if (!NativeMethods.AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, sidAdmins))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "AddAccessAllowedAce Admins failed");
                if (!NativeMethods.AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, sidOwner))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "AddAccessAllowedAce Owner failed");
                return pAcl;
            }
            catch
            {
                Marshal.FreeHGlobal(pAcl);
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
        static readonly int StartupInfoSize = Marshal.SizeOf<STARTUPINFO>();

        const uint CREATE_NEW_CONSOLE = 0x00000010;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const uint LOGON_WITH_PROFILE = 0x00000001;

        static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        const uint SWP_NOSIZE = 0x0001;
        const uint SWP_NOMOVE = 0x0002;
        const uint SWP_SHOWWINDOW = 0x0040;
        const int TOPMOST_TIMEOUT_MS = 10000;
        const int TOPMOST_POLL_INTERVAL_MS = 50;

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

            if (!NativeMethods.CreateEnvironmentBlock(out IntPtr envBlock, token, false))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "CreateEnvironmentBlock failed");

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
                        ? " (Access denied — likely due to PPL / WDAC / AppLocker on cmd.exe)"
                        : err == 1314
                        ? " (SeAssignPrimaryTokenPrivilege missing)"
                        : "";
                    throw new Win32Exception(err, $"CreateProcessAsUser failed{hint}");
                }
                try
                {
                    Console.WriteLine($"  [+] Process launched (PID={pi.dwProcessId})");
                    MakeWindowTopMost(pi.dwProcessId);
                }
                finally
                {
                    if (pi.hThread != IntPtr.Zero) NativeMethods.CloseHandle(pi.hThread);
                    if (pi.hProcess != IntPtr.Zero) NativeMethods.CloseHandle(pi.hProcess);
                }
            }
            finally
            {
                if (envBlock != IntPtr.Zero) NativeMethods.DestroyEnvironmentBlock(envBlock);
            }
        }

        public static void LaunchWithToken(
            SafeTokenHandle token, string application, string arguments, string desktopName)
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
                if (pi.hThread != IntPtr.Zero) NativeMethods.CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) NativeMethods.CloseHandle(pi.hProcess);
            }
        }

        static void MakeWindowTopMost(uint processId)
        {
            try
            {
                Console.WriteLine("  [*] Waiting for child window to appear...");

                IntPtr hwnd = IntPtr.Zero;
                var deadline = DateTime.UtcNow.AddMilliseconds(TOPMOST_TIMEOUT_MS);

                while (DateTime.UtcNow < deadline)
                {
                    hwnd = FindWindowByProcessId(processId);
                    if (hwnd != IntPtr.Zero) break;
                    Thread.Sleep(TOPMOST_POLL_INTERVAL_MS);
                }

                if (hwnd == IntPtr.Zero)
                {
                    Console.WriteLine("  [!] Could not locate child window by PID; skipping topmost");
                    Console.WriteLine("      (target session may be disconnected, or desktop differs)");
                    return;
                }

                if (!NativeMethods.SetWindowPos(
                        hwnd,
                        HWND_TOPMOST,
                        0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW))
                {
                    Console.WriteLine($"  [!] SetWindowPos failed (err={Marshal.GetLastPInvokeError()})");
                    return;
                }

                Console.WriteLine("  [+] Child window set to TOPMOST");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [!] MakeWindowTopMost error: {ex.Message}");
            }
        }

        static IntPtr FindWindowByProcessId(uint processId)
        {
            IntPtr found = IntPtr.Zero;
            NativeMethods.EnumWindows((hWnd, _) =>
            {
                if (!NativeMethods.IsWindowVisible(hWnd)) return true;
                NativeMethods.GetWindowThreadProcessId(hWnd, out uint pid);
                if (pid == processId)
                {
                    found = hWnd;
                    return false;
                }
                return true;
            }, IntPtr.Zero);
            return found;
        }
    }

    // ========================================================================
    //  NativeMethods
    // ========================================================================

    static class NativeMethods
    {
        // ---- kernel32 ----
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

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
        public static extern bool AdjustTokenPrivileges(
            SafeTokenHandle TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            ref ADJUSTABLE_SINGLE_TOKEN_PRIVILEGES NewState,
            uint BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        // pproadv1 修复 [P1]：原 proadv.cs 中这两个结构体为私有（internal），
        // 但被 public 的 AdjustTokenPrivileges P/Invoke 作为 ref 参数使用，
        // 导致 CS0051 "Inconsistent accessibility" 编译错误（已在沙箱 dotnet build 复现）。
        // 提升为 public 后编译通过，行为不变。
        [StructLayout(LayoutKind.Sequential)]
        public struct SINGLE_LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        public struct ADJUSTABLE_SINGLE_TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public SINGLE_LUID_AND_ATTRIBUTES Privileges;
        }

        public static bool AdjustTokenPrivileges(
            SafeTokenHandle TokenHandle,
            bool DisableAllPrivileges,
            string privilegeName,
            uint Attributes)
        {
            if (!LookupPrivilegeValue(null, privilegeName, out LUID luid))
                throw new Win32Exception(
                    Marshal.GetLastPInvokeError(),
                    $"LookupPrivilegeValue failed: {privilegeName}");

            var tp = new ADJUSTABLE_SINGLE_TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new SINGLE_LUID_AND_ATTRIBUTES { Luid = luid, Attributes = Attributes }
            };

            // proadv2 [R3]：紧邻底层 P/Invoke 清零，保证调用方在返回 true 后
            // GetLastPInvokeError()==0，返回 false 时拿到的是本次真实错误码；
            // ERROR_NOT_ALL_ASSIGNED(1300) 由底层写入，不受影响。
            Marshal.SetLastPInvokeError(0);

            return AdjustTokenPrivileges(
                TokenHandle, DisableAllPrivileges, ref tp,
                (uint)Marshal.SizeOf<ADJUSTABLE_SINGLE_TOKEN_PRIVILEGES>(), IntPtr.Zero, IntPtr.Zero);
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            SafeTokenHandle TokenHandle,
            int TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

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
                uint entrySize = (uint)Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
                if (4u + (ulong)count * entrySize > len) return null;

                int offset = 4;
                for (uint i = 0; i < count; i++)
                {
                    var la = Marshal.PtrToStructure<LUID_AND_ATTRIBUTES>(IntPtr.Add(buf, offset));
                    if (la.Luid.LowPart == luid.LowPart && la.Luid.HighPart == luid.HighPart)
                        return la.Attributes;
                    offset += Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
                }
                return 0;
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

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EqualSid(IntPtr pSid1, IntPtr pSid2);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AllocateLocallyUniqueId(out LUID Luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle,
            int tokenInformationClass,
            ref uint tokenInformation,
            int tokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessAsUser(
            SafeTokenHandle hToken,
            string? lpApplicationName,
            StringBuilder? lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessWithTokenW(
            SafeTokenHandle hToken,
            uint dwLogonFlags,
            string? lpApplicationName,
            StringBuilder lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

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
            IntPtr hObj, ref int pSIRequested, IntPtr pSD, uint nLength, out uint nLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetUserObjectSecurity(IntPtr hObj, ref int pSIRequested, IntPtr pSD);

        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetWindowPos(
            IntPtr hWnd, IntPtr hWndInsertAfter,
            int X, int Y, int cx, int cy, uint uFlags);

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

        // proadv 新增：真实 Windows 版本（不受应用 manifest 兼容性垫片影响）
        [DllImport("ntdll.dll")]
        public static extern int RtlGetVersion(ref OSVERSIONINFOEXW versionInfo);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateToken(
            out SafeTokenHandle TokenHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            TOKEN_TYPE TokenType,
            ref LUID AuthenticationId,
            IntPtr ExpirationTime,
            IntPtr TokenUser,
            IntPtr TokenGroups,
            IntPtr TokenPrivileges,
            ref TOKEN_OWNER TokenOwner,
            ref TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
            ref TOKEN_DEFAULT_DACL TokenDefaultDacl,
            ref TOKEN_SOURCE TokenSource);
    }
}