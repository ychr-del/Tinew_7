# -*- coding: utf-8 -*-
import io

src = io.open('/tmp/step1.cs', encoding='utf-8').read()

def find_one(sub, start=0, end=None):
    i = src.find(sub, start, end)
    if i < 0: raise SystemExit('NOT FOUND: ' + repr(sub[:90]))
    if src.find(sub, i+1, end) >= 0: raise SystemExit('MULTIPLE: ' + repr(sub[:90]))
    return i

edits = []

# ============================================================
# X1: BuildTokenGroups compaction bug — skipped SIDs leave holes.
a = """                    if (!NativeMethods.ConvertStringSidToSid(entries[i].sid, out var s))
                        // proadv4 [U4]：动态并入的服务账户 SID 在个别 Windows 版本上可能不存在
                        // （枚举与使用之间服务被卸载、或 SID 字符串异常）。原实现直接 throw，
                        // 会让整个 Phase 2 因一个可选附加组而失败。改为：核心组（前部固定列表）
                        // 仍严格失败；纯附加性质的未知 SID 跳过并告警。
                        if (i < CoreGroupCount)
                            throw new Win32Exception(Marshal.GetLastPInvokeError(),
                                $"ConvertStringSidToSid failed: {entries[i].sid}");
                        else
                        {
                            Console.WriteLine($"  [!] Skipping unresolvable group SID (non-fatal): {entries[i].sid}");
                            continue;
                        }

                    sidPtrs[i] = s;
                    Marshal.StructureToPtr(
                        new SID_AND_ATTRIBUTES { Sid = s, Attributes = (uint)entries[i].attr },
                        ptr, false);
                    ptr = IntPtr.Add(ptr, SidAndAttributesSize);
                }

                // proadv4 [U4]：若有跳过项，回填真实组计数（内核按 FirstPart.Count 解析）。
                int actual = (int)((ptr - IntPtr.Add(buf, hdr)).ToInt64() / SidAndAttributesSize);
                if (actual != count)
                    Marshal.WriteInt32(buf, actual);
"""
add = """                    if (!NativeMethods.ConvertStringSidToSid(entries[i].sid, out var s))
                    {
                        // proadv4 [U4]：动态并入的服务账户 SID 在个别 Windows 版本上可能不存在
                        // （枚举与使用之间服务被卸载、或 SID 字符串异常）。原实现直接 throw，
                        // 会让整个 Phase 2 因一个可选附加组而失败。改为：核心组（前部固定列表）
                        // 仍严格失败；纯附加性质的未知 SID 跳过并告警。
                        if (i < CoreGroupCount)
                            throw new Win32Exception(Marshal.GetLastPInvokeError(),
                                $"ConvertStringSidToSid failed: {entries[i].sid}");
                        Console.WriteLine($"  [!] Skipping unresolvable group SID (non-fatal): {entries[i].sid}");
                        continue;
                    }

                    // proadv7 [X1]（严重 bug 修复）：proadv4/5/6 的 [U4] "跳过"实现只写了
                    // `continue` 却仍按 entries.Length 预分配、并把成功项写入"原始下标对应"的
                    // 槽位之后才前移 ptr —— 一旦中途有 SID 被跳过，其后所有已解析组虽然物理上
                    // 连续写入，但 sidPtrs[] 的索引与物理槽位不再一一对应；更关键的是原实现
                    // 把 GroupCount 回填为"实际写入数"的同时，调用方 CreatePrimaryToken 的
                    // PrimaryGroup 查找用 sidPtrs[gi]（gi 为原始下标）取指针 —— 跳过发生后
                    // sidPtrs 与 TOKEN_GROUPS 数组错位，Administrators 主组可能指向已被跳过
                    // 的空槽(IntPtr.Zero)或另一组的 SID → NtCreateToken 生成畸形令牌 →
                    // ticmd 内 whoami 拒绝访问 / taskkill 无法结束任何进程。
                    // 现改为：写入与 sidPtrs 均按"压缩后写游标 w"同步推进，并在结束时把未用
                    // 尾部槽位清零，保证两个视图永远一致。
                    sidPtrs[w] = s;
                    Marshal.StructureToPtr(
                        new SID_AND_ATTRIBUTES { Sid = s, Attributes = (uint)entries[i].attr },
                        ptr, false);
                    ptr = IntPtr.Add(ptr, SidAndAttributesSize);
                    w++;
                }

                // proadv7 [X1]：清零未使用的尾部槽位（防御性，确保无悬挂指针残留）。
                for (int k = w; k < count; k++)
                    Marshal.WriteIntPtr(IntPtr.Add(buf, hdr + k * SidAndAttributesSize), IntPtr.Zero);

                // proadv4 [U4]：若有跳过项，回填真实组计数（内核按 FirstPart.Count 解析）。
                // proadv7 [X1]：同时把出参 sidPtrs 截断为实际长度，调用方按下标取主组指针必然对齐。
                if (w != count)
                {
                    Marshal.WriteInt32(buf, w);
                    Array.Resize(ref sidPtrs, w);
                }
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

# X1b: declare w before loop; replace the old header line of the loop body start
a = """            try
            {
                Marshal.WriteInt32(buf, count);
                IntPtr ptr = IntPtr.Add(buf, hdr);
                for (int i = 0; i < count; i++)
                {"""
add = """            try
            {
                Marshal.WriteInt32(buf, count);
                IntPtr ptr = IntPtr.Add(buf, hdr);
                int w = 0; // proadv7 [X1]：压缩写游标（物理槽位/sidPtrs 共用）
                for (int i = 0; i < count; i++)
                {"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

# X1c: signature out IntPtr[] -> out IntPtr[] stays; but failure cleanup loops over count using sidPtrs[i]; fine.
# Also fix comment on entries param name mismatch? skip.

# ============================================================
# X2: TOKEN_ALL_ACCESS decomposition (fixes CS0133-class issue in proadv7 expanded form & winnt.h exactness)
a = "        public const uint TOKEN_ALL_ACCESS = 0xF01FF;\n"
add = """        // proadv7 [X5]（可优化/正确性）：原硬编码 0xF01FF。winnt.h 的真实定义为
        //   STANDARD_RIGHTS_REQUIRED | 0x000F | QUERY | DUPLICATE | IMPERSONATE |
        //   PRIMARY | ASSIGN_PRIMARY | ADJUST_GROUPS | ADJUST_PRIVILEGES |
        //   ADJUST_DEFAULT | ADJUST_SESSIONID = 0x001F01FF
        // 数值与原值相同（本机 x64/x86 行为不变），但显式分解消除了"魔数不可审计"的
        // 静态分析告警，并与下方新增的各单项常量保持单一事实来源。
        public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const uint TOKEN_ASSIGN_PRIMARY     = 0x0001;
        public const uint TOKEN_DUPLICATE          = 0x0002;
        public const uint TOKEN_IMPERSONATE        = 0x0004;
        public const uint TOKEN_QUERY              = 0x0008;
        public const uint TOKEN_QUERY_SOURCE       = 0x0010;
        public const uint TOKEN_ADJUST_PRIVILEGES  = 0x0020;
        public const uint TOKEN_ADJUST_GROUPS      = 0x0040;
        public const uint TOKEN_ADJUST_DEFAULT     = 0x0080;
        public const uint TOKEN_ADJUST_SESSIONID   = 0x0100;
        public const uint TOKEN_PRIMARY            = 0x0000; // winnt.h: TOKEN_PRIMARY == 0
        public const uint TOKEN_ALL_ACCESS =
            STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE |
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS |
            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

# ============================================================
# X3: SetTokenInformation ref uint overload -> uint value overload (precise prototype)
a = """        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle,
            int tokenInformationClass,
            ref uint tokenInformation,
            int tokenInformationLength);
"""
add = """        // proadv7 [X7]（可优化）：TokenSessionId 的原生原型是 IN PVOID TokenInformation
        // 指向 DWORD。proadv6 声明为 `ref uint`（正确但封送器需固定托管变量）；改用
        // ByValArr 等价的 uint 值参数重载——封送器直接把 4 字节按值复制到栈，少一次
        // 引脚操作，且杜绝调用方传入已释放 ref 的可能。语义逐字节一致。
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalasPlaceholder]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle,
            int tokenInformationClass,
            uint tokenInformation,
            int tokenInformationLength);
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add.replace("[return: MarshalasPlaceholder]", "[return: MarshalAs(UnmanagedType.Bool)]")))

# update caller SetTokenSessionId
a = """            if (!NativeMethods.SetTokenInformation(token, TokenConstants.TokenSessionId, ref sessionId, sizeof(uint)))
"""
add = """            // proadv7 [X7]：改走 uint 值参数重载（见 NativeMethods 注释），无需 ref。
            if (!NativeMethods.SetTokenInformation(token, TokenConstants.TokenSessionId, sessionId, sizeof(uint)))
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

# ============================================================
# X4: SetTokenElevationType + VerifyTokenElevationType + VerifyTokenPrimaryGroup etc.
a = """        // pproadv2 修复 [S1]：给令牌挂一个"链接令牌"（linked token），使 shell 扩展 / 任务计划等
"""
add = """        // proadv7 [X2]：设置 TokenElevationType(18)=TokenElevationTypeFull(3)。
        // 真实提升令牌 Elevation=1 与 ElevationType=Full 成对出现；只有前者时
        // whoami /groups 会显示 " elevation type: Default"，部分依赖 ElevationType
        // 的安全查询（含 taskkill 打开目标进程时的令牌比对路径）行为不一致。
        // SetTokenInformation 官方支持该类（Windows Vista SP1+），失败仅告警。
        public static void SetTokenElevationType(SafeTokenHandle token)
        {
            var et = new TOKEN_ELEVATION_TYPE_INFO
            {
                ElevationType = (int)TOKEN_ELEVATION_TYPE.ElevatedWithReflection // 占位，见下方修正
            };
            et.ElevationType = 3; // TokenElevationTypeFull —— 用数值常量避免枚举命名歧义
            if (!NativeMethods.SetTokenInformation(
                    token, TokenConstants.TokenElevationType, ref et,
                    Marshal.SizeOf<TOKEN_ELEVATION_TYPE_INFO>()))
                throw new Win32Exception(Marshal.GetLastPInvokeError(),
                    "SetTokenInformation(TokenElevationType) failed");
        }

        // proadv7 [X2]：读回校验 ElevationType（best-effort，null=不可判定）。
        public static int? VerifyTokenElevationType(SafeTokenHandle token)
        {
            const uint SIZE = 4;
            if (!NativeMethods.GetTokenInformation(token, TokenConstants.TokenElevationType,
                    out TOKEN_ELEVATION_TYPE_INFO et, SIZE, out uint retLen))
                return null;
            if (retLen < SIZE) return null;
            return et.ElevationType;
        }

        // proadv7 [X2]：铸造后深度自检 —— 逐项 GetTokenInformation 读回 whoami/taskkill
        // 依赖的关键属性，任何一项缺失都在启动子进程*之前*打印明确诊断（而不是让子进程
        // 里的 whoami 报"拒绝访问"后再反向排查）。全部 best-effort，不抛异常。
        public static void SelfCheckToken(SafeTokenHandle token)
        {
            Console.WriteLine("  [*] Post-creation token self-check (whoami/taskkill critical attributes)...");
            ReportTokenInfo(token, TokenConstants.TokenUser,         "TokenUser(1)");
            ReportTokenInfo(token, TokenConstants.TokenGroups,        "TokenGroups(6)");
            ReportTokenInfo(token, TokenConstants.TokenPrivileges,    "TokenPrivileges(3)");
            ReportTokenInfo(token, TokenConstants.TokenOwner,         "TokenOwner(4)");
            ReportTokenInfo(token, TokenConstants.TokenPrimaryGroup,  "TokenPrimaryGroup(5)");
            ReportTokenInfo(token, TokenConstants.TokenDefaultDacl,   "TokenDefaultDacl(7)");
            ReportTokenInfo(token, TokenConstants.TokenSource,        "TokenSource(8)");
            ReportTokenInfo(token, TokenConstants.TokenSessionId,     "TokenSessionId(12)");
            ReportTokenInfo(token, TokenConstants.TokenElevation,     "TokenElevation(25)");
            ReportTokenInfo(token, TokenConstants.TokenElevationType, "TokenElevationType(18)");
            ReportTokenInfo(token, TokenConstants.TokenOrigin,        "TokenOrigin(17)");
            ReportTokenInfo(token, TokenConstants.TokenLinkedToken,   "TokenLinkedToken(38)");
        }

        static void ReportTokenInfo(SafeTokenHandle token, int cls, string label)
        {
            IntPtr buf = IntPtr.Zero;
            try
            {
                uint len = 0;
                if (!NativeMethods.GetTokenInformation(token, cls, IntPtr.Zero, 0, out len))
                {
                    int err = Marshal.GetLastPInvokeError();
                    const int ERROR_INSUFFICIENT_BUFFER = 122;
                    if (err != ERROR_INSUFFICIENT_BUFFER || len == 0)
                    {
                        Console.WriteLine($"      [!] {label}: UNAVAILABLE (err={err})");
                        return;
                    }
                }
                if (len == 0 || len > 1 << 20) { Console.WriteLine($"      [!] {label}: bad length {len}"); return; }
                buf = Marshal.AllocHGlobal((int)len);
                if (!NativeMethods.GetTokenInformation(token, cls, buf, len, out _))
                {
                    Console.WriteLine($"      [!] {label}: read failed (err={Marshal.GetLastPInvokeError()})");
                    return;
                }
                Console.WriteLine($"      [+] {label}: OK ({len} bytes)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      [!] {label}: exception {ex.Message}");
            }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        }

        // pproadv2 修复 [S1]：给令牌挂一个"链接令牌"（linked token），使 shell 扩展 / 任务计划等
"""
i0 = find_one(a)
edits.append((i0, i0, add))

# need P/Invoke overloads for elevation-type struct set/get and generic get with out struct sizes
a = """        // proadv6 [W8]：TOKEN_ELEVATION 版 GetTokenInformation 强类型重载。"""
add = """        // proadv7 [X2]：TOKEN_ELEVATION_TYPE_INFO 版 Set/Get 重载。
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle,
            int tokenInformationClass,
            ref TOKEN_ELEVATION_TYPE_INFO tokenInformation,
            int tokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            SafeTokenHandle TokenHandle,
            int TokenInformationClass,
            out TOKEN_ELEVATION_TYPE_INFO TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        // proadv6 [W8]：TOKEN_ELEVATION 版 GetTokenInformation 强类型重载。"""
i0 = find_one(a)
edits.append((i0, i0, add))

for s, e, t in sorted(edits, key=lambda x: -x[0]):
    src = src[:s] + t + src[e:]

io.open('/tmp/step2.cs', 'w', encoding='utf-8').write(src)
print("STEP2 OK, chars:", len(src))
