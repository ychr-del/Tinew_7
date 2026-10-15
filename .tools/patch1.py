# -*- coding: utf-8 -*-
import io

src = io.open('/workspace/proadv6.cs', encoding='utf-8').read()

def find_one(sub, start=0, end=None):
    i = src.find(sub, start, end)
    if i < 0: raise SystemExit('NOT FOUND: ' + sub[:80])
    if src.find(sub, i+1, end) >= 0: raise SystemExit('MULTIPLE: ' + sub[:80])
    return i

edits = []

# E1: TokenConstants additions
a = "        public const int TokenOrigin = 17;\n"
add = a + """
        // proadv7 [X2]：TOKEN_INFORMATION_CLASS 补全（whoami /all 与 taskkill 修复核心）。
        // whoami /all 枚举令牌属性时依次查询 TokenUser(1)/TokenOwner(4)/TokenPrimaryGroup(5)/
        // TokenGroups(6)/TokenPrivileges(3)/TokenDefaultDacl(7)/TokenElevationType(18)。
        // NtCreateToken 手工令牌若缺少这些属性的合法构成（尤其 PrimaryGroup 不在组列表、
        // 组数组错位），内核侧查询即失败，表现为 ticmd 内 whoami "拒绝访问"。这里把全部
        // 相关类别常量显式定义，供铸造后逐项读回校验使用（SetTokenInformation 仅允许
        // SessionId/Elevation/ElevationType/LinkedToken/Origin 五类；其余靠 NtCreateToken 参数保证）。
        public const int TokenUser            = 1;
        public const int TokenOwner           = 4;
        public const int TokenPrimaryGroup    = 5;
        public const int TokenGroups          = 6;
        public const int TokenDefaultDacl     = 7;
        public const int TokenSource          = 8;
        public const int TokenElevationType   = 18;
        public const int TokenAppContainerSid = 31;
"""
edits.append((find_one(a), find_one(a)+len(a), add))

# E2: TOKEN_ELEVATION_TYPE after TOKEN_ELEVATION
a = "    [StructLayout(LayoutKind.Sequential)]\n    struct TOKEN_ELEVATION { public uint TokenIsElevated; }\n"
add = a + """
    // proadv7 [X2]：TOKEN_ELEVATION_TYPE（用于 SetTokenInformation(TokenElevationType=18)）。
    // TokenElevationTypeFull=3 —— 与真实提升服务令牌一致；whoami/groups 的部分代码路径读取
    // 该类型判断 UAC 状态，缺失或为 Default 时会按受限用户呈现组列表。
    enum TOKEN_ELEVATION_TYPE : int { Default = 1, Elevated = 2, ElevatedWithReflection = 3 }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_ELEVATION_TYPE_INFO { public int ElevationType; }
"""
edits.append((find_one(a), find_one(a)+len(a), add))

# E3: SID_AND_ATTRIBUTES Pack=8 -> Sequential
a = "    [StructLayout(LayoutKind.Sequential, Pack = 8)]\n    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }\n"
add = """    // proadv7 [X6]（可优化/正确性）：原声明 Pack=8 —— 在 x86(32 位)运行时下会把
    // Sid/Attributes 之间填充到 8 字节，BuildTokenGroups 写入的组数组与内核期望的
    // SID_AND_ATTRIBUTES{PSID;ACCESS_ATTRIBUTES}（自然对齐，x86=8B/x64=16B）不一致，
    // 导致令牌组全部错位 → whoami 拒绝访问 / taskkill 无法结束任何进程。
    // 本文件其余结构体均为默认自然对齐，此处去掉显式 Pack 与之统一：
    // x64 布局逐字节不变（16B），x86 由畸形 16B 修正为正确的 8B。
    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
"""
edits.append((find_one(a), find_one(a)+len(a), add))

# E4: TOKEN_GROUPS_LAYOUT Pack=8 -> Sequential
a = ("    [StructLayout(LayoutKind.Sequential, Pack = 8)]\n    struct TOKEN_GROUPS_LAYOUT\n"
     "    {\n        public uint GroupCount;\n        public SID_AND_ATTRIBUTES FirstGroup;\n    }\n")
add = """    // proadv7 [X6]：随 SID_AND_ATTRIBUTES 去 Pack 同步改为自然对齐。
    // OffsetOf(FirstGroup) 在 x64 仍为 8、x86 由 8 修正为 4 —— 后者正是 Win32
    // TOKEN_GROUPS{DWORD;SID_AND_ATTRIBUTES[]} 的真实头部大小，组数据从此对齐。
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_GROUPS_LAYOUT
    {
        public uint GroupCount;
        public SID_AND_ATTRIBUTES FirstGroup;
    }
"""
edits.append((find_one(a), find_one(a)+len(a), add))

# E5: WellKnownSids extra coverage SIDs
a = '        public const string ExtraServiceSid2 = "S-1-5-80-1913148863-3492436636-2911772495-3404688170-1100133290";\n'
add = a + """
        // proadv7 [X4]（groupsid 保护所有用户和组）：补充三个"覆盖本机全体账户"的
        // 特殊身份别名。Everyone(S-1-1-0)/CreatorOwner(S-1-3-0)/AuthenticatedUsers
        // (S-1-5-11) 已在核心列表，但 Win10+ 上本地用户令牌的 DACL 命中判定还常见依赖
        // 以下别名（旧版本地令牌兼容组）——并入后 ticmd 对授予"所有本地用户/所有组成员"
        // 的对象同样可达：
        public const string ThisOrganizationRep   = "S-1-5-113"; // 本机组织（此工作站上的本机账户）
        public const string LocalAccountAndMember = "S-1-5-114"; // 本地账户且组成员（Win10+ 本地用户）
        public const string NtVtmAndVlmLocal      = "S-1-5-115"; // 虚拟终端管理器/本地账户
"""
edits.append((find_one(a), find_one(a)+len(a), add))

# E6: replace EnumerateServiceAccountSids block with full LSA enumeration
i0 = find_one("""        // ====================================================================
        //  proadv4 [U2] 动态枚举本机所有服务账户 SID（NT AUTHORITY\\SERVICE-*）""")
end_marker = """            result.Sort(StringComparer.OrdinalIgnoreCase);
            return result;
        }
    }
"""
i1 = find_one(end_marker, i0) + len(end_marker)
new_block = r'''        // ====================================================================
        //  proadv7 [X4]（铸造令牌前先用 LSA API 遍历电脑上所有账户）：
        //  proadv4 [U2] 只枚举了 SeTcbPrivilege 权利指派表中的账户（即
        //  NT SERVICE\* 服务账户，S-1-5-80-*），普通本地用户/组、机器账户、
        //  虚拟账户(UMFD/DUMPD)、其他 LogonSession 桶均不在其列 —— 这正是
        //  "groupsid 没有保护所有用户和组"的缺口。
        //  现改为完整的 LSA 遍历管线（全部走 advapi32 LSA 导出；Phase 2 在
        //  调用 NtCreateToken 之前已启用 SeTcbPrivilege，满足打开策略读账户表的条件）：
        //    LsaOpenPolicy(VIEW | SERVER_SECURITY 回退)
        //      ├ LsaEnumerateAccounts            —— SAM 全部账户（用户/组别名列/机器）
        //      │    ├ LsaLookupSidsEx            —— 批量 SID -> SID_NAME_USE 类型
        //      │    ├ LsaEnumerateAccountRights  —— 每账户的权利名（诊断日志用）
        //      │    └ LsaFreeMemory
        //      └ LsaEnumerateLeftoverCredentials —— 残留凭据桶 SID
        //           （UMFD-0/1、DUMPD-*、LogonIds 等非注册表来源账户，转字符串后直接入组）
        //    汇总过滤规则（安全优先，防 MaxTokenSize 溢出与畸形令牌）：
        //      * 保留：User/Group/Alias/WellKnownGroup/Deleted/Computer/SideloadedGroup 类型；
        //      * 保留：S-1-5-80-*（服务）、S-1-5-21-*（本机/域账户主体）、S-1-5-113/114/115；
        //      * 剔除：强制完整性标签(S-1-16-*)、Invalid/Label/CredentialDomain 类型、
        //              与核心组重复项（OrdinalIgnoreCase 去重，见 ExecutePhase2Logic）。
        //  单个账户解析/权利枚举失败不影响整体；整个函数 best-effort，异常返回空表。
        // ====================================================================
        public static List<string> EnumerateAllAccountSids(out int enumeratedAccounts, out int leftoverSids)
        {
            enumeratedAccounts = 0;
            leftoverSids = 0;
            var result = new List<string>();
            IntPtr policy = IntPtr.Zero;
            IntPtr enumBuf = IntPtr.Zero;
            try
            {
                var oa = new LsaInterop.LSA_OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf<LsaInterop.LSA_OBJECT_ATTRIBUTES>()
                };
                // 先以最小权限 POLICY_VIEW_ONLY 打开；不同 Windows 版本对账户枚举所需
                // 掩码略有差异，失败时回退 POLICY_SERVER_SECURITY（与原 [U2] 容错语义一致）。
                uint status = LsaInterop.LsaOpenPolicy(
                    IntPtr.Zero, ref oa, LsaInterop.POLICY_VIEW_ONLY, out policy);
                if (status != 0 || policy == IntPtr.Zero)
                {
                    policy = IntPtr.Zero;
                    status = LsaInterop.LsaOpenPolicy(
                        IntPtr.Zero, ref oa, LsaInterop.POLICY_SERVER_SECURITY, out policy);
                }
                if (status != 0 || policy == IntPtr.Zero)
                {
                    Console.WriteLine($"  [!] LsaOpenPolicy failed (0x{status:X8}) — dynamic account enumeration skipped");
                    return result;
                }

                uint count = 0;
                status = LsaInterop.LsaEnumerateAccounts(policy, out enumBuf, out count);
                if ((status == 0 || status == LsaInterop.STATUS_NO_MORE_ENTRIES)
                        && enumBuf != IntPtr.Zero && count > 0)
                {
                    // PLSA_ENUMERATION_INFORMATION = PLSA_SID_INFO[]，每项仅一个 PSID。
                    int ptrSize = IntPtr.Size;
                    var sidPtrList = new List<IntPtr>((int)count);
                    for (uint i = 0; i < count; i++)
                    {
                        IntPtr sidPtr = Marshal.ReadIntPtr(IntPtr.Add(enumBuf, (int)(i * ptrSize)));
                        if (sidPtr != IntPtr.Zero) sidPtrList.Add(sidPtr);
                    }
                    enumeratedAccounts = sidPtrList.Count;

                    // 一次性批量解析全部账户的使用类型（lookup 失败则退化为纯前缀过滤）。
                    var opts = new LsaInterop.LSA_LOOKUP_OPTIONS();
                    IntPtr domainsPtr = IntPtr.Zero;
                    IntPtr namesArray = IntPtr.Zero;
                    uint nameCount = 0;
                    bool lookupOk = false;
                    try
                    {
                        if (sidPtrList.Count > 0)
                        {
                            IntPtr[] arr = sidPtrList.ToArray();
                            uint st = LsaInterop.LsaLookupSidsEx(
                                policy, arr, ref opts,
                                out domainsPtr, out namesArray, out nameCount);
                            lookupOk = (st == 0 && nameCount == (uint)sidPtrList.Count
                                        && namesArray != IntPtr.Zero);
                        }
                    }
                    catch { lookupOk = false; }

                    for (int i = 0; i < sidPtrList.Count; i++)
                    {
                        try
                        {
                            string? sidStr = SidUtil.ConvertSidToString(sidPtrList[i]);
                            if (string.IsNullOrEmpty(sidStr)) continue;

                            int useType = -1;
                            string useName = "";
                            if (lookupOk)
                            {
                                IntPtr ent = IntPtr.Add(namesArray, i * LsaInterop.TranslatedSid2EntrySize);
                                useType = Marshal.ReadInt32(ent, LsaInterop.UseTypeOffset);
                                useName = LsaInterop.TranslateSidUseType(useType);
                            }

                            if (!ShouldIncludeEnumeratedSid(sidStr, useType))
                                continue;

                            // 附带一次 LsaEnumerateAccountRights 读取该账户权利名（诊断输出用，
                            // 单账户失败静默跳过 —— 与原 [U2] 容错语义一致）。
                            string rightsHint = TryGetAccountRightsHint(policy, sidPtrList[i]);

                            if (!result.Contains(sidStr, StringComparer.OrdinalIgnoreCase))
                            {
                                result.Add(sidStr);
                                if (Program.VerboseAccountLog)
                                    Console.WriteLine($"      · {sidStr} [{useName}] {rightsHint}");
                            }
                        }
                        catch { /* 单个账户失败不影响整体 */ }
                    }

                    // ReferencedDomains 与 TranslatedNames 出自同一策略内存块，统一释放。
                    if (domainsPtr != IntPtr.Zero) LsaInterop.LsaFreeMemory(domainsPtr);
                }
                if (enumBuf != IntPtr.Zero) { LsaInterop.LsaFreeMemory(enumBuf); enumBuf = IntPtr.Zero; }

                // 残留凭据桶：UMFD-*/DUMPD-*/其他 LogonIds —— 这些 SID 不在 SAM 账户表内，
                // 但真实交互令牌的组列表里常见；并入后 ticmd 对授予它们的 ACL 同样可达。
                IntPtr leftBuf = IntPtr.Zero;
                uint leftCount = 0;
                try
                {
                    if (LsaInterop.LsaEnumerateLeftoverCredentials(policy, out leftBuf, out leftCount) == 0
                            && leftBuf != IntPtr.Zero && leftCount > 0)
                    {
                        leftoverSids = (int)leftCount;
                        int ptrSize = IntPtr.Size;
                        for (uint i = 0; i < leftCount; i++)
                        {
                            IntPtr sidPtr = Marshal.ReadIntPtr(IntPtr.Add(leftBuf, (int)(i * ptrSize)));
                            if (sidPtr == IntPtr.Zero) continue;
                            try
                            {
                                string? sidStr = SidUtil.ConvertSidToString(sidPtr);
                                if (sidStr == null) continue;
                                if (sidStr.StartsWith("S-1-16-", StringComparison.Ordinal)) continue; // 标签桶剔除
                                if (!result.Contains(sidStr, StringComparer.OrdinalIgnoreCase))
                                    result.Add(sidStr);
                            }
                            catch { }
                        }
                    }
                }
                finally
                {
                    if (leftBuf != IntPtr.Zero) LsaInterop.LsaFreeMemory(leftBuf);
                }
            }
            catch { /* best-effort */ }
            finally
            {
                if (enumBuf != IntPtr.Zero) LsaInterop.LsaFreeMemory(enumBuf);
                if (policy != IntPtr.Zero) LsaInterop.LsaClose(policy);
            }
            result.Sort(StringComparer.OrdinalIgnoreCase);
            return result;
        }

        // 兼容旧签名（proadv4 [U2]）：仅返回 S-1-5-80-* 服务账户子集，行为不变。
        public static List<string> EnumerateServiceAccountSids()
        {
            var all = EnumerateAllAccountSids(out _, out _);
            return all.Where(s => s.StartsWith("S-1-5-80-", StringComparison.Ordinal)).ToList();
        }

        // [X4] 过滤规则：哪些枚举到的账户 SID 值得并入令牌组。
        static bool ShouldIncludeEnumeratedSid(string sid, int useType)
        {
            // SID_NAME_USE: 1=User 2=Group 3=Alias 4=WellKnownGroup 5=Deleted 6=Invalid
            //               7=Computer 8=Label 9=CredentialDomain 10=SideloadedGroup
            if (useType >= 0)
            {
                if (useType is not (1 or 2 or 3 or 4 or 5 or 7 or 10))
                    return false; // Label/Invalid/CredentialDomain/Unknown 一律剔除
            }
            // 强制完整性标签绝不作为组 SID。
            if (sid.StartsWith("S-1-16-", StringComparison.Ordinal)) return false;
            // 服务 SID / 本机与域账户主体 / 特殊本地别名无条件保留（即便名称解析失败）。
            if (sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)) return true;
            if (sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) return true;
            if (sid.StartsWith("S-1-5-113", StringComparison.Ordinal)
                || sid.StartsWith("S-1-5-114", StringComparison.Ordinal)
                || sid.StartsWith("S-1-5-115", StringComparison.Ordinal)) return true;
            // 其余（如 S-1-5-32-* 已在核心表、S-1-1-* 等）仅在名称类型有效时保留。
            return useType >= 0;
        }

        // [X4] 单账户权利名摘要（best-effort；失败返回空串）。
        static string TryGetAccountRightsHint(IntPtr policy, IntPtr sid)
        {
            IntPtr rightsPtr = IntPtr.Zero;
            try
            {
                uint status = LsaInterop.LsaEnumerateAccountRights(
                    policy, sid, out rightsPtr, out uint rc);
                if (status != 0 || rightsPtr == IntPtr.Zero || rc == 0) return "";
                int lusSize = Marshal.SizeOf<LsaInterop.LSA_UNICODE_STRING>();
                var names = new List<string>(Math.Min((int)rc, 8));
                for (uint i = 0; i < rc && names.Count < 8; i++)
                {
                    var lus = Marshal.PtrToStructure<LsaInterop.LSA_UNICODE_STRING>(
                        IntPtr.Add(rightsPtr, (int)i * lusSize));
                    if (lus.Buffer != IntPtr.Zero && lus.Length > 0)
                        names.Add(Marshal.PtrToStringUni(lus.Buffer, lus.Length / 2) ?? "");
                }
                return names.Count == 0 ? "" : "(" + string.Join(",", names) + ")";
            }
            catch { return ""; }
            finally { if (rightsPtr != IntPtr.Zero) LsaInterop.LsaFreeMemory(rightsPtr); }
        }
    }
'''
edits.append((i0, i1, new_block))

# E7: LsaInterop additions before MakeUnicodeString doc comment
a = '        /// <summary>构造指向托管字符串的 LSA_UNICODE_STRING（调用方负责 FreeHGlobal）。</summary>\n'
i0 = find_one(a)
add = '''        // ====================================================================
        //  proadv7 [X4] 新增：完整账户遍历所需的 LSA P/Invoke 最小子集
        //  （LsaEnumerateAccounts / LsaLookupSidsEx / LsaEnumerateAccountRights /
        //   LsaEnumerateLeftoverCredentials；均为 advapi32 原生导出。）
        // ====================================================================
        public const uint POLICY_SERVER_SECURITY = 0x00000006; // 备用打开权限掩码

        // LSA_LOOKUP_OPTIONS（ntsecapi.h）：本机枚举用默认值即可，字段布局保持与原生一致。
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_LOOKUP_OPTIONS
        {
            public uint LookupOptions;       // LSA_LOOKUP_OPTION_*（0 = 默认）
            public uint ExtendedLookupFlags;
            public long ServerTimeout_ms;    // LARGE_INTEGER
            public uint Context;
        }

        // PLSA_TRANSLATED_SID2 单项：{SID_NAME_USE Use; LSA_UNICODE_STRING Name; ULONG RelativeId; LONG Reserved}
        // 结构大小经 Marshal.SizeOf 推导而非硬编码，避免平台误判。
        [StructLayout(LayoutKind.Sequential)]
        public struct TranslatedSid2
        {
            public int Use;                          // SID_NAME_USE（首字段，偏移 0）
            public LSA_UNICODE_STRING Name;
            public uint RelativeId;
            public int Reserved;
        }

        public static readonly int TranslatedSid2EntrySize = Marshal.SizeOf<TranslatedSid2>();
        public const int UseTypeOffset = 0;          // Use 是结构体首字段

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaEnumerateAccounts(
            IntPtr PolicyHandle, out IntPtr EnumerationBuffer, out uint CountReturned);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaEnumerateAccountRights(
            IntPtr PolicyHandle, IntPtr AccountSid,
            out IntPtr UserRights, out uint CountOfRights);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaEnumerateLeftoverCredentials(
            IntPtr PolicyHandle, out IntPtr EnumerationBuffer, out uint CountReturned);

        // LsaLookupSidsEx(POLICE_HANDLE, PLSA_SID_INFO*, ULONG, PLSA_LOOKUP_OPTIONS*,
        //                 PLSA_REFERENCED_DOMAIN_LIST**, PLSA_TRANSLATED_SID2**, PULONG)
        // —— 原生第 2 参是 PLSA_SID_INFO 数组（每项恰为一个 PSID），与临时打包缓冲逐字节一致。
        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "LsaLookupSidsEx")]
        private static extern uint LsaLookupSidsExNative(
            IntPtr PolicyHandle,
            IntPtr SidInfoArray,
            uint SidCount,
            ref LSA_LOOKUP_OPTIONS LookupOptions,
            out IntPtr ReferencedDomains,
            out IntPtr TranslatedNames,
            out uint NameCount);

        // 托管友好包装：把 PSID 列表打包成 PLSA_SID_INFO 临时数组再调用原生函数。
        public static uint LsaLookupSidsEx(
            IntPtr policy, IntPtr[] sids, ref LSA_LOOKUP_OPTIONS opts,
            out IntPtr referencedDomains, out IntPtr translatedNames, out uint nameCount)
        {
            referencedDomains = IntPtr.Zero;
            translatedNames = IntPtr.Zero;
            nameCount = 0;
            if (sids.Length == 0) return 0xC0000001; // STATUS_UNSUCCESSFUL（调用方按 lookup 失败处理）

            IntPtr sidArr = Marshal.AllocHGlobal(IntPtr.Size * sids.Length);
            try
            {
                for (int i = 0; i < sids.Length; i++)
                    Marshal.WriteIntPtr(sidArr, i * IntPtr.Size, sids[i]);

                return LsaLookupSidsExNative(
                    policy, sidArr, (uint)sids.Length, ref opts,
                    out referencedDomains, out translatedNames, out nameCount);
            }
            finally { Marshal.FreeHGlobal(sidArr); }
        }

        public static string TranslateSidUseType(int use) => use switch
        {
            1 => "User", 2 => "Group", 3 => "Alias", 4 => "WellKnownGroup",
            5 => "Deleted", 6 => "Invalid", 7 => "Computer", 8 => "Label",
            9 => "CredentialDomain", 10 => "SideloadedGroup", _ => "Unknown"
        };

'''
edits.append((i0, i0, add))

# E8: Program.VerboseAccountLog flag
a = "        // proadv 新增：Windows 11 的最低内核 build 号\n        const int Win11MinBuild = 22000;\n"
add = a + """
        // proadv7 [X4]：动态账户枚举的逐行诊断开关（默认关闭，--verbose-accounts 打开）。
        public static bool VerboseAccountLog = false;
"""
edits.append((find_one(a), find_one(a)+len(a), add))

for s, e, t in sorted(edits, key=lambda x: -x[0]):
    src = src[:s] + t + src[e:]

io.open('/tmp/step1.cs', 'w', encoding='utf-8').write(src)
print("STEP1 OK, chars:", len(src))
