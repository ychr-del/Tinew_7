# -*- coding: utf-8 -*-
import io

src = io.open('/tmp/step2.cs', encoding='utf-8').read()

def find_one(sub, start=0, end=None):
    i = src.find(sub, start, end)
    if i < 0: raise SystemExit('NOT FOUND: ' + repr(sub[:90]))
    if src.find(sub, i+1, end) >= 0: raise SystemExit('MULTIPLE: ' + repr(sub[:90]))
    return i

edits = []

# ============================================================
# Y1: ExecutePhase2Logic — switch to full LSA account enumeration (before minting token)
a = """                // proadv4 [U2]：动态枚举本机全部服务账户 SID（LSA SeTcbPrivilege 权利指派表），
                // 去重后作为附加组(Enabled)并入令牌 —— 覆盖"任何文件都可操作"的目标：
                // 凡 DACL 授予任意 NT SERVICE\\* 账户的对象，ticmd 均以组成员身份通过检查。
                // 注意：TokenCreator.CoreGroupCount 静态初始化器会先执行 BuildGroupList()，
                // 此处必须复用它返回的同一数组引用并记录长度，保证 BuildTokenGroups 中
                // "核心组 / 附加组"的分界索引与实际数据严格一致。
                var coreGroups = TokenCreator.BuildGroupList();
                var groups = coreGroups.ToList();

                try
                {
                    var existing = new HashSet<string>(
                        groups.Select(g => g.sid), StringComparer.OrdinalIgnoreCase);
                    int addedDynamic = 0;
                    foreach (var sidStr in WellKnownSids.EnumerateServiceAccountSids())
                    {
                        if (existing.Add(sidStr))
                        {
                            groups.Add((sidStr, TokenCreator.GroupAttributes.Enabled));
                            addedDynamic++;
                        }
                    }
                    Console.WriteLine($"  [+] Dynamic service-account SIDs merged into token groups: +{addedDynamic} "
                                    + $"(total groups now {groups.Count})");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] Dynamic service-SID enumeration failed (non-fatal): {ex.Message}");
                }
"""
add = """                // proadv7 [X4]（铸造令牌前先用 LSA API 遍历电脑上所有账户）：
                // proadv4 [U2] 只把 SeTcbPrivilege 权利指派表里的 NT SERVICE\\* 账户并入组列表；
                // 现改为在调用 NtCreateToken *之前* 用 LsaEnumerateAccounts 遍历本机 SAM 中的
                // 全部用户/组别名列/机器账户，并用 LsaEnumerateLeftoverCredentials 补齐
                // UMFD/DUMPD 等虚拟账户桶（详见 WellKnownSids.EnumerateAllAccountSids）。
                // 去重后作为附加组(Enabled)并入令牌 —— 实现"groupsid 保护所有用户和组"：
                // 凡 DACL 授予任意本机账户/组/服务账户的对象，ticmd 均以组成员身份通过检查。
                // 注意：TokenCreator.CoreGroupCount 静态初始化器会先执行 BuildGroupList()，
                // 此处必须复用它返回的同一数组引用并记录长度，保证 BuildTokenGroups 中
                // "核心组 / 附加组"的分界索引与实际数据严格一致。
                var coreGroups = TokenCreator.BuildGroupList();
                var groups = coreGroups.ToList();

                try
                {
                    var existing = new HashSet<string>(
                        groups.Select(g => g.sid), StringComparer.OrdinalIgnoreCase);
                    int addedDynamic = 0;
                    int samAccounts = 0, leftover = 0;
                    // 三个"覆盖全体账户"的特殊别名先行并入（不依赖枚举成功与否）。
                    foreach (var sidStr in new[]
                        {
                            WellKnownSids.ThisOrganizationRep,
                            WellKnownSids.LocalAccountAndMember,
                            WellKnownSids.NtVtmAndVlmLocal
                        })
                    {
                        if (existing.Add(sidStr))
                        {
                            groups.Add((sidStr, TokenCreator.GroupAttributes.Enabled));
                            addedDynamic++;
                        }
                    }
                    foreach (var sidStr in WellKnownSids.EnumerateAllAccountSids(out samAccounts, out leftover))
                    {
                        if (existing.Add(sidStr))
                        {
                            groups.Add((sidStr, TokenCreator.GroupAttributes.Enabled));
                            addedDynamic++;
                        }
                    }
                    Console.WriteLine($"  [+] LSA account walk: SAM accounts={samAccounts}, "
                                    + $"leftover credential SIDs={leftover}, merged +{addedDynamic} "
                                    + $"(total groups now {groups.Count})");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] Dynamic account-SID enumeration failed (non-fatal): {ex.Message}");
                }
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

# ============================================================
# Y2: SetTokenElevationType after SetTokenElevation verification block
a = """                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] SetTokenElevation failed (non-fatal): {ex.Message}");
                }
"""
add = a + """
                // proadv7 新增 [X2]：与 Elevation=1 成对设置 TokenElevationType=Full(3)。
                // 真实提升服务令牌两字段并存；缺失时 whoami /groups 呈现 elevation type: Default，
                // taskkill 的部分令牌比对路径按受限令牌处理。best-effort，失败不影响主流程。
                try
                {
                    TokenCreator.SetTokenElevationType(newToken);
                    Console.WriteLine("  [+] Token ElevationType set to Full (3)");
                    int? et = TokenCreator.VerifyTokenElevationType(newToken);
                    if (et == 3)
                        Console.WriteLine("  [+] ElevationType verified via GetTokenInformation");
                    else if (et.HasValue)
                        Console.WriteLine($"  [!] WARNING: ElevationType read-back = {et} (expected 3)");
                    else
                        Console.WriteLine("  [!] ElevationType read-back unavailable (non-fatal)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] SetTokenElevationType failed (non-fatal): {ex.Message}");
                }
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

# ============================================================
# Y3: SelfCheckToken before desktop grant / launch
a = """                Console.WriteLine($\"  [*] Granting TrustedInstaller desktop access (best-effort)...\");
"""
add = """                // proadv7 新增 [X2]：铸造后、启动子进程前逐项读回 whoami/taskkill 依赖的
                // 关键令牌属性；异常在此处显式暴露，避免子进程里只剩一句"拒绝访问"。
                try { TokenCreator.SelfCheckToken(newToken); }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] Token self-check error (non-fatal): {ex.Message}");
                }

                Console.WriteLine($  \"  [*] Granting TrustedInstaller desktop access (best-effort)...\")
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add.replace("$  \\\"", "$\"")))

# ============================================================
# Y4: --verbose-accounts argument handling + usage text
a = """                else if (string.Equals(arg, "--check-privileges", StringComparison.OrdinalIgnoreCase))
"""
add = """                else if (string.Equals(arg, "--verbose-accounts", StringComparison.OrdinalIgnoreCase))
                {
                    // proadv7 新增 [X4]（可选入口）：仅做 LSA 全账户遍历演练并打印结果，
                    // 不铸造令牌 —— 用于重启授权后预先确认账户枚举管线工作正常。
                    VerboseAccountLog = true;
                    if (!IsAdministrator())
                    {
                        Console.WriteLine("[-] ERROR: --verbose-accounts 需要以管理员身份运行（LsaOpenPolicy 读取账户表）。");
                        return;
                    }
                    try { Privilege.EnableOnProcess(WellKnownPrivileges.Tcb); }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] SeTcbPrivilege 启用失败（非致命，枚举可能不完整）：" + ex.Message);
                    }
                    var sids = WellKnownSids.EnumerateAllAccountSids(out int n1, out int n2);
                    foreach (var s in sids) Console.WriteLine("    · " + s);
                    Console.WriteLine($"[+] Enumerated: SAM accounts={n1}, leftover={n2}, included={sids.Count}");
                }
                else if (string.Equals(arg, "--check-privileges", StringComparison.OrdinalIgnoreCase))
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

a = """            bool autoYes = Array.Exists(args, a =>
                string.Equals(a, "-y", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(a, "--yes", StringComparison.OrdinalIgnoreCase));
"""
add = """            bool autoYes = Array.Exists(args, a =>
                string.Equals(a, "-y", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(a, "--yes", StringComparison.OrdinalIgnoreCase));

            // proadv7 [X4]：--verbose-accounts 也可作为伴随开关出现在其他分支参数之后。
            if (Array.Exists(args, a => string.Equals(a, "--verbose-accounts", StringComparison.OrdinalIgnoreCase)))
                VerboseAccountLog = true;
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

a = """            Console.WriteLine(\"  --check-privileges                    Check LSA privilege grant status only (no changes)\");
"""
add = a + """            Console.WriteLine(\"  --verbose-accounts                    Walk ALL machine accounts via LSA and print (no token)\");
"""
i0 = find_one(a)
edits.append((i0, i0+len(a), add))

for s, e, t in sorted(edits, key=lambda x: -x[0]):
    src = src[:s] + t + src[e:]

io.open('/tmp/step3.cs', 'w', encoding='utf-8').write(src)
print("STEP3 OK, chars:", len(src))
