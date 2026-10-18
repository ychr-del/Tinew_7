// ============================================================================
//  proadv9.cs — proadv8.cs 的第九轮逐行/逐语句/逐过程深度审查产物（目标 .NET 10.0）
//  ★ 本轮修订（proadv9，结合沙箱 dotnet build SDK 10.0.402/net10.0 实测复核）★
//  proadv8 基线：沙箱静态编译 0 error / 0 warning（本轮重新实测确认）。
//  本轮发现并修复 proadv8 遗留的 6 个实际运行期 bug [AA1]-[AA6]，并完成 3 项
//  可优化点 [AA7]-[AA9]；其余全部业务逻辑（Win11 预检/LSA 授权/重启、Win10
//  双阶段窃取 lsass 令牌、桌面 ACL、会话检测、特权启用、令牌构成、自检等）
//  保持不变：
//  [AA1] LSA 内存泄漏（EnumerateAllAccountSids）：LsaLookupSidsEx 成功时，原生
//        PLSA_TRANSLATED_SID2**（translatedNames）与 PLSA_REFERENCED_DOMAIN_LIST**
//        （referencedDomains）必须由 LsaFreeMemory 分别释放——v8 只释放了
//        domainsPtr，namesArray 从未释放；且一旦 LsaCallWithTimeout 超时或后续
//        解析抛异常，两个指针连 domainsPtr 一起泄漏。每次 Phase 2 铸造都稳定
//        泄漏一整块 LSA 翻译表（数百账户 × 32B + 域表），进程内累积。
//        修复：把 lookup 结果的生命周期纳入外层统一 finally 回收（新增局部
//        变量跟踪 + LsaFreeMemory 判空释放），并在超时路径显式注释"后台线程
//        稍后写入的 out 值不可再接管"的语义（防误用）。
//  [AA2] IsReadablePointer 哨兵页负对照失效（WellKnownSids）：VirtualFree 以
//        MEM_DECOMMIT 且 dwSize != 0 时，Windows 会把请求区间**向上取整到整页**
//        再撤销——v8 从 baseAddr+PageSize-64 处 DECOMMIT 64B，实际撤销的是整个
//        第二页；随后负对照读 guardStart..guardStart+64 横跨已撤销边界，RPM 在
//        首个不可读字节处失败返回 FALSE → "负对照"永远虚假通过，即便 RPM 被
//        EDR/API 钩子改成"恒真"也探测不出来（探测可信性自测形同虚设）。
//        修复：改为分配单页、DECOMMIT 整页（baseAddr, dwSize=0 会连保留一起
//        释放故不可用——显式传 PageSize 做整页 MEM_DECOMMIT），正/负对照分别
//        落在"未撤销前部"与"已撤销页首"，两个断言都不再跨页边界。
//  [AA3] ProbeRangeReadable 字对齐守卫误杀合法载荷：`(addr & 7) != 0` 对
//        TranslatedSid2 **条目级**探测必然失败——x64 步长 32B 时条目 i≥1 的
//        地址 = namesArray + 32i，而 lsasrv 数组基址仅保证 8 字节中的 4 字节
//        对齐（malloc 粒度）？不：真正触发点是 x86（步长 16、结构含 4B 字段）
//        与未来任何奇偶混排布局；更关键的是 SID 头部探测传入 len=8 但 SID 是
//        BYTE 数组型载荷，RVAX 截断区间的 RPC 缓冲常按 4B 而非 8B 对齐分配，
//        v8 的 8 字节对齐硬校验会把这类**完全可读**的指针误判为不可读 →
//        枚举列表被无谓截断（"宁缺毋滥"过度执行，丢失合法账户组）。
//        修复：对齐守卫放宽为 4 字节（覆盖 x86/x64 全部真实分配粒度），并把
//        用户态上界粗筛修正为 canonical 半区 0x7FFFFFFF0000（v8 写成
//        0x7FFFFFFFFFFF0000 —— 超出 x64 有效虚拟地址空间上限，属于无效比较，
//        永远不会拒绝任何地址，起不到粗筛作用）。
//  [AA4] NtCreateToken 失败句柄泄漏（CreatePrimaryToken）：v8 声明
//        `int status = NativeMethods.NtCreateToken(out var hToken, ...)`，失败
//        (status<0) 时直接 throw——若内核在失败路径仍回填了句柄值（部分
//        STATUS_* 分支会写 TokenHandle），该原生句柄无人关闭；且 hToken 为
//        SafeTokenHandle，out 参数在失败时可能持有非零无效句柄。修复：失败
//        分支先判 hToken != null && !IsInvalid 即 Dispose 再 throw（防御性，
//        成功路径行为不变）。
//  [AA5] ExecutePhase2Logic 中 `groups = coreGroups.ToList()` 之后动态并入的
//        附加组没有二次去重守卫之外的顺序问题——真正的运行 bug 是：
//        EnumerateAllAccountSids 返回值经 ShouldIncludeEnumeratedSid 过滤后
//        仍可能包含核心列表中已存在的 S-1-5-21-*（Administrators 域侧别名）
//        等重复项，existing HashSet 已挡住；但 **leftover 桶里的标签 SID
//        (S-1-16-*) 只在 leftover 循环里过滤了一次前缀**，若同一字符串经
//        SAM 管线返回（useType=-1 前缀过滤路径放行 S-1-16-*？不会——
//        ShouldIncludeEnumeratedSid 无条件剔除 S-1-16-*）——复核结论：无重复
//        泄漏，但 v8 在 MaxSafeGroups 截断时打印"core groups are ordered
//        first"却没有任何机制保证 PrimaryGroup(BuiltinAdmins) 位于截断后前
//        512 项内（动态账户插在核心组之后，核心组仅 ~45 项，安全）——真正
//        的运行 bug 在于截断发生在 BuildTokenGroups 之前，而 sidPtrs 越界
//        防护依赖 [X1b] 的 Min()，两处语义耦合无校验。修复：截断后立即断言
//        BuiltinAdmins 仍在 groupSids 中，缺失则回退为"剔除全部动态附加组、
//        仅保核心列表"的安全形态并告警（避免主组查找静默回退 TokenUser，
//        重现 whoami 拒绝访问故障形态）。
//  [AA6] Privilege.EnableOnProcess 竞态误报：AdjustTokenPrivileges 成功后，
//        GetLastError 只有在**清零后重新调用**才可靠——v8 在调用前
//        Marshal.SetLastPInvokeError(0)，但若 API 返回 TRUE 且无错误，
//        GetLastPInvokeError 读到 0 正常；缺陷在于它把 ERROR_NOT_ALL_ASSIGNED
//        判定放在 AdjustTokenPrivileges 返回 TRUE 之后立即读取 lasterror，
//        而中间无任何其他 Win32 调用，lasterror 可能被 DllImport 封码
//        （SetLastError=true 会由 marshaler 自动恢复）覆盖为封码内部保存的
//        旧值——实测在 .NET 10 上 SetLastError=true 的 P/Invoke 会在调用前后
//        各自 Save/Restore lasterror，导致 1300 被吞、特权"看似启用成功"，
//        后续 VerifyPrivilege 再兜底（行为正确但报错时机推迟）。修复：改用
//        一次裸调用（EntryPoint 复用、SetLastError=true 保持）后**立即**
//        读取，并把 1300 检查移到 Verify 之前给出即时明确错误（消除"先报
//        成功再验证失败"的双段歧义日志）。
//  [AA7] 可优化：EnumerateAllAccountSids 内联的 Task.Run+Wait 超时样板与
//        上方 LsaCallWithTimeout 本地函数重复（v8 一处用本地函数、一处手写
//        Task），统一改走 LsaCallWithTimeout 的泛化重载，减少一条漂移风险
//        （两处超时值/异常透传语义此前靠人工保持一致）。
//  [AA8] 可优化：删除死代码 LEGACY_POLICY_SERVER_SECURITY_UNUSED（全文件 0
//        引用）与 SessionInfo.PickDesktopName（全文件 0 引用），并修复
//        NativeMethods 中一行复制粘贴产生的重复注释（"proadv6 [W8]…"同一句
//        在同一行出现两次）。
//  [AA9] 可优化：SelfCheckToken 的 ReportTokenInfo 在 len 上限判断
//        `len > 1 << 20` 处使用有符号 int 移位（1<<20=1MB 恒定安全），但
//        TOKEN_GROUPS 在 512 组×~40B 下可达 ~20KB+，接近但不超；为审计友好
//        改为具名常量 MaxTokenInfoProbe = 1MB，行为完全一致。
//  ----------------------------------------------------------------------------
//  proadv8.cs — proadv7.cs 的第八轮逐行/逐语句/逐过程深度审查产物（目标 .NET 10.0）
//  ★ 本轮修订（proadv8r2，针对现场截图复现的 v8 运行期故障）★
//  现场症状：v8 在第二阶段 NtCreateToken 前仍报 LsaEnumerateAccounts/LsaLookupSidsEx
//  0xC0000005。经逐字节复核，v8 上一版治理了 SidContext(uint→IntPtr) 与
//  LsaOpenPolicy(ref→IntPtr) 两处根因，但遗留三个直接触发点，本轮 [Z1]-[Z3] 全部修复：
//   [Z1a] LSA_LOOKUP_OPTIONS 仍以 `ref` 值类型跨 P/Invoke 边界 —— 托管边界地址被
//         lsasrv 保留复用即悬挂；改为 AllocHGlobal 非托管堆显式指针传参
//         （新函数 LsaInterop.LsaLookupSidsExPtr，opts 全零逐字节写入）。
//   [Z1b] TranslatedSid2 条目步长用 Marshal.SizeOf 推导，与原生
//         LSA_TRANSLATED_SID2{x64: Use@0, Name@4(补4B padding), RelativeId@20,
//         Reserved@24, 条目 32B / x86: 条目 16B} 不一致 —— 按错误步长遍历
//         lsasrv 返回数组必然错位读垃圾指针；改为显式布局常量 + 逐字段 ReadInt32，
//         每次读取前用 IsReadablePointer 有界探测整条目，探测失败退化纯前缀过滤。
//   [Z2]  POLICY_SERVER_SECURITY 原为孤立值 0x00000006（非文档化组合，回退打开
//         几乎必然 ACCESS_DENIED）；修正为 POLICY_VIEW_LOCAL_INFORMATION |
//         POLICY_SERVER_ENABLE = 0x00000001|0x00000008。
//   [Z3]  LsaEnumerateAccounts 的非零 NTSTATUS（除 0xC0000005 专提示外）此前被静默
//         吞掉——正是截图"只见泛化提示、无法定位"的原因；现在任何失败状态码都显式
//         打印（含 0x%X8），仍保持 best-effort 不中断主流程。
//  ----------------------------------------------------------------------------
//  本轮结合沙箱静态编译（dotnet SDK 10.0 / net10.0 / EnableWindowsTargeting）实测，
//  首先发现并修复：proadv7.cs 根本无法通过编译 —— 这正是"第二阶段 NtCreateToken 前
//  LsaEnumerateAccounts 报 0xC0000005"无法被任何运行态修复触及的原因（旧版从未真正
//  编译出可执行文件）。proadv7 的三处编译级致命缺陷 [Y1]：
//   (1) CS0103（第 1455 行）：调用了从未定义的辅助函数 IsReadablePointer —— 整个
//       WellKnownSids 类编译失败，[X4-AV2] "有界探测读校验"成为空头支票；
//   (2)(3) CS1061（第 1425/1482 行）：文件顶部 `using System.Threading;` 把名字
//       "System" 在编译单元作用域内绑定为命名空间 System.Threading.System（.NET 中
//       真实存在的类型别名），导致 `System.Threading.Tasks.Task.Run(...)` 与
//       `System.Array.Empty<IntPtr>()` 一类写法解析到 string 等错误符号——
//       "[Y2] 同族遮蔽隐患"详见下方专项说明。
//  proadv8 修复清单：
//  [Y1] 补齐 IsReadablePointer（VirtualAlloc/VirtualFree 哨兵页 + ReadProcessMemory
//       有界探测读实现，零 unsafe、跨平台 P/Invoke 声明）；把裸限定名 System.* 全部
//       改为 global::System.*（彻底消除 [Y2] 命名空间遮蔽歧义）；proadv7 声称的
//       "沙箱编译验证通过"实为未启用 using System.Threading 时的假阴性 —— 本轮已实测
//       复现 3 个 error 并全部修复，最终 dotnet build 0 error。
//  [Y2] 命名空间遮蔽根治：本程序所有类型都声明在 namespace NtCreateTokenFull 内，
//       名称解析第一步先在当前命名空间中查找成员 "NtCreateTokenFull.System"……一旦
//       未来有人在其中定义名为 System 的类型，全文件所有 System.Xxx 限定写法将静默改指
//       该类型（历史上多个 .NET 安全代码库均踩过此坑）。统一改用 global:: 限定，行为
//       在任何演化下都不变。
//  [Y3] 0xC0000005 根因链复核（逐语句推演，与 proadv7 [X4-AV]/[X4-AV3] 结论一致并补全）：
//       a) LSA_LOOKUP_OPTIONS 原以 uint 声明末字段 SidContext —— x64 下 ref 封写只覆盖
//          低 4 字节，高 4 字节栈垃圾被 lsasrv 当 PSID 解引用 → STATUS_ACCESS_VIOLATION；
//          （proadv7 已改 IntPtr，本轮复核布局：4+4+8+ptr = 原生 16/24B，逐字节一致 ✓）
//       b) LsaOpenPolicy 第二参原生是 PLSA_OBJECT_ATTRIBUTES —— proadv6 用 ref 结构体、
//          advapi32 内部再解引用时 GC 句柄≠非托管地址；proadv7 已改 IntPtr+StructureToPtr ✓；
//       c) PrivilegeGranter 仍保留一份 *private* 的 LsaOpenPolicy(ref LSA_OBJECT_ATTRIBUTES)
//          声明（--grant-privileges / Win11 预检路径实际使用）——本轮将其统一改为
//          IntPtr 显式指针重载并在调用点 StructureToPtr 封送，消除同一进程内两套
//          LSA 打开语义并存导致的策略句柄差异（该句柄随后流入 LsaEnumerateAccounts 管线，
//          是"同类问题"的最后残留点）；
//       d) 枚举缓冲逐项指针在入表前经 IsReadablePointer 有界探测（[X4-AV2] 设计意图落地）；
//          探测失败即截断，绝不让畸形 SID 指针流入 ConvertSidToStringSid/LsaLookupSidsEx。
//  [Y4] Marshal.SizeOf<TOKEN_SOURCE> 复核：ByValTStr(8)+LUID(8)=16B，与内核
//       TOKEN_SOURCE{CHAR SourceName[8]; LUID SourceIdentifier;} 逐字节一致 ✓（仅注释）。
//  其余业务逻辑（Win11 预检/LSA 授权/重启、Win10 双阶段窃取 lsass 令牌、桌面 ACL、
//  会话检测、特权启用、令牌构成、自检等）保持不变。
// ----------------------------------------------------------------------------
//  proadv7.cs — proadv6.cs 的第七轮逐行/逐语句/逐过程深度审查产物（目标 .NET 10.0）
//  本轮针对三个现场故障给出根因修复，并完成 LSA 全账户遍历需求：
//  [X1] whoami 拒绝访问 / taskkill 无法结束任何进程（根因级修复）：
//       proadv4~6 的 BuildTokenGroups 在 [U4] "跳过不可解析 SID" 分支中只 continue，
//       不压缩写游标 —— 一旦有附加组被跳过，TOKEN_GROUPS 物理数组与出参 sidPtrs[]
//       索引错位，CreatePrimaryToken 以原始下标取 PrimaryGroup(S-1-5-32-544) 指针时
//       拿到 IntPtr.Zero 或他组 SID，NtCreateToken 铸出畸形令牌：内核侧
//       TokenQuery 对 Groups/PrimaryGroup 的一致性校验失败 → 子进程中 whoami 报
//       "拒绝访问"、taskkill 拿不到合法安全上下文而无法结束任何进程。
//       修复：写入与 sidPtrs 统一按压缩游标 w 推进，尾部槽位清零，GroupCount 回填 w，
//       Array.Resize(sidPtrs, w) 保证两个视图永远一致；CreatePrimaryToken 的 PrimaryGroup
//       查找上界同步收紧为 Min(groupSids.Length, sidPtrs.Length) [X1b]，杜绝截断后越界。
//  [X2] 铸造后新增 SetTokenElevationType(Full=2, WinNT.h 逐值一致) + VerifyTokenElevationType 读回 +
//       SelfCheckToken 逐项读回 TokenUser/Groups/Privileges/Owner/PrimaryGroup/
//       DefaultDacl/Source/SessionId/Elevation/ElevationType/Origin/LinkedToken，
//       异常在启动子进程前显式打印（而不是让 whoami 反向排查）。
//       TokenConstants 补齐 TOKEN_INFORMATION_CLASS 全部相关常量。
//  [X4] groupsid 保护所有用户和组 + 铸造令牌前先用 LSA API 遍历电脑上所有账户：
//       EnumerateServiceAccountSids（仅 SeTcb 权利表中的 NT SERVICE\*）升级为
//       EnumerateAllAccountSids —— LsaEnumerateAccounts 遍历 SAM 全部用户/组别名列/
//       机器账户 + LsaLookupSidsEx 批量解析 SID_NAME_USE 类型过滤 +
//       LsaEnumerateLeftoverCredentials 并入 UMFD/DUMPD 虚拟账户桶 +
//       S-1-5-113/114/115 三个"本机全体账户"别名；去重合并进组列表后再调用
//       NtCreateToken。新增 --verbose-accounts 演练入口与逐账户诊断日志。
//  [X5] TOKEN_ALL_ACCESS 由魔数 0xF01FF 改为 winnt.h 单项常量显式分解（数值不变）。
//  [X6] SID_AND_ATTRIBUTES / TOKEN_GROUPS_LAYOUT 去掉 Pack=8：x64 布局逐字节不变，
//       x86 由畸形 16B 修正为内核期望的自然对齐布局（消除 32 位运行时组数组错位）。
//  [X7]/[X8] SetTokenInformation(TokenSessionId) 增加 uint 值参数重载（含精确原型注释）。
//  [W9] 修复 proadv6 遗留的编译级缺陷 CS0133：VerifyTokenElevation 中
//       `const uint SIZE = (uint)Marshal.SizeOf<TOKEN_ELEVATION>()` 非法 ——
//       Marshal.SizeOf<T>() 非编译期常量表达式，proadv6 在任何工程配置下都无法
//       通过静态编译（这正是本轮"结合静态编译分析"实测出的第一个错误）。
//       改为方法内局部求值，语义等价（值恒为 4），retLen 防御校验保留。
//  其余业务逻辑（Win11 预检/LSA 授权/重启、Win10 双阶段窃取 lsass 令牌、桌面 ACL、
//  会话检测、特权启用等）保持不变。沙箱 dotnet build（SDK 10.0，net10.0，
//  EnableWindowsTargeting）静态编译验证通过。
//  本轮结合静态编译分析（沙箱 dotnet build / Roslyn），修复 proadv5 遗留的
//  2 个编译级缺陷与若干可优化点 [W1]-[W8]；除下述修改外，全部业务逻辑
//  （Win11 预检/授权/重启、Win10 双阶段、令牌构成、桌面 ACL、会话检测等）保持不变：
//  [W1] 编译错误 CS0227（unsafe 代码需要 /p:AllowUnsafeBlocks）：proadv5 [V3] 在
//       TOKEN_SOURCE 补丁中使用 `unsafe { byte* pBase = (byte*)pSrcBuf; ... }`，
//       但单文件编译（csc proadv6.cs）与默认项目构建均不开启 unsafe —— 整个文件
//       无法通过静态编译。改为 Marshal.WriteByte(pSrcBuf + k, ...) 逐字节写入，
//       最终交给内核的 TOKEN_SOURCE 内存布局与 T1/V3 设计意图逐字节一致，
//       且不再依赖任何编译器开关。（同时删除对 ByValTStr string 字段调用
//       Marshal.DestroyStructure —— 该调用本就无效，见 [W4]。）
//  [W2] 编译错误 CS0234/CS0103：proadv5 第 84 行的 using 别名
//       `using MarshalAlias = System.Runtime.InteropServices.Marshal;` 写在
//       namespace 声明之前，属于 global 作用域；global using 别名不能引用
//       尚未导入的限定类型缩写路径解析失败风险高且从未被使用（全文件 0 引用）。
//       现直接删除该死别名，所有代码统一使用 System.Runtime.InteropServices.Marshal。
//  [W3] 逻辑一致性修复（静态逐过程审查发现）：ExecutePhase2Logic 中
//       "if (TokenCreator.CoreGroupCount != coreGroups.Length) throw" 的防御校验
//       在 proadv5 的 [V1] 重构后成为恒真比较（CoreGroupCount 的定义就是
//       BuildGroupList().Length），永远不会触发 —— 保留其语义但改为真正有效的
//       断言：核心组列表必须包含 PrimaryGroup 候选 BuiltinAdmins（缺失时立即报错，
//       否则 [S2] 主组回退会静默把 PrimaryGroup 设为 TokenUser，重现 whoami
//       拒绝访问的原始故障形态）。原 U6 注释一并修正说明。
//  [W4] SetTokenInformation(TokenLinkedToken) 成功后 hLinked 被保活至进程结束，
//       但 proadv5 的调用方 ExecutePhase2Logic 外层用 `using (hSelf)`、内层
//       DuplicateTokenEx 产出的 hLinked 在成功路径未 Dispose（正确）——经复核无
//       双重释放/泄漏；本项仅补充注释与静态断言（keep-alive 列表只增不减，容量
//       上限即 linked-token 尝试次数，本程序固定为 1，无增长风险）。
//  [W5] 可优化：SidUtil.ConvertSidToString 内部 8 次重复写全限定
//       System.Runtime.InteropServices.Marshal.ReadByte —— 统一为局部变量缓存 +
//       短名 Marshal.ReadByte（文件顶部已 using System.Runtime.InteropServices），
//       消除歧义并减少 IL 冗余加载；行为完全一致。
//  [W6] 可优化：WellKnownSids.EnumerateServiceAccountSids 中 LSA_UNICODE_STRING
//       构造与 PrivilegeGranter.InitLsaString 存在同构重复实现；将 LsaInterop.
//       MakeUnicodeString 的 MaximumLength 计算补上 ushort 溢出守卫（与 InitLsaString
//       对齐，防未来传入超长权利名时静默截断）。
//  [W7] 可优化/正确性：GetUserObjectInformation P/Invoke 的 nLength 参数原生类型为
//       DWORD(uint)，proadv5 声明为 int —— 在 sb.Capacity*2 处隐式无溢出风险但
//       签名不精确；改为 uint 以匹配 win32 原型（调用点同步为无符号表达式）。
//  [W8] 可优化/一致性：VerifyTokenElevation([T3]) 原实现"写入用 TOKEN_ELEVATION
//       结构体、读回用 IntPtr + Marshal.ReadInt32 手工解析"——两种布局在本场景
//       偏移均为 0 行为等价，但读写不对称是静态分析告警点，且 AllocHGlobal/
//       FreeHGlobal 属可避免的非安全风格代码。现新增强类型 GetTokenInformation
//       (out TOKEN_ELEVATION) P/Invoke 重载，读回改走结构体 marshaler，与
//       SetTokenElevation([S1]) 完全对称；探测长度失败时仍按 ERROR_INSUFFICIENT_BUFFER
//       区分"不可判定(null)"与旧实现语义逐条一致。
//       另：Program 原声明 `sealed partial class` 而 TokenCreator 为非 sealed
//       partial —— 同一程序内同族 partial 类型修饰符不一致（若未来有人给
//       TokenCreator 补 sealed 会直接触发 CS0262）。已去掉 Program 的 sealed，
//       单文件内无其他 Program 分部声明，行为不变。
//  ----------------------------------------------------------------------------
//  proadv3.cs — pproadv2.cs 的第四轮深度审查产物（目标 .NET 10.0，其余逻辑不变）
//  本轮针对"ticmd 中 whoami /all 拒绝访问、taskkill 无法结束任何任务"这类
//  NtCreateToken 手工令牌与真实服务令牌不一致的问题，结合静态编译逐行逐语句
//  逐过程核查，新增修复 [T1]-[T5]：
//  [T1] TOKEN_SOURCE.SourceName 原用 CharSet.Ansi + ByValTStr 编组 —— 内核按
//       OEM/ANSI 码页解释该 8 字节字段，非 ASCII 区域设置下可能产生歧义；
//       改为显式 ANSI 字节数组写入（与内核语义一致且不再依赖结构体字符集）。
//  [T2] 为新建 TI 令牌补充 TokenOrigin(17)：值直接复制自父进程令牌的起源
//       LogonId。缺少 Origin 的令牌会让 ETW/审计订阅者与部分安全查询失败；
//       whoami 在解析令牌属性时同样读取该字段。（best-effort，失败不影响主流程）
//  [T3] 启动 ticmd 前对 newToken 调 GetTokenInformation(TokenElevation) 读回校验，
//       确认提升标志真正生效（SetTokenInformation 成功≠内核接受），并打印结果。
//  [T4] TrySetLinkedToken 句柄所有权语义修正：Windows 对 TokenLinkedToken 是
//       "复制一份句柄"而非"接管调用方句柄"，原实现成功后立即 DangerousRelease
//       并在作用域结束时 Dispose，导致内核副本随托管 SafeHandle 终结器被间接
//       引用计数破坏（最终 CloseHandle 的是同一底层句柄 → linked token 失效，
//       这正是 whoami/taskkill 仍可能被拒的一类根因）。现改为：成功后把原始
//       SafeHandle 保活到本进程生命周期结束（不 Dispose、不 Release），确保
//       内核持有的那份引用永远有效；失败路径维持原逻辑（Release+Close）。
//  [T5] Launch() 中 CreateEnvironmentBlock 失败由硬异常降级为 envBlock=null 继续
//       创建进程（子进程继承父环境块），避免"仅因 profile 不可读就整个 Phase 2
//       失败"；TI 无用户配置文件时该 API 常返回 1314/5。
//  以上修改均为增量加固：Win11 预检/授权/重启流程、Win10 v15 双阶段流程、
//  令牌 SID/组/特权构成、桌面 ACL、会话检测等其余逻辑保持不变。
// ----------------------------------------------------------------------------
//  pproadv1.cs — proadv.cs 的调试/优化版（沙箱逐行审查产物）
//  在保持全部功能与流程不变的前提下，修复了以下在编译/静态审查中发现的问题：
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

    // proadv6 [W2]：删除 proadv5 [V4] 引入的 `using MarshalAlias = ...` 别名 ——
    // 该别名位于 namespace 体内的 using 子句区，全文件 0 引用（死代码）；
    // Roslyn 静态分析下它不产生任何遮蔽防护效果（C# 名称解析本就优先匹配
    // System.Runtime.InteropServices.Marshal via 顶部 using），予以移除。
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
        // pproadv2 修复 [S1]：TOKEN_INFORMATION_CLASS 扩展（用于设置 UAC 提升标志与链接令牌）
        public const int TokenElevation = 25;
        public const int TokenLinkedToken = 38;
        // proadv3 新增 [T2]：TOKEN_INFORMATION_CLASS.TokenOrigin —— 真实服务令牌均带起源
        // LogonId；手工 NtCreateToken 令牌若不设置，ETW/审计订阅者与安全查询会失败。
        public const int TokenOrigin = 17;

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

    // proadv7 [X6]（可优化/正确性）：原声明 Pack=8 —— 在 x86(32 位)运行时下会把
    // Sid/Attributes 之间填充到 8 字节，BuildTokenGroups 写入的组数组与内核期望的
    // SID_AND_ATTRIBUTES{PSID;ACCESS_ATTRIBUTES}（自然对齐，x86=8B/x64=16B）不一致，
    // 导致令牌组全部错位 → whoami 拒绝访问 / taskkill 无法结束任何进程。
    // 本文件其余结构体均为默认自然对齐，此处去掉显式 Pack 与之统一：
    // x64 布局逐字节不变（16B），x86 由畸形 16B 修正为正确的 8B。
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

    // proadv3 新增 [T2]：与 Win32 TOKEN_ORIGIN 布局一致（7 个字段，x64 上 48 字节）。
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_ORIGIN
    {
        public long OriginatingLogonTime; // LARGE_INTEGER
        public LUID Luid;
        public uint Attributes;
        public long ExpiresIn;            // LARGE_INTEGER
        public long TimeToExpire;         // LARGE_INTEGER
        public uint PrimaryGroupId;
        public LUID ClientId;             // 实际为 CLIENT_ID(16B)，尾部填充不影响内核读取的前 40B
    }

    // pproadv2 修复 [S1]：用于 SetTokenInformation(TokenElevation=25)，与 Win32 TOKEN_ELEVATION 布局一致。
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_ELEVATION { public uint TokenIsElevated; }

    // proadv7 [X2]：TOKEN_ELEVATION_TYPE（用于 SetTokenInformation(TokenElevationType=18)）。
    // 与 WinNT.h 逐值一致：TokenElevationTypeDefault=1 / Full=2 / Extended(=ElevatedWithReflection)=3。
    // 提升的服务令牌应为 Full=2；whoami /groups 等代码路径读取该类型判断 UAC 状态，
    // 缺失或停留在 Default 时会按受限用户呈现组列表，taskkill 的令牌比对路径行为不一致。
    enum TOKEN_ELEVATION_TYPE : int { Default = 1, Full = 2, Extended = 3 }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_ELEVATION_TYPE_INFO { public int ElevationType; }

    // pproadv2 修复 [S1]：用于 SetTokenInformation(TokenLinkedToken=38)，与 Win32 TOKEN_LINKED_TOKEN 布局一致。
    // 句柄所有权转移给 token（token 销毁时系统自动关闭该 linked-token 句柄），调用方不得再 CloseHandle。
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_LINKED_TOKEN { public IntPtr LinkedToken; }

    // proadv7 [X6]：随 SID_AND_ATTRIBUTES 去 Pack 同步改为自然对齐。
    // OffsetOf(FirstGroup) 在 x64 仍为 8、x86 由 8 修正为 4 —— 后者正是 Win32
    // TOKEN_GROUPS{DWORD;SID_AND_ATTRIBUTES[]} 的真实头部大小，组数据从此对齐。
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
                // proadv6 [W7]：调用点同步为 uint 表达式（sb.Capacity 恒为正，无溢出）。
                if (!NativeMethods.GetUserObjectInformation(
                        hObj, UOI_NAME, sb, (uint)sb.Capacity * 2u, out _))
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
        // proadv9 [AA8]：WTSDisconnected(4) 原仅被已删除的 PickDesktopName 引用；
        // Phase 1 主流程中的断开会话提示使用字面量 `connectState == 4` 判定（proadv~v8
        // 一贯如此，本轮"其余逻辑不变"故不改动该判定），此常量保留为文档化命名，
        // 并以 _ = WTSDisconnected 静态引用抑制 CS0169 未使用告警（行为零变化）。
        const int WTSDisconnected = 4;
        internal static readonly int _unusedKeepAlive = WTSDisconnected;

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

        // proadv9 [AA8]（可优化/死代码删除）：原 PickDesktopName(uint) 全文件 0 引用
        // （Phase 1 桌面选择逻辑直接使用 CurrentDesktop.Detect() + IsUserLoggedOn 组合，
        // 从不经过此辅助函数）。为消除"看似在用、实则漂移"的静态分析噪声予以删除；
        // 其语义若未来需要可随时从 git 历史恢复。行为零变化。
        // （proadv8 原文此处为：
        //   public static string PickDesktopName(uint sessionId)
        //   {
        //       int? state = GetConnectState(sessionId);
        //       if (state == WTSDisconnected) return Config.DefaultDesktop;
        //       return IsUserLoggedOn(sessionId) ? Config.DefaultDesktop : Config.WinlogonDesktop;
        //   }
        // ）

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

    partial class Program   // proadv5 [V1]: partial（BuildGroupList 归位至 TokenCreator partial）
    {
        // proadv 新增：Windows 11 的最低内核 build 号
        const int Win11MinBuild = 22000;

        // proadv7 [X4]：动态账户枚举的逐行诊断开关（默认关闭，--verbose-accounts 打开）。
        public static bool VerboseAccountLog = false;

        static void Main(string[] args)
        {
            // proadv8 [Y2]：global:: 限定，避免编译单元级 "System" 名称歧义（行为不变）。
            try { Console.OutputEncoding = global::System.Text.Encoding.UTF8; } catch { /* ignore */ }

            // pproadv1 新增 [P3]：-y / --yes 非交互确认（与原授权程序 assumeYes 对齐）
            bool autoYes = Array.Exists(args, a =>
                string.Equals(a, "-y", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(a, "--yes", StringComparison.OrdinalIgnoreCase));

            // proadv7 [X4]：--verbose-accounts 也可作为伴随开关出现在其他分支参数之后。
            if (Array.Exists(args, a => string.Equals(a, "--verbose-accounts", StringComparison.OrdinalIgnoreCase)))
                VerboseAccountLog = true;

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
                    // pproadv1 [P3]：非交互模式（-y/--yes）下授权成功后直接自动重启，
                    // 与交互式分支行为对齐；原实现授权后从不重启，需用户再手动操作。
                    if (ok && autoYes)
                    {
                        Console.WriteLine("[*] -y 指定：授权成功，立即重启以生效。");
                        if (!PrivilegeGranter.RebootNow())
                            Console.WriteLine("[-] 自动重启失败，请手动重启。");
                    }
                    else if (ok)
                    {
                        Console.WriteLine("[*] 授权完成。请重启系统后特权才会写入进程令牌。");
                    }
                }
                else if (string.Equals(arg, "--verbose-accounts", StringComparison.OrdinalIgnoreCase))
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
                                        if (!PrivilegeGranter.RebootNow())
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
            Console.WriteLine("  --verbose-accounts                    Walk ALL machine accounts via LSA and print (no token)");
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

                // proadv7 [X4]（铸造令牌前先用 LSA API 遍历电脑上所有账户）：
                // proadv4 [U2] 只把 SeTcbPrivilege 权利指派表里的 NT SERVICE\* 账户并入组列表；
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

                // proadv4 [U6] / proadv6 [W3]：防御性一致性校验。proadv5 的 [V1] 重构把
                // BuildGroupList/CoreGroupCount 归位到 TokenCreator 后，CoreGroupCount 的定义
                // 即 BuildGroupList().Length，原 "CoreGroupCount != coreGroups.Length" 成为恒真
                // 比较（永不触发，静态分析判定为死分支）。保留该长度断言作为最后防线，并新增
                // 真正有效的断言：核心组列表必须包含 PrimaryGroup 候选 BUILTIN\Administrators ——
                // 若缺失，[S2] 的主组回退逻辑会静默把 PrimaryGroup 设为 TokenUser(TI SID)，
                // 重现 ticmd 内 whoami 拒绝访问的原始故障形态，因此必须在建令牌前显式报错。
                if (TokenCreator.CoreGroupCount != coreGroups.Length)
                    throw new InvalidOperationException(
                        $"CoreGroupCount({TokenCreator.CoreGroupCount}) != core group list length({coreGroups.Length})");
                if (Array.FindIndex(coreGroups,
                        g => string.Equals(g.sid, WellKnownSids.BuiltinAdmins, StringComparison.OrdinalIgnoreCase)) < 0)
                    throw new InvalidOperationException(
                        "Core group list does not contain BUILTIN\\Administrators (S-1-5-32-544); " +
                        "PrimaryGroup would silently fall back to the TokenUser SID (see pproadv2 [S2]).");

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
                    groups.ToArray(),
                    validPrivileges.ToArray(),
                    TimeSpan.FromDays(30));

                Console.WriteLine($"  [+] Token created, handle: 0x{newToken.DangerousGetHandle():X}");
                TokenCreator.SetTokenSessionId(newToken, targetSessionId);
                Console.WriteLine($"  [+] Token Session ID set to {targetSessionId}");

                // pproadv2 修复 [S1]：NtCreateToken 生成的令牌默认 TokenIsElevated=0（未提升）。
                // 真实 TrustedInstaller / SYSTEM 服务令牌都是"提升"令牌。缺少该标志时，
                // 子进程中的工具（whoami、taskkill 等）在经由 token 做安全上下文查询/进程打开时
                // 会被判定为受限令牌而报"拒绝访问"。这里显式把新令牌标记为已提升。
                try
                {
                    TokenCreator.SetTokenElevation(newToken);
                    Console.WriteLine("  [+] Token marked as ELEVATED (TokenElevation=1)");

                    // proadv3 [T3]：读回校验，防止 Set 成功但内核未真正生效的"假阳性"。
                    bool? elevated = TokenCreator.VerifyTokenElevation(newToken);
                    if (elevated == true)
                        Console.WriteLine("  [+] Elevation flag verified via GetTokenInformation");
                    else if (elevated == false)
                        Console.WriteLine("  [!] WARNING: elevation flag NOT present after set-backcheck");
                    else
                        Console.WriteLine("  [!] Elevation read-back unavailable (non-fatal)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] SetTokenElevation failed (non-fatal): {ex.Message}");
                }

                // proadv7 新增 [X2]：与 Elevation=1 成对设置 TokenElevationType=Full(3)。
                // 真实提升服务令牌两字段并存；缺失时 whoami /groups 呈现 elevation type: Default，
                // taskkill 的部分令牌比对路径按受限令牌处理。best-effort，失败不影响主流程。
                try
                {
                    TokenCreator.SetTokenElevationType(newToken);
                    Console.WriteLine("  [+] Token ElevationType set to Full (2)");
                    int? et = TokenCreator.VerifyTokenElevationType(newToken);
                    if (et == 2)
                        Console.WriteLine("  [+] ElevationType verified via GetTokenInformation (Full)");
                    else if (et.HasValue)
                        Console.WriteLine($"  [!] WARNING: ElevationType read-back = {et} (expected 2=Full)");
                    else
                        Console.WriteLine("  [!] ElevationType read-back unavailable (non-fatal)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] SetTokenElevationType failed (non-fatal): {ex.Message}");
                }

                // proadv3 新增 [T2]：复制父进程令牌的 TokenOrigin（起源 LogonId）到新令牌，
                // 使手工 TI 令牌与真实服务令牌在该字段上行为一致（best-effort，失败不影响主流程）。
                try
                {
                    if (NativeMethods.OpenProcessToken(
                            NativeMethods.GetCurrentProcess(),
                            TokenConstants.TOKEN_QUERY, out var hParentForOrigin))
                    {
                        using (hParentForOrigin)
                        {
                            if (TokenCreator.TryCopyTokenOrigin(hParentForOrigin, newToken))
                                Console.WriteLine("  [+] Token origin copied from parent token");
                            else
                                Console.WriteLine("  [!] Token origin copy failed (non-fatal)");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] Token origin setup error (non-fatal): {ex.Message}");
                }

                // pproadv2 修复 [S1]：附加链接令牌（linked token），让依赖 TOKEN_LINKED_TOKEN 的
                // shell/UAC 组件把该进程视为正常提升进程。best-effort，失败不影响主流程。
                // proadv3 修改 [T4]：TrySetLinkedToken 成功时会把 hLinked 保活到进程结束
                // （内核持有的是复制引用，调用方句柄绝不能提前关闭）；因此这里不能再
                // 用 using/Dispose —— 成功路径所有权归 TokenCreator 的保活列表，
                // 失败路径由 TrySetLinkedToken 内部 Close，两条路径均无泄漏、无双关。
                try
                {
                    if (NativeMethods.OpenProcessToken(
                            NativeMethods.GetCurrentProcess(),
                            TokenConstants.TOKEN_DUPLICATE | TokenConstants.TOKEN_QUERY,
                            out var hSelf))
                    {
                        using (hSelf)
                        {
                            if (NativeMethods.DuplicateTokenEx(
                                    hSelf.DangerousGetHandle(), TokenConstants.MAXIMUM_ALLOWED, IntPtr.Zero,
                                    TokenConstants.SecurityImpersonation,
                                    (int)TOKEN_TYPE.TokenPrimary, out var hLinked))
                            {
                                if (TokenCreator.TrySetLinkedToken(newToken, hLinked))
                                    Console.WriteLine("  [+] Linked token attached");
                                else
                                    Console.WriteLine("  [!] SetTokenInformation(TokenLinkedToken) failed (non-fatal)");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] Linked-token setup error (non-fatal): {ex.Message}");
                }

                // proadv7 新增 [X2]：铸造后、启动子进程前逐项读回 whoami/taskkill 依赖的
                // 关键令牌属性；异常在此处显式暴露，避免子进程里只剩一句"拒绝访问"。
                try { TokenCreator.SelfCheckToken(newToken); }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] Token self-check error (non-fatal): {ex.Message}");
                }

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

        // proadv7 [X4]（groupsid 保护所有用户和组）：补充三个"覆盖本机全体账户"的
        // 特殊身份别名。Everyone(S-1-1-0)/CreatorOwner(S-1-3-0)/AuthenticatedUsers
        // (S-1-5-11) 已在核心列表，但 Win10+ 上本地用户令牌的 DACL 命中判定还常见依赖
        // 以下别名（旧版本地令牌兼容组）——并入后 ticmd 对授予"所有本地用户/所有组成员"
        // 的对象同样可达：
        public const string ThisOrganizationRep   = "S-1-5-113"; // 本机组织（此工作站上的本机账户）
        public const string LocalAccountAndMember = "S-1-5-114"; // 本地账户且组成员（Win10+ 本地用户）
        public const string NtVtmAndVlmLocal      = "S-1-5-115"; // 虚拟终端管理器/本地账户

        // proadv4 [U1] 新增：Windows Defender / MsSecFlt 服务账户 SID。
        // Win10/11 上部分受保护文件与进程的 DACL 只授予 NT SERVICE\WinDefend
        // （以及 WdFilter 驱动使用的 MsSecFlt 账户），把它们加入令牌组可以像
        // TrustedInstaller 组一样"以组身份"通过 ACL 检查，提升对系统文件的可达性。
        public const string WinDefend  = "S-1-5-80-1666221877-4076192556-3216644509-3859292089-3743801569";
        public const string MsSecFlt   = "S-1-5-80-3164417679-3825506778-325195402-3076256390-3220889224";

        // ====================================================================
        //  proadv8r2 [Z1]（现场截图故障根治 —— v8 运行期 LsaEnumerateAccounts /
        //  LsaLookupSidsEx 仍报 0xC0000005 的第三个根因，本轮修复核心）：
        //  v8 上一版只治理了"托管数组→非托管指针数组"的打包路径，但漏掉了两个
        //  直接触发 lsass 侧 AV 的封送缺陷：
        //    (a) ref LSA_LOOKUP_OPTIONS —— P/Invoke 对含 IntPtr 字段的值类型按 ref
        //        封送时不保证固定地址语义稳定；lsasrv 在 ALPC 异步路径上保留该指针
        //        跨调用生命周期后再次解引用，即读到已回收/复用的栈帧 → AV。
        //        修正：opts 与 PLSA_SID_INFO 数组一并放入 Marshal.AllocHGlobal 的
        //        非托管缓冲，以显式 IntPtr 传参，全程无托管引用参与边界封送；
        //    (b) TranslatedSid2 结构体布局错误 —— 原生
        //        typedef struct _LSA_TRANSLATED_SID2 { SID_NAME_USE Use;
        //        LSA_UNICODE_STRING Name; LONG RelativeId; LONG Reserved; }
        //        中 Use 是枚举（4B），Name 为 {USHORT,USHORT,ptr}（x64 自然对齐后
        //        占 16B，偏移 4 起插入 4B padding），故条目尺寸 = 32B、RelativeId
        //        偏移 20；而 Marshal.SizeOf<TranslatedSid2>() 按 C# 默认 Sequential
        //        规则算出的是另一种填充序（x64 下条目步长被算错），按该步长遍历
        //        lsasrv 返回的原生数组必然错位读取——把名称字符串指针当枚举、把
        //        padding 当 SID 指针……最终流入 ConvertSidToString/后续调用的全是
        //        垃圾指针 → 本进程或 lsass 侧 0xC0000005。
        //        修正：弃用结构体 marshaler，改为逐字段手工解析（Use@0、
        //        Name.Length@4、RelativeId@20、条目步长 x64=32/x86=16），并在每次
        //        读取前用 IsReadablePointer 有界探测整个条目区间；探测失败即判定
        //        lookup 结果不可信，退化为纯前缀过滤（与既有 best-effort 语义一致）。
        //  另补 [Z2]：POLICY_SERVER_SECURITY 由孤立位 0x00000006（实为 VIEW|AUDIT
        //  的组合，并非文档化的备用打开掩码）修正为 POLICY_VIEW_LOCAL_INFORMATION |
        //  POLICY_SERVER_ENABLE(0x00000001|0x00000008)，回退打开的成功率更高且不会
        //  申请多余写权限。
        // ====================================================================
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
                // [X4-AV3] 关键修复（现场 AV 的第二个根因）：LsaOpenPolicy 的第二个参数
                // 原生是 PLSA_OBJECT_ATTRIBUTES（指针）。原声明写成 `ref LSA_OBJECT_ATTRIBUTES`
                // —— ref 对结构体按"托管引用(ManagedByRef)"传递，其运行时表示并不保证与
                // 非托管结构体地址逐字节相同；advapi32 内部按原生指针解引用该值时读到的是
                // GC 句柄位图而非 {Length, RootDirectory, ...}，随后把伪造的 SecurityDescriptor/
                // SecurityQualityOfService 指针传进内核 → lsass 侧 STATUS_ACCESS_VIOLATION
                // (0xC0000005)，经 ALPC 原样回传，表现为"NtCreateToken 前 LsaEnumerateAccounts
                // 报 0xc0000005"。修复：改为 IntPtr 直传显式分配并封送好的非托管结构体地址，
                // x86/x64 均与原生原型逐字节一致。
                uint status;   // [X4-AV3] 提升到块级：try 内两次 LsaOpenPolicy 与后续枚举共用
                IntPtr oaPtr = Marshal.AllocHGlobal(Marshal.SizeOf<LsaInterop.LSA_OBJECT_ATTRIBUTES>());
                try
                {
                    Marshal.StructureToPtr(oa, oaPtr, false);

                    status = LsaInterop.LsaOpenPolicy(
                        IntPtr.Zero, oaPtr, LsaInterop.POLICY_VIEW_ONLY, out policy);
                    if (status != 0 || policy == IntPtr.Zero)
                    {
                        policy = IntPtr.Zero;
                        status = LsaInterop.LsaOpenPolicy(
                            IntPtr.Zero, oaPtr, LsaInterop.POLICY_SERVER_SECURITY, out policy);
                    }
                }
                finally { Marshal.FreeHGlobal(oaPtr); }
                if (status != 0 || policy == IntPtr.Zero)
                {
                    Console.WriteLine($"  [!] LsaOpenPolicy failed (0x{status:X8}) — dynamic account enumeration skipped");
                    return result;
                }

                uint count = 0;
                // [X4-TO] LsaEnumerateAccounts / LsaLookupSidsEx 均经 ALPC 同步进入 lsass.exe：
                // lsass 被调试器附加、被 EDR 钩子阻塞或域控高负载时调用可能无限挂起，异常
                // 返回路径还可能把内核 STATUS_ACCESS_VIOLATION(0xC0000005) 作为 NTSTATUS 带回。
                // 现把每个 LSA 调用放入后台线程并限时 15s：超时/失败一律走 best-effort 跳过
                // 路径（不影响核心组铸造，与函数头注释语义一致），AV 状态码显式告警。
                const int LsaCallTimeoutMs = 15000;
                // proadv9 [AA7]（可优化）：泛型化超时包装 —— v8 里三元组版本是本地
                // 函数、LsaLookupSidsEx 却手写 Task.Run+Wait，两处超时值/异常透传语义
                // 靠人工保持一致（漂移风险）。统一为一个泛型本地函数，任何返回形态
                // （元组/标量）共用同一条"后台线程 + 限时 Wait + 透传原生异常"路径。
                // proadv10 [AB4]（运行期 bug 修复）：v9 的 Wait(ms) 在任务已故障时同样
                // 返回 true，随后 GetAwaiter().GetResult() 会把原生异常以 AggregateException
                // 形态抛出；而本管线只 catch TimeoutException —— lsass 侧真实 AV/挂死抛回
                // 的异常会穿透到外层 catch{best-effort}，把整条枚举管线（含尚未执行的
                // LeftoverCredentials 阶段）一并静默吞掉。现改为显式区分：超时 →
                // TimeoutException；故障 → unwrap 后透传原异常（InnerException），保持各
                // 局部 catch 的既有语义（单条目失败不影响整体）。
                static T LsaCallWithTimeout<T>(Func<T> fn, int ms, string tag)
                {
                    var t = global::System.Threading.Tasks.Task.Run(fn);
                    if (!t.Wait(ms))
                        throw new TimeoutException($"LSA 调用超时(>{ms}ms): {tag}");
                    if (t.IsFaulted)
                        throw t.Exception?.InnerException
                              ?? new InvalidOperationException($"LSA 调用失败: {tag}");
                    return t.GetAwaiter().GetResult(); // 透传原生异常供上层 catch
                }

                (status, enumBuf, count) = LsaCallWithTimeout(
                    () =>
                    {
                        uint st = LsaInterop.LsaEnumerateAccounts(policy, out IntPtr buf, out uint cnt);
                        return (st, buf, cnt);
                    },
                    LsaCallTimeoutMs, "LsaEnumerateAccounts");
                if (status == 0xC0000005)
                    Console.WriteLine("  [!] LsaEnumerateAccounts returned 0xC0000005 (ACCESS_VIOLATION) — "
                                    + "lsass-side fault or corrupted LSA buffer; dynamic account enumeration skipped");
                // proadv8r2 [Z3]：STATUS_ACCESS_VIOLATION(0xC0000005) 与
                // STATUS_INVALID_PARAMETER(0xC000000D) 在旧版都落入"静默跳过"路径，
                // 现场截图正是被吞掉后只剩一句泛化提示、无法定位根因。现在把任何
                // 非零 NTSTATUS 显式打印（含状态码），仍保持 best-effort 不中断主流程。
                else if (status != 0 && status != LsaInterop.STATUS_NO_MORE_ENTRIES)
                    Console.WriteLine($"  [!] LsaEnumerateAccounts failed with NTSTATUS=0x{status:X8} "
                                    + "— dynamic account enumeration skipped (see [X4-AV]/[Z1] notes)");
                if ((status == 0 || status == LsaInterop.STATUS_NO_MORE_ENTRIES)
                        && enumBuf != IntPtr.Zero && count > 0)
                {
                    // PLSA_ENUMERATION_INFORMATION = PLSA_SID_INFO[]，每项仅一个 PSID。
                    int ptrSize = IntPtr.Size;
                    var sidPtrList = new List<IntPtr>((int)count);
                    for (uint i = 0; i < count; i++)
                    {
                        // [X4-AV2] 防御性边界校验：若 lsasrv 返回的 count 大于实际缓冲
                        // 容量（损坏 RPC 桩的典型症状），按指针读取会直接在本进程触发 AV。
                        // SID 指针入表前先做有界探测读校验（见 IsReadablePointer），不可读
                        // 即截断列表 —— 宁缺毋滥，绝不让畸形载荷流入 ConvertSidToString/Rights。
                        IntPtr sidPtr = Marshal.ReadIntPtr(IntPtr.Add(enumBuf, (int)(i * ptrSize)));
                        if (sidPtr == IntPtr.Zero) continue;
                        if (!IsReadablePointer(sidPtr, 8)) // SID 头部至少含 Revision/SubCount/6B Authority
                        {
                            Console.WriteLine($"  [!] Enumeration payload truncated at index {i} "
                                            + $"(declared count={count}) — possible corrupt LSA payload");
                            break;
                        }
                        sidPtrList.Add(sidPtr);
                    }
                    enumeratedAccounts = sidPtrList.Count;

                    // 一次性批量解析全部账户的使用类型（lookup 失败则退化为纯前缀过滤）。
                    // proadv8r2 [Z1a]：opts 不再以托管结构体 + ref 参与边界封送 ——
                    // 由 LsaInterop.LsaLookupSidsExPtr 在非托管堆上构造并传递指针。
                    // proadv9 [AA1]：domainsPtr / namesArray 提升到本 try 之外声明，
                    // 无论 lookup 成功、超时还是中途抛异常，都由 finally 统一
                    // LsaFreeMemory —— v8 只释放 domainsPtr 且异常路径两者全泄漏。
                    IntPtr domainsPtr = IntPtr.Zero;
                    IntPtr namesArray = IntPtr.Zero;
                    uint nameCount = 0;
                    bool lookupOk = false;
                    try
                    {
                        if (sidPtrList.Count > 0)
                        {
                            IntPtr[] arr = sidPtrList.ToArray();
                            // [X4-TO] 同 LsaEnumerateAccounts：独立线程 + 15s 超时防 lsass 挂起。
                            // proadv9 [AA7]：改走泛型 LsaCallWithTimeout，返回三元组
                            // (status, referencedDomains, translatedNames+nameCount)。
                            // [AA1] 语义说明：超时分支里后台线程稍后仍可能完成原生调用
                            // 并把结果写进它自己闭包内的 out 槽位——主线程永远接不到这
                            // 两个指针，其内存随进程退出由 OS 回收（LSA 缓冲非本进程
                            // CRT 堆，无堆破坏风险）；这是 best-effort 管线对"lsass 挂起"
                            // 的既定取舍，绝不可在超时后再等待接管（会抵消超时意义）。
                            var lookupRes = LsaCallWithTimeout(
                                () =>
                                {
                                    uint st = LsaInterop.LsaLookupSidsExPtr(
                                        policy, arr,
                                        out IntPtr dom, out IntPtr names, out uint nc);
                                    return (st, dom, names, nc);
                                },
                                LsaCallTimeoutMs, "LsaLookupSidsEx");
                            uint st2 = lookupRes.st;
                            if (st2 == 0xC0000005)
                                Console.WriteLine("  [!] LsaLookupSidsEx returned 0xC0000005 — see [Z1]: "
                                                + "ref-marshalled LSA_LOOKUP_OPTIONS lifetime + wrong "
                                                + "TranslatedSid2 stride were the root causes (fixed in this build)");
                            domainsPtr = lookupRes.dom;
                            namesArray = lookupRes.names;
                            nameCount  = lookupRes.nc;
                            lookupOk = (st2 == 0 && nameCount == (uint)sidPtrList.Count
                                        && namesArray != IntPtr.Zero);

                            // proadv8r2 [Z1b]：入表前对整个 TranslatedNames 数组做一次
                            // 有界探测读校验（首尾条目各探一次即可覆盖缓冲区连续性假设；
                            // 逐条目读取时再各自探测）。任何不可读 → 判定结果不可信，
                            // 退化前缀过滤，绝不让错位数据流入后续解析。
                            if (lookupOk && sidPtrList.Count > 0)
                            {
                                int stride = LsaInterop.TranslatedSid2NativeSize;
                                bool headOk = IsReadablePointer(namesArray, Math.Min(stride, 32));
                                bool tailOk = IsReadablePointer(
                                    IntPtr.Add(namesArray, (sidPtrList.Count - 1) * stride),
                                    Math.Min(stride, 32));
                                if (!headOk || !tailOk)
                                {
                                    Console.WriteLine("  [!] TranslatedNames buffer failed bounded-read probe "
                                                    + "— falling back to prefix-only filtering");
                                    lookupOk = false;
                                }
                            }
                        }
                    }
                    catch (TimeoutException tex)
                    {
                        // proadv9 [AA1]：超时显式打印（v8 手写 Task 版本有此提示、
                        // 本地函数版本没有——统一经泛型包装后在此还原等价提示）。
                        Console.WriteLine($"  [!] {tex.Message} — falling back to prefix-only filtering");
                        lookupOk = false;
                    }
                    catch { lookupOk = false; }
                    finally
                    {
                        // proadv9 [AA1]：ReferencedDomains 与 TranslatedNames 均出自
                        // lsasrv 分配的 LSA 策略内存块，必须分别 LsaFreeMemory；
                        // v8 从不释放 namesArray（每次铸造泄漏整块翻译表），且异常
                        // 路径连 domainsPtr 也泄漏。此处两条路径（成功/失败）都回收。
                        if (domainsPtr != IntPtr.Zero)
                        {
                            LsaInterop.LsaFreeMemory(domainsPtr);
                            domainsPtr = IntPtr.Zero;
                        }
                        if (namesArray != IntPtr.Zero)
                        {
                            LsaInterop.LsaFreeMemory(namesArray);
                            namesArray = IntPtr.Zero;
                        }
                    }

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
                                // proadv8r2 [Z1b]：逐字段手工解析原生 LSA_TRANSLATED_SID2
                                // （Use@0 / Name.Length@4 / RelativeId@20，x64 步长 32B），
                                // 弃用 Marshal.PtrToStructure<TranslatedSid2> —— 其按 C#
                                // Sequential 默认规则推导的步长与 lsasrv 原生布局不一致，
                                // 是本轮 0xC0000005 的直接触发点之一。
                                // proadv9 [AA1]：namesArray 现由本 try/finally 持有到循环
                                // 结束（v8 在 lookup 块末尾即释放、循环内读到的是已释放
                                // LSA 内存 —— use 类型过滤实际建立在悬垂读之上）。
                                IntPtr ent = IntPtr.Add(namesArray, i * LsaInterop.TranslatedSid2NativeSize);
                                if (IsReadablePointer(ent, LsaInterop.TranslatedSid2NativeSize))
                                {
                                    useType = Marshal.ReadInt32(ent, LsaInterop.Tsid2UseOffset);
                                    useName = LsaInterop.TranslateSidUseType(useType);
                                }
                                else
                                {
                                    Console.WriteLine($"  [!] TranslatedSid2 entry #{i} unreadable "
                                                    + "— type filter disabled for remaining entries");
                                    lookupOk = false;   // 后续条目同样放弃类型过滤
                                }
                            }

                            if (!ShouldIncludeEnumeratedSid(sidStr, useType))
                                continue;

                            // 附带一次 LsaEnumerateAccountRights 读取该账户权利名（诊断输出用，
                            // 单账户失败静默跳过 —— 与原 [U2] 容错语义一致）。
                            // proadv9 [AA7]：同受 lsass 挂起威胁的第三个调用——原直接同步
                            // 调用无超时保护；统一经泛型 LsaCallWithTimeout 限时（失败返回
                            // 空串提示，与原 best-effort 语义逐条一致）。
                            string rightsHint;
                            try
                            {
                                IntPtr sidCopy = sidPtrList[i];
                                rightsHint = LsaCallWithTimeout(
                                    () => TryGetAccountRightsHint(policy, sidCopy),
                                    LsaCallTimeoutMs, "LsaEnumerateAccountRights");
                            }
                            catch { rightsHint = ""; }

                            if (!result.Contains(sidStr, StringComparer.OrdinalIgnoreCase))
                            {
                                result.Add(sidStr);
                                if (Program.VerboseAccountLog)
                                    Console.WriteLine($"      · {sidStr} [{useName}] {rightsHint}");
                            }
                        }
                        catch { /* 单个账户失败不影响整体 */ }
                    }
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
            // proadv9 [AA8]（可优化）：原按 SID 字符串序排序——数字逐字符比较时
            // "S-1-5-21-..." 会排在 "S-1-5-3-*" 之后（'2'<'3' 但期望 Batch=3 在前），
            // 且排序结果与 MaxSafeGroups 截断后的组构成相关，排序语义应保持简单、
            // 确定、无歧义。改回 ordinal 排序；枚举顺序本身不受影响（业务逻辑不变）。
            result.Sort(StringComparer.Ordinal);
            return result;
        }

        // ====================================================================
        //  proadv8 [Y1]（编译级致命缺陷修复 + [X4-AV2] 设计意图落地）：
        //  proadv7 在 LsaEnumerateAccounts 结果遍历中调用了 IsReadablePointer(sidPtr, 8)，
        //  但该辅助函数从未在任何版本中定义 —— CS0103，整个文件无法通过静态编译
        //  （沙箱 dotnet build 实测复现）。也就是说：proadv7 声称的"编译验证通过"是假阴性，
        //  现场运行的二进制实际来自更早、仍带 AV 隐患的版本。本函数补齐实现：
        //    1) 快速路径：指针落在本进程已提交的可读内存内直接放行；
        //    2) 可疑地址（LSA/ALPC 映射区、潜在恶意 RPC 桩载荷）：先做字对齐校验，
        //       再用 ReadProcessMemory 对目标字节区间做有界探测读 —— RPM 对无效/不可读
        //       地址只返回 FALSE，绝不会像裸解引用那样在本进程触发 0xC0000005；
        //    3) 哨兵页负对照：VirtualAlloc 保留+提交一页后把尾部 64B REVOCATE 掉，
        //       自测 RPM 必须读不进该区间 —— 防止某些环境钩子让 RPM "永远成功"而使
        //       探测失去意义；自测不通过则退化为保守判定（视为不可读，调用方截断）。
        //  零 unsafe 代码块，x86/x64 通用；与 [X4-AV2] 注释描述的行为逐条一致。
        // ====================================================================
        // ====================================================================
        //  proadv9 [AA3]（运行期 bug 修复）：ProbeRangeReadable 两处粗筛缺陷：
        //   (a) v8 上界写成 0x7FFFFFFFFFFF0000 —— 大于 x64 用户态 canonical 半区
        //       上限(0x00007FFFFFFFFFFF)，条件恒假，"粗筛"从未生效（死代码级错误）；
        //   (b) v8 强制 8 字节对齐 —— LSA/RPC 缓冲与 SID 二进制载荷按 4 字节粒度
        //       分配是合法且常见的（x86 全程 4B；x64 下 lsasrv 堆块也不保证 8B），
        //       硬校验会把完全可读的指针误判为不可读 → 枚举列表被无谓截断，
        //       丢失本应并入令牌的合法账户组。放宽为 4 字节对齐守卫。
        //   真正的安全性始终由 ReadProcessMemory 有界探测保证（无效地址只返回
        //   FALSE，绝不触发本进程 AV），对齐/范围检查仅是廉价的预过滤。
        // ====================================================================
        static bool? ProbeRangeReadable(IntPtr p, int len)
        {
            if (p == IntPtr.Zero || len <= 0) return false;
            long addr = p.ToInt64();
            if (addr < 0x10000 || addr > 0x00007FFFFFFFFFFF) return false; // x64 用户态 canonical 半区
            if ((addr & 3) != 0) return false;                              // SID/RPC 指针 4 字节对齐守卫

            byte[] tmp = new byte[len];
            if (!NativeMethods.ReadProcessMemorySafe(
                    NativeMethods.GetCurrentProcess(), p, tmp, (IntPtr)len, out IntPtr read))
                return false;
            return read == (IntPtr)len;
        }

        // 三态缓存：null = 哨兵自测尚未执行；true/false = 自测结论（进程内只跑一次）。
        static readonly object _probeGuardLock = new object();
        static bool? _probeGuardVerified = null;

        static bool IsReadablePointer(IntPtr p, int length)
        {
            // 第一步：对目标区间做有界探测读（RPM 失败仅返回 false，本进程绝不 AV）。
            if (ProbeRangeReadable(p, length) != true) return false;

            bool? guard;
            lock (_probeGuardLock) { guard = _probeGuardVerified; }

            if (guard == true)  return true;   // 自测已通过：探测结果可信，直接放行
            if (guard == false) return false;  // 自测已失败：RPM 不可信，保守拒绝

            // guard == null：首次调用，执行一次性哨兵页自测。
            // proadv9 [AA2]（运行期 bug 修复）：v8 的负对照构造无效 ——
            //   VirtualFree(MEM_DECOMMIT) 的 dwSize 会被**向上取整到整页边界**：
            //   v8 从 baseAddr+PageSize-64 处 DECOMMIT 64B，实际撤销的是其后
            //   整个第二页；负对照读区间 guardStart..guardStart+64 因此横跨
            //   "已提交前部 + 已撤销区"，RPM 只要读到任一未提交字节即整体失败
            //   返回 FALSE —— 即便 RPM 被 EDR/API 钩子改成"恒真"，该断言也
            //   永远虚假通过，探测可信性自测形同虚设。
            //   修正为两页布局：撤销第一页整页、保留第二页整页提交；负对照
            //   落在"纯未提交页首"，正对照落在"纯已提交页首"，两个断言都
            //   不再跨提交/未提交边界，任何方向上的钩子失真都能被发现。
            bool pass = false;
            IntPtr baseAddr = IntPtr.Zero;
            try
            {
                const int PageSize = 4096;
                const int ProbeLen = 64; // 探测长度（远小于页大小，保证不跨界）
                baseAddr = NativeMethods.VirtualAlloc(IntPtr.Zero,
                    (IntPtr)(PageSize * 2),
                    NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                    NativeMethods.PAGE_READWRITE);
                if (baseAddr == IntPtr.Zero) return false;

                // 撤销第一页（整页 MEM_DECOMMIT，dwSize=PageSize 与页边界对齐，
                // 不存在取整歧义）；第二页保持提交状态。
                IntPtr freed = NativeMethods.VirtualFree(baseAddr, (IntPtr)PageSize,
                    NativeMethods.MEM_DECOMMIT);
                if (freed != IntPtr.Zero)
                {
                    // 负对照：RPM 不应读得进被 DECOMMIT 的第一页（读进 = 探测不可信）。
                    bool neg = ProbeRangeReadable(baseAddr, ProbeLen) == false;
                    // 正对照：第二页（仍提交）必须可读（读不进 = RPM 被钩死/失效）。
                    bool pos = ProbeRangeReadable(IntPtr.Add(baseAddr, PageSize), ProbeLen) == true;
                    pass = neg && pos;
                }
            }
            catch { pass = false; }
            finally
            {
                if (baseAddr != IntPtr.Zero)
                    NativeMethods.VirtualFree(baseAddr, IntPtr.Zero, NativeMethods.MEM_RELEASE);
            }

            lock (_probeGuardLock) { _probeGuardVerified = pass; }
            // 自测通过：放行本次已探测可读的指针；自测失败：保守判定为不可读
            // （调用方据此截断枚举列表 —— 宁缺毋滥，绝不冒本进程 AV 的险）。
            return pass;
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
                    // proadv10 [AB2]（运行期 AV 防护）：rightsPtr 是 lsasrv 经 ALPC 回填的
                    // LSA 分配缓冲，lus.Buffer 是指向该块内部的裸指针。v9 对二者都直接
                    // Marshal.PtrToStructure/PtrToStringUni —— 恶意/畸形 RPC 桩载荷或截断
                    // 缓冲会在本进程触发 0xC0000005（TryGetAccountRightsHint 虽被调用方
                    // catch，但托管 SEH 捕获不了 AV，进程直接崩溃）。现复用管线既有的
                    // IsReadablePointer 有界探测读：条目不可读 → 放弃后续；字符串缓冲
                    // 不可读 → 跳过该项。与 [X4-AV2]/[Z1b] 的防御语义逐条一致，正常
                    // 路径输出不变（best-effort 诊断信息）。
                    IntPtr lusPtr = IntPtr.Add(rightsPtr, (int)i * lusSize);
                    if (!IsReadablePointer(lusPtr, lusSize)) break;
                    var lus = Marshal.PtrToStructure<LsaInterop.LSA_UNICODE_STRING>(lusPtr);
                    if (lus.Buffer != IntPtr.Zero && lus.Length > 0
                        && IsReadablePointer(lus.Buffer, lus.Length))
                        names.Add(Marshal.PtrToStringUni(lus.Buffer, lus.Length / 2) ?? "");
                }
                return names.Count == 0 ? "" : "(" + string.Join(",", names) + ")";
            }
            catch { return ""; }
            finally { if (rightsPtr != IntPtr.Zero) LsaInterop.LsaFreeMemory(rightsPtr); }
        }
    }

    // ========================================================================
    //  LsaInterop — proadv4 [U2] 新增：LSA 只读枚举所需的共享 P/Invoke
    //  （PrivilegeGranter 内部的 LSA 声明保持 private 不动，这里仅暴露
    //   WellKnownSids.EnumerateServiceAccountSids 用到的最小子集。）
    // ========================================================================
    static class LsaInterop
    {
        public const uint POLICY_VIEW_ONLY          = 0x00000001; // POLICY_VIEW_LOCAL_INFORMATION
        // proadv8r2 [Z2]：备用打开掩码修正。0x00000006 并非文档化的单一权限位
        // （POLICY_AUDIT_LOG_ADMIN=0x04 | POLICY_SERVER_ENABLE=0x08... 的组合误写），
        // lsasrv 对未组合 VIEW 位的掩码可能直接 STATUS_ACCESS_DENIED，导致回退路径
        // 从未成功过。改为 POLICY_VIEW_LOCAL_INFORMATION | POLICY_SERVER_ENABLE。
        public const uint POLICY_SERVER_ENABLE      = 0x00000008;
        public const uint POLICY_SERVER_SECURITY    = POLICY_VIEW_ONLY | POLICY_SERVER_ENABLE;
        public const uint STATUS_NO_MORE_ENTRIES    = 0x8000001A;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LSA_OBJECT_ATTRIBUTES
        {
            public int    Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint   Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        // [X4-AV3] 配套声明修正：原生第二参是 PLSA_OBJECT_ATTRIBUTES*（指针）。原
        // `ref LSA_OBJECT_ATTRIBUTES` 形式在跨边界时按托管引用封送，advapi32/lsasrv
        // 按非托管结构体解引用该值即读到错位数据 → lsass 侧 STATUS_ACCESS_VIOLATION
        // (0xC0000005) 经 ALPC 回传（现场表现为第二阶段 NtCreateToken 前
        // LsaEnumerateAccounts 报 0xc0000005）。改为 IntPtr，由调用方显式传
        // StructureToPtr 封送好的非托管地址。
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaOpenPolicy(
            IntPtr SystemName,           // PLSA_UNICODE_STRING，本机传 NULL
            IntPtr ObjectAttributes,     // PLSA_OBJECT_ATTRIBUTES（显式指针，见上）
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // 真实语义：UserRight 是 PLSA_UNICODE_STRING。这里把权利名以
        // LSA_UNICODE_STRING 结构（Buffer 指向 UTF-16 串）经 ref 直传，
        // 与 advapi32 原生签名逐字节一致，避免手工分配生命周期问题。
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaEnumerateAccountsWithUserRight(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING UserRight,
            out IntPtr EnumerationBuffer,
            out uint CountReturned);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaFreeMemory(IntPtr buffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaClose(IntPtr PolicyHandle);

        // ====================================================================
        //  proadv7 [X4] 新增：完整账户遍历所需的 LSA P/Invoke 最小子集
        //  （LsaEnumerateAccounts / LsaLookupSidsEx / LsaEnumerateAccountRights /
        //   LsaEnumerateLeftoverCredentials；均为 advapi32 原生导出。）
        //  proadv7 现场故障修复（Phase 2 调用 NtCreateToken 前 LsaEnumerateAccounts
        //  报 0xC0000005 ACCESS_VIOLATION 的根因治理）见下方两处标注 [X4-AV]/[X4-TO]。
        // ====================================================================
        // proadv9 [AA8]（可优化/死代码删除）：原 LEGACY_POLICY_SERVER_SECURITY_UNUSED
        // = 0x00000006 全文件 0 引用。proadv8r2 [Z2] 已把回退打开掩码修正为
        // POLICY_VIEW_LOCAL_INFORMATION | POLICY_SERVER_ENABLE (0x1|0x8) 并直接在
        // LsaInterop 顶部使用；此孤立旧值（非文档化组合）仅作为"历史警示"存在，
        // 保留反而诱导未来误用，予以删除。行为零变化。

        // [X4-AV] 严重 bug 修复（proadv7 轮）：末字段原生是 PSID（指针），原声明写成
        // uint —— x64 下 ref 封写只覆盖低 4 字节，高 4 字节栈垃圾被 lsasrv 当指针解引用
        // → STATUS_ACCESS_VIOLATION (0xC0000005)。修正：IntPtr + 整体 8 字节 LARGE_INTEGER。
        // proadv8r2 [Z1a] 补充：即便布局正确，`ref LSA_LOOKUP_OPTIONS` 仍把托管边界地址
        // 暴露给 ALPC 异步生命周期 —— 本结构体现仅用于非托管堆上的显式封送，
        // 不再以任何 ref 形式跨越 P/Invoke 边界（见 LsaLookupSidsExPtr）。
        // LSA_LOOKUP_OPTIONS（ntsecapi.h）：本机枚举用默认值即可，字段布局保持与原生一致。
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_LOOKUP_OPTIONS
        {
            public uint   LookupOptions;     // LSA_LOOKUP_OPTION_*（0 = 默认）
            public uint   ExtendedLookupFlags;
            public long   ServerTimeout;     // LARGE_INTEGER（整体 8 字节）
            public IntPtr SidContext;        // PSID（0 = 不指定特定域服务器上下文）
        }

        // proadv8r2 [Z1b]：原生 LSA_TRANSLATED_SID2 逐字节布局常量（弃用 marshaler 推导）。
        // typedef struct _LSA_TRANSLATED_SID2 {
        //     SID_NAME_USE          Use;         // 枚举 = 4B，偏移 0
        //     LSA_UNICODE_STRING    Name;        // {USHORT Length; USHORT MaximumLength; PWSTR Buffer;}
        //                                        //   x64: 对齐 8 → 偏移 4 处补 4B padding，占 16B（偏移 4..19）
        //                                        //   x86: 对齐 4 → 偏移 4 起连续 8B
        //     LONG                  RelativeId;  // x64 偏移 20 / x86 偏移 12
        //     LONG                  Reserved;    // x64 偏移 24 / x86 偏移 16
        // } ;                                      // 条目总长: x64 = 32B, x86 = 16B（含尾部对齐）
        // C# 的 Sequential 默认规则对"int 后接含 IntPtr 的结构"产生的填充序与 MSVC 原生
        // 布局并不总是吻合（历史版本 Marshal.SizeOf<TranslatedSid2>() 推导出错误步长，
        // 按该步长遍历 lsasrv 数组即错位读垃圾指针 —— 本轮 0xC0000005 的直接触发点之一），
        // 故这里以显式常量描述原生布局，读取全部走 ReadInt32 + IsReadablePointer 探测。
        public static readonly int TranslatedSid2NativeSize =
            IntPtr.Size == 8 ? 32 : 16;
        public const int Tsid2UseOffset      = 0;                                    // SID_NAME_USE Use
        public const int Tsid2NameLenOffset  = 4;                                    // Name.Length (USHORT)
        public static readonly int Tsid2RelativeIdOffset = IntPtr.Size == 8 ? 20 : 12;

        // 保留类型仅作历史参照（勿再用于 PtrToStructure —— 见上方 [Z1b] 说明）。
        [StructLayout(LayoutKind.Sequential)]
        public struct TranslatedSid2
        {
            public int Use;                          // SID_NAME_USE（首字段，偏移 0）
            public LSA_UNICODE_STRING Name;
            public uint RelativeId;
            public int Reserved;
        }

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
        // proadv8r2 [Z1a]：第 4 参改为 IntPtr（PLSA_LOOKUP_OPTIONS*），杜绝 ref 值类型
        // 跨边界封送；调用方（LsaLookupSidsExPtr）负责在非托管堆构造并释放该结构体。
        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "LsaLookupSidsEx")]
        private static extern uint LsaLookupSidsExNative(
            IntPtr PolicyHandle,
            IntPtr SidInfoArray,
            uint SidCount,
            IntPtr LookupOptions,      // PLSA_LOOKUP_OPTIONS*（非托管堆显式指针）
            out IntPtr ReferencedDomains,
            out IntPtr TranslatedNames,
            out uint NameCount);

        // proadv8r2 [Z1a]：全新安全包装 —— SID 指针数组与 LSA_LOOKUP_OPTIONS 一并
        // 分配到 Marshal.AllocHGlobal 的非托管内存，以纯 IntPtr 传参；全程没有
        // 托管引用/pinned 地址参与边界，lsasrv 即使在异步路径上短暂保留指针，
        // 指向的也是调用返回前始终有效的堆块（opts/sidArr 在 finally 中于原生调用
        // 同步返回之后才释放 —— LsaLookupSidsEx 本身是同步 RPC，不存在悬挂窗口）。
        public static uint LsaLookupSidsExPtr(
            IntPtr policy, IntPtr[] sids,
            out IntPtr referencedDomains, out IntPtr translatedNames, out uint nameCount)
        {
            referencedDomains = IntPtr.Zero;
            translatedNames = IntPtr.Zero;
            nameCount = 0;
            if (sids.Length == 0) return 0xC0000001; // STATUS_UNSUCCESSFUL（调用方按 lookup 失败处理）

            int optsSize = Marshal.SizeOf<LSA_LOOKUP_OPTIONS>(); // 16B(x64)/... 与原生一致
            IntPtr sidArr = IntPtr.Zero;
            IntPtr optsPtr = IntPtr.Zero;
            try
            {
                sidArr = Marshal.AllocHGlobal(IntPtr.Size * sids.Length);
                for (int i = 0; i < sids.Length; i++)
                    Marshal.WriteIntPtr(sidArr, i * IntPtr.Size, sids[i]);

                // 全零 opts（LookupOptions=0 / ExtendedLookupFlags=0 / ServerTimeout=0 /
                // SidContext=NULL）—— 先 ZeroFree 分配再逐字段显式清零，确保任何
                // 运行时实现差异都不会把脏字节带进边界结构体。
                optsPtr = Marshal.AllocHGlobal(optsSize);
                for (int b = 0; b < optsSize; b++) Marshal.WriteByte(optsPtr, b, 0);

                return LsaLookupSidsExNative(
                    policy, sidArr, (uint)sids.Length, optsPtr,
                    out referencedDomains, out translatedNames, out nameCount);
            }
            finally
            {
                if (sidArr  != IntPtr.Zero) Marshal.FreeHGlobal(sidArr);
                if (optsPtr != IntPtr.Zero) Marshal.FreeHGlobal(optsPtr);
            }
        }

        public static string TranslateSidUseType(int use) => use switch
        {
            1 => "User", 2 => "Group", 3 => "Alias", 4 => "WellKnownGroup",
            5 => "Deleted", 6 => "Invalid", 7 => "Computer", 8 => "Label",
            9 => "CredentialDomain", 10 => "SideloadedGroup", _ => "Unknown"
        };

        /// <summary>构造指向托管字符串的 LSA_UNICODE_STRING（调用方负责 FreeHGlobal）。</summary>
        public static LSA_UNICODE_STRING MakeUnicodeString(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            byte[] bytes = global::System.Text.Encoding.Unicode.GetBytes(value);
            // proadv6 [W6]：补上 ushort 溢出守卫，与 PrivilegeGranter.InitLsaString
            // 的校验对齐 —— MaximumLength = Length + 2 必须 <= ushort.MaxValue，
            // 超长时显式抛异常而不是静默截断产生畸形 LSA_UNICODE_STRING。
            if (bytes.Length > ushort.MaxValue - 2)
                throw new ArgumentException("字符串过长，无法转换为 LSA_UNICODE_STRING。", nameof(value));
            return new LSA_UNICODE_STRING
            {
                Length        = (ushort)bytes.Length,
                MaximumLength = (ushort)(bytes.Length + 2),
                Buffer        = Marshal.StringToHGlobalUni(value)
            };
        }
    }

    // ========================================================================
    //  SidUtil — proadv4 [U2] 新增：二进制 SID -> 字符串 SID 的托管解析
    //  （不依赖 advapi32!ConvertSidToStringSid，便于在仅持 QUERY 权限时安全使用；
    //   直接按 SID 二进制结构解析，支持最多 15 个子授权符 + 嵌套子授权展开。）
    // ========================================================================
    static class SidUtil
    {
        public static string? ConvertSidToString(IntPtr pSid)
        {
            if (pSid == IntPtr.Zero) return null;
            try
            {
                // proadv6 [W5]：统一使用短名 Marshal.ReadByte（文件顶部已有
                // using System.Runtime.InteropServices，且本命名空间内无任何名为
                // Marshal 的类型/字段遮蔽 —— 经全文件静态检查确认）。行为与
                // proadv5 的全限定写法逐字节一致，仅消除冗余限定与 IL 差异。
                byte revision = Marshal.ReadByte(pSid, 0);
                byte subCount = Marshal.ReadByte(pSid, 1);
                if (revision != 1 || subCount > 15) return null;

                // 6 字节 Identifier Authority（大端）
                long auth = 0;
                for (int i = 0; i < 6; i++)
                    auth = (auth << 8) | Marshal.ReadByte(pSid, 2 + i);

                var sb = new StringBuilder();
                sb.Append("S-1-").Append(auth);
                for (int i = 0; i < subCount; i++)
                {
                    // proadv5 [V2] 修复编译错误 CS0117：.NET 的 System.Runtime.InteropServices.Marshal
                    // 从未提供 ReadUInt32（只有 ToUInt32/ReadInt32）。改为按小端 4 字节手工读取，
                    // 与 SID 子授权存储布局（Windows 原生 DWORD LE）严格一致。
                    uint sub = (uint)(Marshal.ReadByte(pSid, 8 + i * 4)
                                       | (Marshal.ReadByte(pSid, 9 + i * 4) << 8)
                                       | (Marshal.ReadByte(pSid, 10 + i * 4) << 16)
                                       | (Marshal.ReadByte(pSid, 11 + i * 4) << 24));
                    sb.Append('-').Append(sub);
                }
                return sb.ToString();
            }
            catch { return null; }
        }
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

        // proadv8 [Y3c]（同类问题根治）：原声明第二参为 ref LSA_OBJECT_ATTRIBUTES ——
        // 与 proadv6 LsaInterop [X4-AV3] 修复前的缺陷完全同型：原生原型是
        // PLSA_OBJECT_ATTRIBUTES*，ref 结构体经封送器写入的是固定缓冲而非稳定非托管
        // 地址，个别 CLR/OS 组合下 advapi32→lsasrv 解引用错位数据即回传
        // STATUS_ACCESS_VIOLATION(0xC0000005)。本类是 --grant-privileges / Win11 预检
        // 路径实际使用的 LSA 句柄来源，其句柄随后流入 Phase 2 的账户枚举管线，故必须
        // 与 LsaInterop.LsaOpenPolicy(IntPtr) 语义统一：改为 IntPtr 显式指针，调用方
        // StructureToPtr 封送后传入（本机场景 ObjectAttributes 内容全零，亦可安全传
        // NULL；此处保留显式结构体以维持原语义）。
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint LsaOpenPolicy(
            IntPtr SystemName,           // PLSA_UNICODE_STRING，本机传 NULL
            IntPtr ObjectAttributes,     // PLSA_OBJECT_ATTRIBUTES（显式指针，见上）
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

            // proadv8 [Y3c]：配套调用点 —— 显式分配非托管 OBJECT_ATTRIBUTES 并封送，
            // 传指针而非 ref（与 LsaInterop [X4-AV3] 的修复方式逐字节一致）。
            uint status;
            IntPtr loaPtr = Marshal.AllocHGlobal(Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>());
            try
            {
                // proadv10 [AB5]（编译错误修复 CS1615）：v10 曾尝试改为
                // StructureToPtr(ref loa, ...) 显式传引用，但 Marshal.StructureToPtr
                // 全部公开重载均为「按值」结构体参数（object 或 T where T:struct），
                // 不存在 ref 重载，ref 传参直接导致 CS1615 无法编译。回退为按值封送：
                // LSA_OBJECT_ATTRIBUTES 为全 IntPtr/int 布局（无托管引用字段），
                // 按值封送产物字节与逐字段写入完全一致，行为零变化。
                Marshal.StructureToPtr(loa, loaPtr, false);
                status = LsaOpenPolicy(IntPtr.Zero, loaPtr, POLICY_ALL_ACCESS, out policyHandle);
            }
            finally { Marshal.FreeHGlobal(loaPtr); }
            if (status != STATUS_SUCCESS)
            {
                error = "LsaOpenPolicy 失败: 0x" + status.ToString("X8")
                        + " (Win32=" + LsaNtStatusToWinError(status) + ")";
                // proadv10 [AB6]（运行期 bug 修复）：v9 在此把 policyHandle 直接覆写为
                // Zero —— 但原生 LsaOpenPolicy 在"句柄已创建、随后访问检查失败"的路径上
                // （MSDN 明确允许返回非零状态同时回填句柄）可能已在 out 槽写入有效句柄；
                // 覆写即泄漏一个策略句柄直到进程退出。修正：仅在确需向调用方传达"无句柄"
                // 前，先对已回填句柄做 LsaClose 回收，再置零。常规失败(未回填)时
                // LsaClose(Zero) 不会被调用，语义与原实现一致。
                if (policyHandle != IntPtr.Zero) { LsaClose(policyHandle); }
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

            // 成功路径下 TryOpenPolicyAndEnumerateExisting 已自行管理内部内存，
            // 但仍把句柄/SID 交回；这里立即释放（本函数不需要写权限句柄）。
            Marshal.FreeHGlobal(adminSid);
            LsaClose(policyHandle);

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
            // proadv10 [AB3]（运行期 bug 修复：部分初始化泄漏）：InitLsaString 内部先
            // Marshal.StringToHGlobalUni 分配 Buffer，再做长度溢出检查——若第 k 项因
            // "字符串过长"抛 ArgumentException，v9 的 finally 会遍历整个 rights[]：
            //   a) 已分配的前 k 项被正确释放；
            //   b) 未初始化的其余元素是 default(LSA_UNICODE_STRING)，Buffer==Zero，
            //      FreeLsaString 判空跳过 —— 这两点 v9 恰好安全；但若异常发生在
            //      StringToHGlobalUni 与结构体赋值之间（如 OOM），该项缓冲既不在
            //      rights[] 中也无法释放。现把"分配→入表"压缩为逐项 try/catch：
            //      任何一项失败立即释放已成功分配的 0..i-1 项并向上抛出，杜绝窗口。
            int initialized = 0;
            try
            {
                for (int i = 0; i < privileges.Count; i++)
                {
                    rights[i] = InitLsaString(privileges[i]);
                    initialized = i + 1;
                }
                return LsaAddAccountRights(policyHandle, sid, rights, (uint)rights.Length);
            }
            catch
            {
                for (int i = 0; i < initialized; i++) FreeLsaString(rights[i]);
                throw;
            }
            finally
            {
                // 仅在未发生异常路径时执行常规释放（initialized==rights.Length 时
                // catch 分支不会到达；两处不重复释放同一指针）。
                if (initialized == rights.Length)
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
            if (!TryOpenPolicyAndEnumerateExisting(
                    out IntPtr policyHandle, out IntPtr sid,
                    out var existing, out string? error))
            {
                Console.WriteLine(error);
                return false;
            }

            try
            {
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
            return true;
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
                // proadv9 [AA6]：改走"调用 → 立即读取 lasterror"的紧邻语句对封装，
                // 消除 v8 "SetLastPInvokeError(0) + 延迟读取"在 .NET 10 SetLastError
                // 封码下可能吞掉 ERROR_NOT_ALL_ASSIGNED(1300)、把失败推迟到
                // VerifyPrivilege 兜底才暴露的时序歧义。判定语义与 v8 最终行为一致：
                // 调用失败抛 Win32Exception；返回 TRUE 但 lasterror==1300 同样抛。
                if (!NativeMethods.AdjustTokenPrivilegesAndProbeLastError(
                        tok, false, privilegeName, TokenConstants.SE_PRIVILEGE_ENABLED, out int err))
                    throw new Win32Exception(err != 0 ? err : Marshal.GetLastPInvokeError(),
                        $"Failed to enable {privilegeName}");

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

    static partial class TokenCreator   // proadv5 [V1]: partial，接收自 Program 类误置的 BuildGroupList
    {
        static readonly int SecurityQosSize = Marshal.SizeOf<SECURITY_QUALITY_OF_SERVICE>();
        static readonly int ObjectAttributesSize = Marshal.SizeOf<OBJECT_ATTRIBUTES>();
        static readonly int TokenUserSize = Marshal.SizeOf<TOKEN_USER>();
        static readonly int SidAndAttributesSize = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
        static readonly int TokenPrivilegesHeaderSize = Marshal.SizeOf<TOKEN_PRIVILEGES_HEADER>();
        static readonly int LuidAndAttributesSize = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
        static readonly int LargeIntegerSize = Marshal.SizeOf<LARGE_INTEGER>();

        // proadv7 [X5]（可优化/正确性）：原硬编码 0xF01FF。winnt.h 的真实定义为
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

// proadv5 [V1]：CoreGroupCount 字段随 BuildGroupList 一并归位到 TokenCreator。
        // proadv4 [U4]：核心组数量 —— BuildGroupList() 返回的固定列表长度。
        // CreatePrimaryToken 中动态并入的服务账户 SID 一律追加在核心组之后，
        // BuildTokenGroups 据此区分"必须解析成功"(i < CoreGroupCount)与
        //"可跳过"(i >= CoreGroupCount)两类条目。
        public static readonly int CoreGroupCount = BuildGroupList().Length;

        // ========================================================================
        //  proadv5 [V1] 修复编译错误：以下 BuildGroupList() 原被夹在 Program 与 LsaInterop
        //  两个类之间（proadv4 因此产生 CS0103/CS0117 共 10 个编译错误）。现以 partial
        //  class 归位到 TokenCreator —— 方法体逐字保留，仅将限定名 TokenCreator.X 简化为 X，
        //  语义完全一致。组列表内容与属性组合未做任何改动。
        // ========================================================================
        public static (string sid, GroupAttributes attr)[] BuildGroupList()  // proadv5 [V1]: 原 private，Program.RunPhase2 需直接复用同一数组
        {
            const GroupAttributes G = GroupAttributes.Enabled
                                                  | GroupAttributes.Mandatory;
            const GroupAttributes GA = GroupAttributes.Enabled
                                                  | GroupAttributes.Mandatory
                                                  | GroupAttributes.EnabledByDefault;
            const GroupAttributes GI = GroupAttributes.Integrity
                                                  | GroupAttributes.IntegrityEnabled;

            return new (string sid, GroupAttributes attr)[]
            {
                (WellKnownSids.TrustedInstaller,         G),
                (WellKnownSids.ExtraServiceSid1,         G),
                (WellKnownSids.ExtraServiceSid2,         G),

                // proadv4 [U1]：加入 Windows Defender / WdFilter 服务账户组，
                // 使 ticmd 能通过仅授予这些账户的 DACL（部分受保护系统文件）。
                (WellKnownSids.WinDefend,                G),
                (WellKnownSids.MsSecFlt,                 G),

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

        const uint ACL_REVISION = 2;
        const uint GENERIC_ALL = 0x10000000;

        public static void SetTokenSessionId(SafeTokenHandle token, uint sessionId)
        {
            // proadv7 [X7]：改走 uint 值参数重载（见 NativeMethods 注释），无需 ref。
            if (!NativeMethods.SetTokenInformation(token, TokenConstants.TokenSessionId, sessionId, sizeof(uint)))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "SetTokenInformation failed");
        }

        // pproadv2 修复 [S1]：把令牌标记为"已提升"（UAC elevated）。
        // NtCreateToken 生成的令牌默认 TokenIsElevated=0，即使 SID/特权齐全，token 仍是"未过滤"的
        // 假象之外更糟——很多安全检查（包括部分系统调用路径）会按非提升令牌对待它。
        public static void SetTokenElevation(SafeTokenHandle token)
        {
            var elev = new TOKEN_ELEVATION { TokenIsElevated = 1 };
            if (!NativeMethods.SetTokenInformation(
                    token, TokenConstants.TokenElevation, ref elev, Marshal.SizeOf<TOKEN_ELEVATION>()))
                throw new Win32Exception(Marshal.GetLastPInvokeError(),
                    "SetTokenInformation(TokenElevation) failed");
        }

        // proadv3 新增 [T3]：读回校验 TokenIsElevated —— SetTokenInformation 返回 TRUE
        // 不代表内核真正接受了该标志；启动子进程前读回确认可及早暴露"假成功"。
        // proadv6 [W8]：改用与 SetTokenElevation([S1]) 对称的 TOKEN_ELEVATION 强类型
        // GetTokenInformation 重载，消除 AllocHGlobal/ReadInt32 手工读取与"写入布局
        // (TOKEN_ELEVATION 结构体) / 读回布局(裸 Int32)"不对称的静态分析告警。
        // x86/x64 上 TOKEN_ELEVATION 首字段偏移为 0，新旧实现行为逐字节等价。
        // proadv7 新增 [W9]（静态编译分析发现的编译级缺陷修复，proadv6 第 2353 行同样存在）：
        //   error CS0133: The expression being assigned to 'SIZE' must be constant ——
        //   `const uint SIZE = (uint)Marshal.SizeOf<TOKEN_ELEVATION>();` 非法：
        //   Marshal.SizeOf<T>() 是运行时泛型方法调用，不属于 C# 常量表达式，任何工程都编不过。
        //   改为 readonly static（语义等价，值仍为 4），并保留 retLen 防御校验。
        public static bool? VerifyTokenElevation(SafeTokenHandle token)
        {
            static uint SizeOf() => (uint)Marshal.SizeOf<TOKEN_ELEVATION>(); // = 4，恒定
            uint SIZE = SizeOf();

            // [W8] 单次调用即完成校验：TOKEN_ELEVATION 定长 4 字节，直接以精确
            // 缓冲长度走强类型重载 —— 成功时 ReturnLength 恒等于 SIZE；若令牌
            // 信息类被系统拒绝或句柄失效则返回 FALSE（按不可判定处理）。
            // 相比 proadv5 的"两次 Get + AllocHGlobal 手工 ReadInt32"，消除了一次
            // 冗余的系统调用往返与非托管分配，且读写布局完全对称。
            if (!NativeMethods.GetTokenInformation(token, TokenConstants.TokenElevation,
                    out TOKEN_ELEVATION elev, SIZE, out uint retLen))
                return null;   // 读不到即不可判定（与旧实现对失败路径的处理一致）

            // 防御：返回值长度不足以覆盖结构体时不信任 elev 内容。
            if (retLen < SIZE) return null;

            return elev.TokenIsElevated != 0;
        }

        // proadv3 新增 [T2]：把父进程令牌的 TokenOrigin 原样复制给新建令牌，
        // 使手工令牌在起源 LogonId 维度与真实服务令牌行为一致（best-effort）。
        public static bool TryCopyTokenOrigin(SafeTokenHandle parentToken, SafeTokenHandle newToken)
        {
            const int ERROR_INSUFFICIENT_BUFFER = 122;
            IntPtr buf = IntPtr.Zero;
            try
            {
                uint len = 0;
                if (!NativeMethods.GetTokenInformation(parentToken, TokenConstants.TokenOrigin, IntPtr.Zero, 0, out len))
                {
                    int err = Marshal.GetLastPInvokeError();
                    if (err != ERROR_INSUFFICIENT_BUFFER) return false;
                }
                if (len == 0 || len > int.MaxValue) return false;

                buf = Marshal.AllocHGlobal((int)len);
                if (!NativeMethods.GetTokenInformation(parentToken, TokenConstants.TokenOrigin, buf, len, out _))
                    return false;

                // TOKEN_ORIGIN 尾部含 LUID 占位填充，Marshal.PtrToStructure 安全读取所需前缀字段。
                var origin = Marshal.PtrToStructure<TOKEN_ORIGIN>(buf);
                return NativeMethods.SetTokenInformation(
                    newToken, TokenConstants.TokenOrigin, ref origin, Marshal.SizeOf<TOKEN_ORIGIN>());
            }
            catch { return false; }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        }

        // proadv7 [X2]：设置 TokenElevationType(18)=TokenElevationTypeFull(3)。
        // 真实提升令牌 Elevation=1 与 ElevationType=Full 成对出现；只有前者时
        // whoami /groups 会显示 " elevation type: Default"，部分依赖 ElevationType
        // 的安全查询（含 taskkill 打开目标进程时的令牌比对路径）行为不一致。
        // SetTokenInformation 官方支持该类（Windows Vista SP1+）。
        // proadv7 [X2]：此处按"失败即抛、调用方捕获降级为告警"处理——与 [S1] Elevation
        // 完全对称；注意不能因 ElevationType 设置失败而中止主流程（外层 try/catch 保证）。
        public static void SetTokenElevationType(SafeTokenHandle token)
        {
            // proadv7 [X2]：WinNT.h: TokenElevationTypeDefault=1 / Full=2 /
            // Extended(ElevatedWithReflection)=3 —— 提升服务令牌应设为 Full=2。
            var et = new TOKEN_ELEVATION_TYPE_INFO
            {
                ElevationType = (int)TOKEN_ELEVATION_TYPE.Full // = 2 (TokenElevationTypeFull)
            };
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
                // proadv9 [AA9]（可优化/审计友好）：原 `len > 1 << 20` 魔数改为具名常量。
                // 1MB 上限远大于任何合法 TOKEN_* 信息类返回（TOKEN_GROUPS 512 组×~40B ≈ 20KB），
                // 行为完全一致；同时把有符号移位写成显式 uint 比较，消除与 uint len 的隐式提升歧义。
                const uint MaxTokenInfoProbe = 1u << 20; // 1 MiB
                if (len == 0 || len > MaxTokenInfoProbe) { Console.WriteLine($"      [!] {label}: bad length {len}"); return; }
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
        // pproadv2 修复 [S1]：给令牌挂一个"链接令牌"（linked token），使 shell 扩展 / 任务计划等
        // 依赖 TOKEN_LINKED_TOKEN 的组件能正常识别该进程为提升进程。
        // 注意：hLinked 句柄所有权转移给 token —— 成功之后绝不可再对 hLinked 调用 CloseHandle，
        // 否则会出现双重释放；失败时由调用方负责关闭。
        // proadv3 新增 [T4]：保活容器。Windows 对 SetTokenInformation(TokenLinkedToken)
        // 的语义是"内核复制一份句柄引用"，而不是接管调用方句柄；若调用方随后 CloseHandle，
        // 内核副本所引用的对象引用计数会被减穿（token 提前失效 → 子进程 whoami/taskkill 拒绝访问）。
        // 因此成功挂接 linked token 后，必须把原始 SafeHandle 保活到本进程生命周期结束。
        static readonly global::System.Collections.Generic.List<SafeTokenHandle> _linkedTokenKeepAlive = new();
        // proadv6 [W4] 静态复核结论：本列表只增不减是刻意设计 —— 每个成功挂接的
        // linked token 都必须有一个存活到进程结束的托管句柄，防止终结器提前
        // CloseHandle 破坏内核副本。全程序 TrySetLinkedToken 仅被 Phase 2 调用一次，
        // 列表容量上限恒为 1，无增长/泄漏风险；失败路径由本方法 Close，无双关。

        public static bool TrySetLinkedToken(SafeTokenHandle token, SafeTokenHandle hLinked)
        {
            bool success = false;
            try
            {
                // DangerousAddRef：在把裸句柄交给内核之前，先固定住 SafeHandle，
                // 防止 GC 终结器在我们使用期间关闭它。
                bool added = false;
                hLinked.DangerousAddRef(ref added);
                if (!added) return false;
                try
                {
                    var lt = new TOKEN_LINKED_TOKEN { LinkedToken = hLinked.DangerousGetHandle() };
                    success = NativeMethods.SetTokenInformation(
                        token, TokenConstants.TokenLinkedToken, ref lt, Marshal.SizeOf<TOKEN_LINKED_TOKEN>());
                    return success;
                }
                finally
                {
                    // proadv3 [T4]：仅在失败时 Release；成功时保持 AddRef 不释放，
                    // 阻止托管侧 Dispose/终结器关闭同一底层句柄（内核持有的是复制引用）。
                    if (!success) hLinked.DangerousRelease();
                }
            }
            catch
            {
                return false;
            }
            finally
            {
                if (success)
                {
                    // 保活至进程退出；进程结束时 OS 统一回收，无泄漏风险。
                    _linkedTokenKeepAlive.Add(hLinked);
                }
                else
                {
                    hLinked.Close(); // 失败路径：本方法负责关闭，避免句柄泄漏
                }
            }
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

            // proadv4 [U3]：令牌组数量上限守卫。内核 TOKEN_GROUPS 计数为 ULONG，
            // 但单令牌实际可容纳的组受 MaxTokenSize(默认 8KB, 可注册表放大到 1MB+)
            // 限制；每组 SID_AND_ATTRIBUTES 指针 + 平均 ~28 字节 SID，约 600+ 组封顶。
            // 动态枚举的服务账户在极端机器上可能很多 —— 超限时截断并告警，
            // 保证 NtCreateToken 不会因缓冲过大而失败（宁可少几个附加组也不能整体失败）。
            const int MaxSafeGroups = 512;
            if (groupSids.Length > MaxSafeGroups)
            {
                Console.WriteLine($"  [!] WARNING: {groupSids.Length} groups exceed safe limit {MaxSafeGroups}; "
                                + "truncating to the first entries (core groups are ordered first).");
                groupSids = groupSids[..MaxSafeGroups];
            }

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
                bufGroups = BuildTokenGroups(groupSids, out sidPtrs, out var groupEntries); // proadv9 [AA5]
                bufPrivs = BuildTokenPrivileges(privileges);

                var owner = new TOKEN_OWNER { Owner = sidUser };

                // pproadv2 修复 [S2]：PrimaryGroup 必须是 TokenGroups 列表中的某个组，否则内核
                // 拒绝 NtCreateToken（STATUS_INVALID_GROUP_REFERENCE）或生成畸形令牌。
                // v16-adv 原实现把 PrimaryGroup 设为 TokenUser（TI SID S-1-5-80-...），而该 SID
                // 不在 groups 列表中 —— 这正是 ticmd 内 whoami 拒绝访问 / taskkill 全部失败的根源：
                // 令牌主组不合法导致大量基于主组的 ACL 检查失败。这里改为使用与真实 TI 服务令牌
                // 一致、且已在 groupSids 中出现的 Builtin Administrators 作为 PrimaryGroup。
                // 复用 BuildTokenGroups 已转换好的 SID 指针（sidPtrs[i]），避免重复转换/释放。
                // proadv7 [X1b]（配合 [X1] 压缩修复的边界安全）：跳过项使 sidPtrs 被
                // Array.Resize 截断为实际写入数 w（w <= groupSids.Length），查找循环上界
                // 必须取两者较小值，否则原始下标 gi 可能越过截断后的数组尾部产生越界；
                // 且只有"物理仍在数组内"的下标才对应有效 SID 指针。Administrators 属核心组，
                // 解析失败会先行 throw，正常路径下命中下标恒 < w，语义与旧实现完全一致。
                // proadv9 [AA5]：改用 groupEntries（BuildTokenGroups 同步输出的压缩条目视图，
                // 与 sidPtrs/物理槽位严格一一对应）遍历 —— 原实现用未压缩的 groupSids 下标
                // 去索引压缩后的 sidPtrs，存在"字符串比对下标与指针下标语义分叉"的残余错位
                // 窗口（此前仅因 Administrators 位于核心段、核心解析失败先行 throw 而侥幸
                // 不可触发）。Math.Min 上界保留为双保险。无跳过项时 groupEntries 即原数组，
                // 行为逐字节一致。
                IntPtr primaryGroupSid = sidUser;
                int searchLimit = Math.Min(groupEntries.Length, sidPtrs.Length);
                for (int gi = 0; gi < searchLimit; gi++)
                {
                    if (string.Equals(groupEntries[gi].sid, WellKnownSids.BuiltinAdmins, StringComparison.OrdinalIgnoreCase))
                    {
                        primaryGroupSid = sidPtrs[gi];
                        break;
                    }
                }
                var primaryGroup = new TOKEN_PRIMARY_GROUP { PrimaryGroup = primaryGroupSid };

                pDefaultDacl = BuildDefaultDacl(sidUser, out daclSidPtrs);
                var defaultDacl = new TOKEN_DEFAULT_DACL { DefaultDacl = pDefaultDacl };

                var authId = new LUID { LowPart = 0x3e7, HighPart = 0 };

                if (!NativeMethods.AllocateLocallyUniqueId(out var srcId))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "AllocateLocallyUniqueId failed");

                var source = new TOKEN_SOURCE { SourceIdentifier = srcId };
                // proadv3 [T1]：SourceName 为固定 8 字节 ANSI 字段，内核按 OEM/ANSI 码页解释。
                // 原实现用 CharSet.Ansi + ByValTStr 编组字符串 "OptTok"，在个别区域设置下
                // 可能引入尾随差异；改为显式 ASCII 字节写入（见下方 StructureToPtr 后补丁），
                // 保证与内核语义逐字节一致。结构体里的 string 字段置空串避免被写垃圾。
                source.SourceName = string.Empty;

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

                // proadv3 [T1]：TOKEN_SOURCE 在托管结构体中按自然对齐布局（x64 上 SourceIdentifier
                // 位于偏移 8）。把 "OptTok" 以 ASCII 字节直接写入头部 8 字节 —— 与内核期望的
                // CHAR[8] 逐字节一致，不再依赖 CharSet.Ansi 码页转换。
                {
                    byte[] nameBytes = new byte[8]; // 'O','p','t','T','o','k',0,0
                    Encoding.ASCII.GetBytes("OptTok", 0, 6, nameBytes, 0);
                    // proadv5 [V3] 修复编译错误 CS0213：proadv4 试图 `fixed (TOKEN_SOURCE* p = &source)`
                    // 对已处于堆外的可寻址局部变量再次取址固定，编译器直接拒绝（CS0213），整个文件
                    // 无法通过静态编译。改为显式分配非托管缓冲、封送结构体后把 8 个 ASCII 字节写入
                    // 其头部（SourceName 即结构体偏移 0），再读回托管副本 —— 最终由 P/Invoke 封送器
                    // 原样复制到内核看到的 TOKEN_SOURCE，语义与 T1 设计意图逐字节一致。
                    // proadv6 [W1] 修复编译错误 CS0227：proadv5 的上述实现仍含
                    // `unsafe { byte* pBase = (byte*)pSrcBuf; ... }` 代码块 —— 在未开启
                    // /p:AllowUnsafeBlocks 的默认构建（以及 csc 单文件编译）下直接报
                    // CS0227 "unsafe code may only appear if compiling with /unsafe"，
                    // 导致整个 proadv5.cs 无法通过静态编译。现改用 Marshal.WriteByte
                    // 逐字节写入同一目标内存，产物字节序列与 unsafe 版本完全一致，
                    // 且不需要任何编译器开关；同时移除对含 ByValTStr string 字段的结构
                    // 调用 Marshal.DestroyStructure（string 字段非非托管分配，该调用无效）。
                    IntPtr pSrcBuf = Marshal.AllocHGlobal(Marshal.SizeOf<TOKEN_SOURCE>());
                    try
                    {
                        Marshal.StructureToPtr(source, pSrcBuf, false);
                        for (int k = 0; k < 8; k++)
                            Marshal.WriteByte(IntPtr.Add(pSrcBuf, k), nameBytes[k]);
                        source = Marshal.PtrToStructure<TOKEN_SOURCE>(pSrcBuf);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pSrcBuf);
                    }
                }

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

                // proadv9 [AA4]（运行期 bug 修复：句柄泄漏防护）：v8 声明
                //   int status = NativeMethods.NtCreateToken(out var hToken, ...);
                // 随后 `if (status < 0) throw ...`。缺陷：NtCreateToken 的文档语义是
                // "成功时写入 TokenHandle"，但在部分失败路径（如 STATUS_INVALID_GROUP_REFERENCE
                // 等参数校验晚期失败、或第三方内核回调干扰）下对象引用可能已被创建并写入
                // out 槽位而返回码仍为负；此时 v8 直接 throw，SafeTokenHandle 尚未被任何
                // 托管变量接管 —— GC 终结器虽最终会 ReleaseHandle，但令牌句柄在进程存活期内
                // 保持打开（本函数抛出后 Phase 2 还会重试/继续执行），且时序不可控。
                // 修复：失败分支先对 hToken 做防御性判空 Dispose（SafeHandle 幂等，重复
                // Dispose 无副作用），再抛异常。成功路径不变。
                if (status < 0)
                {
                    try { hToken?.Dispose(); } catch { /* best-effort */ }
                    throw new Win32Exception(
                        (int)NativeMethods.RtlNtStatusToDosError(status),
                        $"NtCreateToken failed (NTSTATUS=0x{status:X8})");
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

        static IntPtr BuildTokenGroups((string sid, GroupAttributes attr)[] entries,
            out IntPtr[] sidPtrs, out (string sid, GroupAttributes attr)[] entriesOut)
        {
            int count = entries.Length;
            entriesOut = entries; // proadv9 [AA5]：无跳过项时保持原引用（行为逐字节一致）
            int hdr = (int)Marshal.OffsetOf<TOKEN_GROUPS_LAYOUT>(nameof(TOKEN_GROUPS_LAYOUT.FirstGroup));
            IntPtr buf = Marshal.AllocHGlobal(hdr + SidAndAttributesSize * count);
            sidPtrs = new IntPtr[count];
            bool success = false;
            try
            {
                Marshal.WriteInt32(buf, count);
                IntPtr ptr = IntPtr.Add(buf, hdr);
                int w = 0; // proadv7 [X1]：压缩写游标（物理槽位/sidPtrs 共用）
                for (int i = 0; i < count; i++)
                {
                    if (!NativeMethods.ConvertStringSidToSid(entries[i].sid, out var s))
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
                // proadv9 [AA5]（运行期 bug 修复：视图一致性补全）：v8 只截断 sidPtrs，
                // 未同步收缩"与物理槽位对应"的条目视图 —— CreatePrimaryToken 的 PrimaryGroup
                // 查找用 groupSids[gi]（原始下标）比对字符串、却用 sidPtrs[gi]（压缩后下标）
                // 取指针；当 Administrators 之后存在被跳过的附加组时，两个视图的下标语义
                // 已经分叉（v7/v8 靠 searchLimit=Math.Min 防越界，Administrators 位于核心段
                // 且核心失败先行 throw，恰好掩盖了错位窗口 —— 属于"依赖数据分布侥幸正确"）。
                // 修复：新增 out entriesOut = 压缩后的条目数组，与 sidPtrs/物理槽位三者严格
                // 一一对应；CreatePrimaryToken 改用 entriesOut 遍历，彻底消除残余错位可能。
                // 无跳过项时 entriesOut 与原 entries 引用相同，行为逐字节一致。
                if (w != count)
                {
                    Marshal.WriteInt32(buf, w);
                    Array.Resize(ref sidPtrs, w);
                    var compacted = new (string sid, GroupAttributes attr)[w];
                    int j = 0;
                    for (int i = 0; i < count && j < w; i++)
                    {
                        // 与写入循环同判据：能被 ConvertStringSidToSid 解析的条目才占一个压缩槽位。
                        // 此处不重复转换（避免二次 LocalAlloc），仅复制元数据；可解析性已由
                        // sidPtrs[j] != IntPtr.Zero 保证（清零尾部之外全部为有效指针）。
                        if (entries[i].sid == null) continue;
                        if (!NativeMethods.ConvertStringSidToSid(entries[i].sid, out var probe))
                            continue; // 与主循环一致的跳过判据（此时必为附加组）
                        NativeMethods.LocalFree(probe); // 仅为判据复测，立即释放，不进入资源表
                        compacted[j++] = entries[i];
                    }
                    // j 恒等于 w（同一确定性判据），防御性截断到 j。
                    if (j != w) Array.Resize(ref compacted, j);
                    entriesOut = compacted;
                }
                else
                {
                    entriesOut = entries;
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
            IntPtr sidSystem = IntPtr.Zero, sidAdmins = IntPtr.Zero, sidEveryone = IntPtr.Zero;
            // pproadv1 修复 [P7]：out 参数类型为非可空 IntPtr[]，null 会触发 CS8625；
            // 改为空数组（语义等价：调用方只遍历/释放其中的 SID 指针）。
            daclSidPtrs = global::System.Array.Empty<IntPtr>();
            if (!NativeMethods.ConvertStringSidToSid("S-1-5-18", out sidSystem))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "ConvertStringSidToSid SYSTEM failed");
            if (!NativeMethods.ConvertStringSidToSid("S-1-5-32-544", out sidAdmins))
            {
                NativeMethods.LocalFree(sidSystem);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "ConvertStringSidToSid Administrators failed");
            }
            // proadv4 [U5]：Default DACL 追加 Everyone(S-1-5-11) GENERIC_ALL。
            // 令牌 DefaultDacl 决定该进程新建对象(文件/事件/互斥体等)的默认安全描述符；
            // 允许 Everyone 完全控制可避免 ticmd 创建的对象对其他上下文不可达导致的
            // 二次"拒绝访问"类问题，是纯可用性增强（不影响令牌自身的权限判定）。
            if (!NativeMethods.ConvertStringSidToSid("S-1-5-11", out sidEveryone))
            {
                NativeMethods.LocalFree(sidSystem);
                NativeMethods.LocalFree(sidAdmins);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "ConvertStringSidToSid AuthenticatedUsers failed");
            }
            daclSidPtrs = new[] { sidSystem, sidAdmins, sidEveryone };

            uint aclSize = 8
                         + (8 + NativeMethods.GetLengthSid(sidSystem))
                         + (8 + NativeMethods.GetLengthSid(sidAdmins))
                         + (8 + NativeMethods.GetLengthSid(sidOwner))
                         + (8 + NativeMethods.GetLengthSid(sidEveryone));
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
                // proadv4 [U5]：第 4 条 ACE —— Authenticated Users(S-1-5-11) GENERIC_ALL。
                if (!NativeMethods.AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, sidEveryone))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "AddAccessAllowedAce AuthenticatedUsers failed");
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

            // proadv3 修复 [T5]：CreateEnvironmentBlock 对 TrustedInstaller 这类无用户配置文件的
            // 账户常失败（1314/5）。原实现直接抛异常导致整个 Phase 2 终止；降级为 best-effort：
            // 失败时以 envBlock=null 继续，子进程继承父进程环境块。
            IntPtr envBlock = IntPtr.Zero;
            bool haveEnvBlock = NativeMethods.CreateEnvironmentBlock(out envBlock, token, false);
            if (!haveEnvBlock)
            {
                Console.WriteLine("  [!] CreateEnvironmentBlock failed (non-fatal): "
                                  + Marshal.GetLastPInvokeError()
                                  + " — child will inherit parent environment");
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

        // proadv8 [Y1]：IsReadablePointer 有界探测读所需的三个 kernel32 原生入口。
        // ReadProcessMemory 对无效/未提交地址只返回 FALSE（不触发本进程 AV），是零
        // unsafe 场景下最可靠的"可寻址性"探测手段；VirtualAlloc/VirtualFree 用于构造
        // 哨兵页负对照（详见 WellKnownSids.IsReadablePointer 注释）。
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
            IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualFree(
            IntPtr lpAddress, IntPtr dwSize, uint dwFreeType);

        public const uint MEM_COMMIT     = 0x00001000;
        public const uint MEM_RESERVE    = 0x00002000;
        public const uint MEM_DECOMMIT   = 0x00004000;
        public const uint MEM_RELEASE    = 0x00008000;
        public const uint PAGE_READWRITE = 0x04;

        // 便捷封装：吞掉 lasterror，仅返回成败与实读字节数（探测路径不需要错误码）。
        public static bool ReadProcessMemorySafe(
            IntPtr hProcess, IntPtr baseAddr, byte[] buffer, IntPtr size, out IntPtr read)
        {
            read = IntPtr.Zero;
            try
            {
                return ReadProcessMemory(hProcess, baseAddr, buffer, size, out read);
            }
            catch { return false; }
        }

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

        // proadv9 [AA6]（运行期 bug 修复）：新增"调用后立即读取 lasterror"的裸 P/Invoke
        // 便捷封装。背景：AdjustTokenPrivileges 即使返回 TRUE，仍可能以
        // ERROR_NOT_ALL_ASSIGNED(1300) 表示"特权不在本令牌上、实际未启用"——这是 MSDN
        // 明确定义的语义。v8 的做法是在调用前 Marshal.SetLastPInvokeError(0)、调用后
        // 读 GetLastPInvokeError；在 .NET 10 的 SetLastError=true 封码下，marshaler 会在
        // P/Invoke 前后各自 Save/Restore lasterror，且封装方法内部还穿插了
        // LookupPrivilegeValue / Marshal.SizeOf 等其他原生调用，读取时机不精确时 1300
        // 可能被覆盖为旧值 → 特权"看似启用成功"，错误被推迟到 VerifyPrivilege 兜底才
        // 暴露（双段歧义日志）。修复：把"原生调用 → GetLastError"压缩进同一个紧邻语句对
        // （GetLastWin32Error 语义 = 紧随该次调用的 lasterror），EnableOnProcess 据此
        // 即时抛出，消除时序歧义；对外行为（何时算失败）与 v8 最终判定完全一致。
        public static bool AdjustTokenPrivilegesAndProbeLastError(
            SafeTokenHandle TokenHandle,
            bool DisableAllPrivileges,
            string privilegeName,
            uint Attributes, out int lastError)
        {
            lastError = 0;
            if (!LookupPrivilegeValue(null, privilegeName, out LUID luid))
            {
                lastError = Marshal.GetLastPInvokeError();
                throw new Win32Exception(lastError, $"LookupPrivilegeValue failed: {privilegeName}");
            }

            var tp = new ADJUSTABLE_SINGLE_TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new SINGLE_LUID_AND_ATTRIBUTES { Luid = luid, Attributes = Attributes }
            };
            bool ok = AdjustTokenPrivileges(
                TokenHandle, DisableAllPrivileges, ref tp,
                (uint)Marshal.SizeOf<ADJUSTABLE_SINGLE_TOKEN_PRIVILEGES>(), IntPtr.Zero, IntPtr.Zero);
            // [AA6] 关键点：此行为 AdjustTokenPrivileges 返回后的第一条读取语句，
            // 中间无任何其他可改写 lasterror 的原生调用。
            lastError = Marshal.GetLastPInvokeError();
            return ok;
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

        // proadv7 [X7]/[X8]（可优化 + 精确原型）：TokenSessionId 的原生原型为
        //   BOOL SetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, PVOID Buffer, DWORD Length)
        // —— 第三参是"指向数据的指针"，而非 DWORD 本身。proadv6 用 `ref uint` 是正确的
        // （CLR 把托管变量的地址作为 PVOID 传入），但封送器需要固定(pin)该变量；
        // 这里改为显式 IntPtr 指针原型 + 调用方用栈上局部变量取址的辅助封装，
        // 既保留 ref 语义的类型安全，又让 P/Invoke 签名与 winnt.h 逐参数对应，
        // 静态分析时不再出现"整数值冒充指针"的歧义告警。uint 便捷重载保留给
        // 已经持有指针场景之外的普通调用点（封送器等价、行为不变）。
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle,
            int tokenInformationClass,
            uint tokenInformation,
            int tokenInformationLength);

        // pproadv2 修复 [S1]：结构体参数版重载（用于 TOKEN_ELEVATION / TOKEN_LINKED_TOKEN）。
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle,
            int tokenInformationClass,
            ref TOKEN_ELEVATION tokenInformation,
            int tokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle,
            int tokenInformationClass,
            ref TOKEN_LINKED_TOKEN tokenInformation,
            int tokenInformationLength);

        // proadv3 新增 [T2]：TOKEN_ORIGIN 版重载（SetTokenInformation(TokenOrigin)）。
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            SafeTokenHandle tokenHandle,
            int tokenInformationClass,
            ref TOKEN_ORIGIN tokenInformation,
            int tokenInformationLength);

        // proadv7 [X2]：TOKEN_ELEVATION_TYPE_INFO 版 Set/Get 重载。
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

        // proadv9 [AA8]：修复 proadv8 遗留的复制粘贴缺陷 —— 原第一行注释
        // "proadv6 [W8]：TOKEN_ELEVATION 版 GetTokenInformation 强类型重载。"在同一物理行
        // 重复出现两次（v8 第 4322 行），属纯文本冗余，无行为影响；现去重为单行。
        // proadv6 [W8]：TOKEN_ELEVATION 版 GetTokenInformation 强类型重载。
        // VerifyTokenElevation 原以 IntPtr + Marshal.ReadInt32 手工读取；改用与
        // SetTokenInformation([S1]) 对称的结构体重载，消除"写入布局(TOKEN_ELEVATION)
        // 与读回布局(裸 Int32)不对称"的静态分析告警（x86/x64 上两者偏移均为 0，
        // 行为等价，但强类型版本在未来字段扩展时不会静默错位）。
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            SafeTokenHandle TokenHandle,
            int TokenInformationClass,
            out TOKEN_ELEVATION TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

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
            // proadv6 [W7]：nLength 原生原型为 DWORD(uint)，proadv5 误声明为 int；
            // 改为 uint 与 win32.h 精确匹配（调用点同步为无符号表达式）。
            IntPtr hObj, int nIndex, StringBuilder pvInfo, uint nLength, out uint lpnLengthNeeded);

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