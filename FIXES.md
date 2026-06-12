# VulnScope 修复总结

## 一、安全问题修复（#1-#7）

| # | 问题 | 严重程度 | 修复方案 | 修改文件 |
|---|------|---------|---------|---------|
| 1 | APIKey 通过 URL Query 参数传递 | 高 | 移除 Query 参数传递方式，仅保留 Header(`x-API-Key`) 认证 | `router.go` |
| 2 | CORS 默认允许所有来源(*) | 高 | 默认改为空（不允许任何来源），通过配置项 `cors_allowed_origins` 设置 | `router.go`, `config.go` |
| 3 | 硬编码数据库默认密码 | 中 | 移除默认密码，必须通过环境变量或配置文件提供 | `config.go` |
| 4 | TLS 证书验证自动跳过 | 中 | 默认 `insecure_tls: false`，仅在明确配置时跳过 | `config.go`, `alive.go`, `finger.go`, `vuln.go` |
| 5 | 自动下载可执行文件无签名校验 | 中 | 添加 SHA256 哈希计算并输出，供用户与官方校验值比对 | `checker.go` |
| 6 | SQL 注入风险(Raw SQL) | 中 | 将 Raw SQL 替换为 GORM 子查询构建，消除注入风险 | `store.go` |
| 7 | 配置文件中密码明文存储 | 中 | 支持环境变量覆盖敏感配置（`VULNSCOPE_DB_DSN`、`VULNSCOPE_REDIS_PASSWORD`等） | `config.go` |

## 二、架构/功能问题修复（#8-#16）

| # | 问题 | 严重程度 | 修复方案 | 修改文件 |
|---|------|---------|---------|---------|
| 8 | 流水线全量串行，无并行化 | 高 | 重构为按单个资产粒度入队，每个目标完成当前阶段后立即入队下一阶段 | `scheduler.go`, `worker.go` |
| 9 | 模块名不一致 | 高 | 统一模块名为 `vulnscope`，修复所有 import 路径 | `go.mod`, 所有 `.go` 文件 |
| 10 | 任务取消机制缺失 | 高 | 实现取消/暂停/恢复 API，Worker 每阶段检查任务状态 | `task.go`, `router.go`, `worker.go` |
| 11 | 无扫描时间段控制 | 中 | 添加 `allow_scan_start`/`allow_scan_end` 配置，Scheduler 入队前检查 | `config.go`, `scheduler.go` |
| 12 | 无排除目标机制 | 中 | 添加 `exclude_targets`(IP/域名/CIDR/通配符) 和 `exclude_ports` 配置 | `config.go`, `worker.go` |
| 13 | Nuclei CLI 方式局限性 | 中 | 优化子进程调用：模板过滤、并发控制(`-c`/`-bs`)、超时(`-timeout`)、上下文取消、结构化 JSON 解析 | `vuln.go` |
| 14 | 无节点状态同步 | 低 | 添加定期节点心跳写入数据库 | `main.go` |
| 15 | IP 级并发控制与防重缺失 | 中 | 添加 `ip_scan_cooldown_min` 配置，通过数据库 Config 表实现 IP 扫描冷却 | `config.go`, `worker.go` |
| 16 | Worker 职责混乱 | 中 | Worker 通过 `EnqueueFunc` 回调委托 Scheduler 入队，移除自身 `asynq.Client` 依赖 | `worker.go`, `main.go` |

## 三、扫描引擎问题修复（#17-#23）

| # | 问题 | 严重程度 | 修复方案 | 修改文件 |
|---|------|---------|---------|---------|
| 17 | 无 CPE 精确匹配引擎 | 高 | 集成 `knqyf263/go-cpe` 库，使用 WFN 格式的 `IsSuperset`/`IsSubset`/`IsEqual` 替换简单字符串比较，支持通配符和版本范围 | `store.go` |
| 18 | 无 OAST/反连验证 | 中 | 通过 Nuclei 的 `-interactsh-server`/`-interactsh-token` 参数集成反连服务，支持 SSRF、Log4j 等无回显漏洞检测 | `vuln.go`, `config.go` |
| 19 | 无 Chrome 无头浏览器支持 | 中 | 集成 `go-rod/rod`，新建 `browser.go` 实现浏览器渲染、JS 全局变量技术栈检测、DOM 提取；在 `finger.go` 第四步对指纹不足的目标使用浏览器补充 | `browser.go`, `finger.go`, `config.go` |
| 20 | ICMP ping 实现不可靠 | 低 | 重构 `ping()` 函数：构造正确的 ICMP Echo Request 包（含 type/code/checksum），添加权限检测和自动降级 | `alive.go` |
| 21 | 域名扫描无子域名发现 | 中 | 新增 `discoverSubdomains`，集成 crt.sh 证书透明度日志查询、DNS 区域传输尝试、子域名爆破 | `domain.go`, `config.go` |
| 22 | 漏洞结果无资产维度关联 | 中 | 新增 `resolveAssetID` 函数，从漏洞 URL 提取主机信息并在 assets 表中查找匹配的资产 ID | `worker.go` |
| 23 | 无复测任务支持 | 中 | Scheduler 新增 `enqueueRetestTask`，Worker 新增 `handleRetestScan`，支持直接从漏洞扫描阶段开始复测 | `scheduler.go`, `worker.go` |

## 四、代码质量/运维问题修复（#24-#32）

| # | 问题 | 严重程度 | 修复方案 | 修改文件 |
|---|------|---------|---------|---------|
| 24 | `splitIDs` 返回 `[]int` 但当 `[]uint` 使用 | 中 | 改为直接返回 `[]uint`，使用 `strconv.ParseUint`，简化调用处 | `scheduler.go` |
| 25 | `VulnScanByService` 遍历 `targets` 而非 `targetInfos` | 高 | 改为 `for i := range targetInfos`，从 `targetInfos[i].Target` 获取目标，修复模板分组逻辑 | `vuln.go` |
| 26 | 并发扫描无速率限制 | 中 | 添加 `time.Ticker` 速率限制器（~500/s），防止对目标过大压力 | `port.go` |
| 27 | `PrintProgress` 用 `log.Printf("\r...")` 无效 | 低 | 改为 `fmt.Fprintf(os.Stderr, "\r...")`，实现终端进度覆盖 | `checker.go` |
| 28 | `extractTitle` 只读 4096 字节 | 低 | 改为 `io.ReadAll(io.LimitReader(resp.Body, 1MB))`，限制最大 1MB | `alive.go` |
| 29 | go.mod 声明 `go 1.25.7` 不存在版本 | 低 | 改为 `go 1.24` | `go.mod` |
| 30 | 无优雅关闭(graceful shutdown) | 中 | Worker 变量提升到外层作用域，收到信号后调用 `w.Shutdown()` 等待任务完成 | `main.go` |
| 32 | 无数据库连接池配置 | 中 | 添加 `MaxIdleConns=10`、`MaxOpenConns=100`、`ConnMaxLifetime=1h` | `store.go` |

## 五、核心差距对照

| 差距 | 修复前 | 修复后 |
|------|-------|-------|
| 流水线并行化 | 全量串行，所有目标完成上一阶段才能进入下一阶段 | 按单个资产粒度入队，每个目标完成当前阶段后立即进入下一阶段 |
| CPE 匹配精度 | 简单 `strings.Split` 比较 `vendor:product` | `go-cpe` 库 WFN 格式匹配，支持通配符、版本范围 |
| 任务管控能力 | 无暂停/取消/时间段控制/排除机制 | 完整的取消/暂停/恢复 API + 时间段控制 + 排除目标/端口 + IP 冷却 |
| nuclei 集成方式 | 简单 CLI 调用，无控制 | 优化子进程：模板过滤、并发控制、超时、上下文取消、OAST 反连 |
| VulnScanByService 索引 bug | `for i := range targets` 用 targets 索引访问 targetInfos | `for i := range targetInfos` 正确遍历 |

## 六、新增依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `github.com/knqyf263/go-cpe` | v0.0.0-20230627041855 | CPE WFN 精确匹配引擎 |
| `github.com/go-rod/rod` | v0.116.2 | Chrome 无头浏览器渲染 |

## 七、新增配置项

| 配置项 | 类型 | 说明 |
|--------|------|------|
| `cors_allowed_origins` | []string | CORS 允许的来源列表 |
| `allow_scan_start` | string | 允许扫描的开始时间（如 "08:00"） |
| `allow_scan_end` | string | 允许扫描的结束时间（如 "20:00"） |
| `exclude_targets` | []string | 排除的目标列表（IP/域名/CIDR/通配符） |
| `exclude_ports` | []int | 排除的端口列表 |
| `ip_scan_cooldown_min` | int | IP 扫描冷却时间（分钟） |
| `subdomain_wordlist` | string | 子域名爆破字典文件路径 |
| `chrome_path` | string | Chrome/Chromium 可执行文件路径 |
| `interactsh_server` | string | OAST 反连服务器地址 |
| `interactsh_token` | string | OAST 反连服务器认证 token |
