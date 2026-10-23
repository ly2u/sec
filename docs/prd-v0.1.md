# LY2U SecWatch — 产品与技术需求文档（PRD + 技术设计）

> **文档版本**：V1.0 草案（2026-10-23）  
> **产品名称**：LY2U SecWatch（暂定）  
> **公开站点**：`https://sec.ly2u.com`（计划使用，尚未部署）  
> **代码仓库**：GitHub 公开仓库 `secwatch`（仓库归属待确定；尚未创建）  
> **许可证建议**：Apache-2.0（须保留第三方数据、依赖及商标的各自授权声明）  
> **目标读者**：项目开发者、Codex、潜在贡献者、VPS 管理员。

---

## 0. 决策摘要：历史漏洞保存多久？

**结论：公开历史漏洞“长期可检索、按需深度补齐”，不按照 CVE 发布年份直接删除；同时避免在本地永久复制所有原始材料。**

1. **全历史基础索引**：尽可能导入全部已公开 CVE（不设年份截止线），保留 CVE ID、状态、标题/简述、首次发布时间、最后更新时间、来源链接及必要检索字段。处于 `REJECTED` 状态的编号保留墓碑及原因，避免把它当作有效漏洞；未公开的 `RESERVED` 记录不得当作已披露漏洞展示。
2. **近期热点**：过去 **90 天内新发布或发生重要变化**的漏洞，高频补充详情。90 天只是处理窗口，不是保留期限。
3. **长期重点**：CISA KEV、重大/高危、影响当前仍受支持版本、仍被利用、尚无补丁的漏洞，不论公开年份，持续追踪。
4. **长尾详情**：低优先级历史漏洞保留索引；用户打开详情页或自检结果匹配到时，按需拉取 NVD、OSV、发行版/厂商补丁情报并缓存。
5. **原始文档归档**：数据库优先保留结构化事实、来源 URL、采集时间、内容哈希、重要变更记录。上游完整 JSON 可压缩归档并定期清理冗余副本；不应为了省空间删除 CVE 索引或丢失必要的来源证据。
6. **老漏洞新事件**：任何旧 CVE 新增 KEV、首次确认在野利用、修复版本、撤回/修订，均作为**新事件**重新参与告警，不因其发布时间过久而忽略。

**理由**：不同用户可能运行旧系统、停止维护的软件或定制镜像。同一 CVE 在不同发行版中的修复状态也可能不同。仅保存“最近一年的高危 CVE”会导致自检产生严重漏报。

---

## 1. 项目目标、定位和边界

### 1.1 一句话定位

面向全球 VPS、独立服务器及自托管服务用户，提供**可信漏洞情报检索、可独立部署的本地安全自检、可验证的修复建议、关键漏洞订阅和社区纠错**。

### 1.2 核心用户场景

- 用户看到新 CVE，访问网站查询影响组件、版本、前置条件和官方补丁。
- 用户在 Debian/Ubuntu/RHEL 系等 VPS 上运行只读 CLI，自检 OS 包、运行内核、容器和常见应用依赖。
- 用户订阅“特定软件/发行版/严重程度/KEV”，仅收到新的相关风险与修复动态。
- 贡献者提交公告链接、错误修正、补丁说明、检测规则，通过审核后公开。
- 社区使用 GitHub 仓库自行部署完整站点，也可仅运行本地扫描器。

### 1.3 非目标

- 不承诺检测一切漏洞、零日漏洞或所有利用路径。
- 不替代主机入侵检测、EDR、渗透测试和人工风险分析。
- 不通过公网主动扫描未获授权的第三方 IP。
- V0.1 **不自动 SSH 登录、不自动修改用户 VPS、不自动执行社区提交的脚本**。
- 不把 CVSS 分数等同于可直接远程提权；“有受影响版本”不等于“已被利用”。

### 1.4 主要指标（MVP 验收目标）

- 已公开历史 CVE 基础索引可查，并提供初次导入进度及最新同步水位。
- 官方源支持失败重试、去重、幂等导入与断点续传。
- 新增或修改的安全记录通常在上游可用后 **60 分钟内**进入本地情报（目标，不保证上游同步和网络 SLA）。
- 对关键公告与 KEV 变化进行事件级告警去重。
- 自检报告每条“受影响/可能受影响”都有依据和修复引用，不能单凭通用版本号判定发行版包必定存在漏洞。
- 自部署说明可在全新 VPS 上通过 Docker Compose 完成部署、恢复和升级。

---

## 2. 首期支持范围

**情报覆盖**（不等于 V0.1 CLI 全面深度适配）：

- Linux：Debian、Ubuntu、RHEL、Rocky、AlmaLinux、CentOS Stream、Fedora、Alpine、Arch、openSUSE/SLES、Amazon Linux、Oracle Linux；相关时包含 Windows Server。
- 基础组件：Linux kernel、OpenSSH、sudo、glibc、systemd、OpenSSL、BIND、curl、Git。
- Web/代理：Nginx、Apache HTTP Server、Caddy、Traefik、HAProxy。
- 容器/编排：Docker、containerd、runc、Podman、Kubernetes。
- 语言/框架：Node.js、PHP、Python、Java、Go、Ruby、Next.js、React。
- 数据：MySQL、MariaDB、PostgreSQL、Redis、MongoDB。
- 自托管系统：WordPress、1Panel、aaPanel/宝塔、Plesk、cPanel 及其他有可信厂商通告的软件。
- 供应链：npm、PyPI、Composer、Maven、Go Modules、RubyGems、GitHub Actions。

**CLI V0.1 深度支持顺序**：Debian/Ubuntu 的包和运行内核 → Docker 镜像/容器 → RHEL/Rocky/Alma/RPM → Alpine/APK。其余系统第一版尽量提供“识别 OS + 推荐适用检测器/告知支持级别”，不可伪称完全适配。

---

## 3. 总体架构与部署

### 3.1 架构

```text
官方/厂商漏洞源 ──> Collector/Normalizer ──> PostgreSQL
                                         │          │
                                         ├──> Alert Engine ──> RSS/Telegram/Email/Webhook
                                         │          │
GitHub Issues/PR ──> 审核与贡献队列 ──────┘          v
                                              FastAPI Web/API <──> 网站检索和详情
                                                   │
VPS 本地只读 CLI ──(HTTPS 下载签名/校验的规则或查询公开 API)──┘

站点部署：Docker Compose + Caddy + PostgreSQL + API/Web + Collector/Worker
GitHub：源码、Issue/PR、Actions CI、安全公告、版本发布
Cloudflare（可选）：DNS、CDN、WAF/限速，不能替代源站鉴权与防护
```

### 3.2 推荐技术

- **后端**：Python 3.12+ / FastAPI / Pydantic / SQLAlchemy + Alembic。
- **网页**：服务端渲染 Jinja2 + HTMX + 少量原生 JS，优先 SEO、速度和可访问性；不强制引入复杂前端工程。
- **数据库**：PostgreSQL（B-tree/GIN + 全文检索，先不必部署 Elasticsearch）。
- **采集/调度**：独立 Python Worker + 持久化任务水位；V0.1 可用 APScheduler 或系统调度，确保多实例时有互斥锁；不得由 Web 请求线程承担长期采集。
- **本地 CLI**：优先 Go 单文件可执行程序，适配 Linux amd64/arm64；扫描器通过成熟开源工具 Trivy/OSV-Scanner 的受支持能力输出，再补足宿主机进程、端口、重启需求和证据解释；若首版研发受限，先以可审计的 Python CLI 实现相同接口，后续替换。
- **反向代理**：Caddy。数据库和 Worker 不暴露公网端口。
- **开源部署**：`compose.yaml`、`.env.example`、数据库迁移、健康检查、备份/恢复、升级说明。

### 3.3 最小生产服务

| 服务 | 职责 | 端口暴露 |
|---|---|---|
| caddy | TLS/反代、静态缓存、基础安全头 | 80/443 |
| web | 前台页面、只读 API、提交入口 | 仅内部网络 |
| collector | 定时增量获取、重新核验、归一化 | 不暴露 |
| notifier | 告警事件消费、去重、重试 | 不暴露 |
| postgres | 情报与社区数据 | 不暴露 |
| admin | 审核操作（可作为 Web 私有路由） | 必须鉴权，建议单独保护 |

**部署建议**：可先用自有 VPS（预计 2–4 vCPU、4 GB RAM 可起步，但必须实测全量导入峰值）；数据盘预留约 20–40 GB 作为初期容量规划而非保证值。采集器增量运行通常负载低，**全量历史导入/索引重建**可能消耗较多磁盘与 CPU，应可限速、分批、暂停。先检查实际磁盘余量和备份位置。

---

## 4. 官方情报数据源与优先级

| 来源 | 官方入口 | 用途 | 处理要点 |
|---|---|---|---|
| CVE Program cvelistV5 | https://github.com/CVEProject/cvelistV5 | 全历史基础索引、权威 CVE 内容 | 一次基线导入 + hourly/delta；遵守 CVE Program 条款 |
| CISA KEV | https://github.com/cisagov/kev-data | 已知遭利用记录 | “KEV 收录”与“仅有 PoC”区分；变化事件最高关注 |
| NVD CVE API | https://nvd.nist.gov/developers/vulnerabilities | CVSS、CPE、NVD 补充和修改 | 增量 + 分页 + 限速 + 退避；不可依赖 NVD 作为唯一事实源 |
| GitHub Advisory Database | https://docs.github.com/en/rest/security-advisories/global-advisories | GHSA、语言包影响区间/修复版本 | 按 `updated` 分页，关联 CVE 与 PURL |
| OSV | https://osv.dev/ | 生态依赖漏洞与版本区间 | 按 PURL/生态与版本匹配；保留来源归属 |
| Debian Security Tracker | https://security-tracker.debian.org/tracker/ | Debian 版本、软件包状态和修复 | 尊重 Debian 包版本与安全回移补丁 |
| Ubuntu Security API | https://ubuntu.com/security/api/docs | Ubuntu 各发行版状态和 USN | 注意接口嵌套/分页与状态区分 |
| Red Hat 安全公告/CSAF | https://access.redhat.com/security/security-updates/ | RHEL/RHSA 与包修复状态 | 识别产品、EUS 分支和修复包版本 |
| 其他系统/厂商 RSS/API | 各厂商官方公告 | Alpine/Rocky/Alma/CentOS Stream/openSUSE、PHP、Node.js、Docker 等 | 每个适配器独立定义更新水位及来源可靠度 |

**来源合并原则**：以 CVE ID 为主要关联键；GHSA/OSV 无 CVE 的记录使用各自 ID 建独立主实体；源报告不能强制覆盖其他来源的冲突字段。对产品包采用 PURL/CPE + 厂商/发行版标识，保留映射置信度。

**特殊情况**：CVE 可能被拒绝、拆分、合并，厂商可能调整严重性和修复版本。必须使用事件记录和数据版本，而不是只有一个可覆盖的最终字段。

---

## 5. 历史数据规模、分层、同步与存储策略（关键）

### 5.1 保留策略

| 类别 | 入库范围 | 持久化策略 | 重核频率 |
|---|---|---|---|
| 基础 CVE 索引 | 全部已公开历史（含撤销墓碑） | 长期、不按年份删 | 随官方增量变化更新；每周对账 |
| 近 90 天新增/更新 | 全部公开严重程度 | 结构化详情缓存、来源与版本事实 | 每小时/随上游更新 |
| KEV/高危/仍被利用/未修复 | 不限年份 | 长期保存关键结构化详情与事件轨迹 | 每日复核 + 官方变化立即重算 |
| 其他历史长尾 | 不限年份 | 最小索引；详情可按需补齐 | 用户访问时按需补充，定期抽样核验 |
| 采集流水日志/临时原始文件 | 所有源 | 例如 30–90 天轮转，保留必要审计元数据 | 自动回收 |
| 经审核修复规则与来源证据 | 不限年份 | 版本化、可追溯 | 每次修订留历史 |

上述周期是可配置默认值。**绝不将“超过 90 天”理解为自动删除或停止监控**。

### 5.2 初始化与后续增量

1. 启动时优先导入 CVE Program 官方 baseline，采用流式 ZIP 解压和分批 upsert，不要一次把所有记录加载内存，也不要复制整个 Git 历史。
2. 初始导入记录 `source_cursor` / release 标识 / 最后成功批次；可在失败后继续，重复导入不产生重复数据。
3. 基线导入期间独立消费后续 delta，完成基线后按修改时间进行补偿对账，避免跨越时间窗漏掉更新。
4. 高频采集使用官方增量能力（ETag、Last-Modified、游标、delta 或时间窗）；对 NVD/GHSA 做分页、频率限制、429/5xx 退避、抖动。
5. 每天运行一次 7 天滚动窗口补偿同步，每周做一次更大范围的基准对账；数据源存在历史修订时进行按需回补。
6. 系统记录 `published_at`（首次公开）、`source_modified_at`（官方修改）、`ingested_at`（本项目接收）三个不同的时间字段，统一存 UTC。
7. 用户查询历史 CVE 不命中详细包版本信息时，只提示“需要从上游核验”，绝不把“没找到”显示为“安全”。

### 5.3 存储成本控制

- 主表保存规范化检索字段与必要的证据；巨大原始 JSON 按压缩文件/对象存储或短期可追溯缓存管理。
- 搜索第一版使用 PostgreSQL FTS + `pg_trgm`（可选），优先建针对 CVE ID、更新时间、KEV、严重级、产品/软件包的索引。
- 热数据与长尾数据可逻辑分层，不急于物理分库；观察真实数据规模再分区。
- 定期 `VACUUM/ANALYZE`、备份与恢复演练；报告数据库体积、索引体积和每日新增量，避免纸面估算替代测量。
- 针对公开数据的来源使用条款、商标和再分发许可做明确归属；不要把第三方许可自动等同于项目自身 Apache-2.0。

### 5.4 为什么不能直接按上游版本比较？

发行版可能对旧版本回移安全补丁。示例：`OpenSSL 3.x 某发行版包` 即使低于上游修复版本，也可能包含补丁；同一个产品在 Debian 12/13、Ubuntu 22.04/24.04、RHEL 9 的修复包版本不相同。

**版本判断优先级**：发行版/产品官方公告的特定包状态与修复版本 > 上游厂商明确的发行版本范围 > 经核验的 GHSA/OSV 范围 > CPE 泛匹配（仅作线索）。

若没有足够证据，应输出 `UNKNOWN` 或 `POTENTIALLY_AFFECTED`，不得宣称“确认存在漏洞”。

---

## 6. 数据模型（建议 PostgreSQL）

应由 Alembic 生成迁移；以下是概念模型，不要求照抄字段名：

| 表 | 核心字段 / 索引 | 用途 |
|---|---|---|
| `vulnerabilities` | `id`（CVE/GHSA/OSV）、`status`、`summary`、`published_at`、`updated_at`、`severity`, `kev`, `last_verified_at` | 主实体与全历史检索 |
| `advisories` | `source`, `source_advisory_id`, `url`, `published_at`, `modified_at`, `content_hash`, `confidence` | 多来源事实和归属 |
| `vulnerability_aliases` | `vuln_id`, `alias`（CVE、GHSA、OSV） | 多 ID 去重与关联 |
| `affected_products` | `vuln_id`, `vendor`, `product`, `purl`, `cpe`, `range_expression`, `range_type` | 通用产品及版本范围 |
| `distro_package_status` | `vuln_id`, `distro`, `release`, `repo_channel`, `package`, `status`, `fixed_version`, `advisory_id` | 发行版具体补丁状态 |
| `vulnerability_events` | `vuln_id`, `event_type`, `old_value`, `new_value`, `detected_at`, `source_id`, `fingerprint` | 历史变更和触发告警 |
| `ingestion_state` | `source`, `cursor`, `etag`, `last_success_at`, `error_count`, `last_error` | 断点续采与质量监控 |
| `community_submissions` | `type`, `author`, `reference_url`, `body`, `review_state`, `reviewer`, `created_at` | 用户投稿与人工审核 |
| `remediation_guides` | `vuln_id`, `scope`, `safe_checks`, `upgrade_guidance`, `validation`, `source_refs`, `reviewed_at` | 结构化修复指南 |
| `subscriptions` | `channel`, `verified_target`, `filter_json`, `enabled` | 用户订阅（MVP 可推迟） |
| `notification_deliveries` | `event_id`, `target_id`, `fingerprint`, `status`, `attempts`, `sent_at` | 事件级去重、重试与投递状态 |

**必要约束**：所有上游 ID 与别名设唯一约束，增量导入具有幂等性；源记录不可被社区未经审核覆盖；删除/撤回保留审计事件。

---

## 7. 漏洞风险优先级与通知

### 7.1 重要级判定

- **P0 紧急**：新增 KEV/可靠证据确认在野利用，且广泛部署或暴露面大；有针对关键基础设施的可利用漏洞且已发布紧急补丁/缓解。
- **P1 高优先**：CVSS Critical/High，且具备可信的可远程触达场景，或厂商明确紧急更新；暂未证实在野利用。
- **P2 信息更新**：修复包发布、影响范围扩大/缩小、攻击条件变化、误报纠正；若用户订阅匹配则推送。
- **P3 常规**：中低危、旧公告一般修订，只入库/归档，不默认打扰用户。

评分要综合 KEV、利用证据、受影响面、认证前置条件、网络暴露、补丁可用性、厂商提示；CVSS 分数只是一个维度。重要变化要带出处，禁止从评分直接推断“root 提权”。

### 7.2 事件触发（旧 CVE 同样触发）

- `new_publication` / `added_to_kev` / `confirmed_exploitation`
- `severity_escalated` / `affected_range_expanded`
- `fixed_version_published` / `patch_regressed_or_withdrawn`
- `material_correction` / `poc_published`（PoC 不等于已在野利用）

**去重键**：`event_type + vulnerability_id + meaningful_version/source_revision + subscription_target`。推送应是“发生了什么变化”，而非每小时重发同一个 CVE。

### 7.3 推送渠道

- V0.1：网站首页重大公告、RSS/Atom、Telegram（站长广播频道或授权订阅）。
- V0.2：Webhook、邮件、按发行版/软件生态定制订阅。
- 投递失败重试，限速，定期汇总，提供取消订阅；不自动收集用户 VPS 清单。

**告警模板**：CVE、首次披露日、新进展日期、影响组件和版本、修复版本、攻击前提、是否 KEV/在野、用户应该采取的动作、来源链接、未确认点。

---

## 8. Web 页面与 API

### 8.1 页面

1. 首页：搜索框、过去 24 小时重大变化、KEV 动态、主要发行版筛选、项目介绍、CLI 安装入口。
2. `/cve/{id}` 或 `/advisory/{id}`：漏洞详情、多个来源、版本/发行版补丁矩阵、历史时间线、修复建议、纠错入口。
3. `/feed`：按时间、严重级、来源、产品、KEV、是否有补丁筛选；默认近期最重要事件而不是堆砌全部 CVE。
4. `/scanner`：CLI 使用示例、权限说明、报告示例、受支持系统矩阵、离线用法。
5. `/contribute`：提漏洞、补充公告、修复建议、检测规则、纠错和负责任披露引导。
6. `/about`、`/privacy`、`/security`、`/docs`：来源与授权、隐私、工具边界、自部署说明。

### 8.2 API（建议先只读）

- `GET /api/v1/health`：状态（不得泄露环境变量/数据库信息）。
- `GET /api/v1/vulnerabilities?q=&severity=&kev=&product=&since=&page=`。
- `GET /api/v1/vulnerabilities/{id}`。
- `GET /api/v1/vulnerabilities/{id}/events`。
- `GET /api/v1/advisories?source=&updated_since=`。
- `GET /api/v1/rules/manifest`：版本号、校验哈希、下载链接、签名信息。
- `GET /rss.xml`：主要风险事件。
- `POST /api/v1/submissions`（可推迟）：防滥用、限制大小、审核后展示；不接受未经校验的任意脚本执行。

API 分页上限、速率限制、输入验证、缓存头、结构版本号、OpenAPI 文档应从 V0.1 即具备。敏感管理接口不应挂在公开 API 下。

---

## 9. VPS 自检工具（必须明确范围）

### 9.1 CLI 用户体验

正式命令建议：

```bash
secwatch scan --scope os,containers --format table
secwatch scan --format json --output scan.json
secwatch scan --offline --rules ./rules-bundle.json
secwatch explain CVE-2026-XXXXX
secwatch doctor
```

以上是**计划接口**，非当前可执行命令。不得以 `curl https://... | sudo bash` 作为唯一安装方法；优先 GitHub Release 下载校验哈希/签名的二进制包。

### 9.2 最小采集面

- OS：`/etc/os-release`、包管理器已安装版本、当前运行内核、是否有新的已安装内核及待重启状态；Ubuntu/Debian、RPM、APK分别处理。
- 端口/服务：只收集当前运行服务与监听关系用于判断“是否暴露”，默认不主动探测公网 IP。
- Docker：可选检测正在运行的容器、镜像 ID、基础镜像、软件 BOM；需要 Docker 权限时明确提示该权限等同于较高宿主机控制能力，用户需明确启用。
- 语言依赖：从 lockfile/SBOM 或受支持的检测器得出，不默认扫描所有用户隐私目录。
- 工具运行结果：记录本地检测时间、规则数据库版本、数据源、受支持范围与限制。

### 9.3 风险判断状态

- `CONFIRMED_AFFECTED`：版本、发行版包状态或明确条件均满足，来源可靠。
- `POTENTIALLY_AFFECTED`：泛产品/版本范围匹配，但缺关键条件或不确定发行版回移补丁。
- `FIXED`：官方包/运行镜像确定包含修复；需标明是“已安装”还是“已运行生效”。
- `NOT_APPLICABLE`：明确不存在该组件/版本/条件（且检查范围足以支持）。
- `UNKNOWN`：组件不可读、情报缺失、第三方来源、映射置信度不足。

**不可把“没找到软件包”或“命令不在 PATH”单独作为彻底不受影响的证明**，因为容器、静态打包二进制、内置模块等可能绕过 PATH 检查。

### 9.4 修复输出

每项至少包含：事实依据、涉及资产、官方修复版本/发行版包、只读复核命令、建议操作、可能停机/重启提示、修复后验证命令、来源链接；存在回移补丁时解释比较方法。禁止自动执行管理员级升级，禁止运行社区自由文本命令。

### 9.5 隐私与可信

扫描默认仅本地处理；不上传完整软件清单、IP、域名、环境变量、证书、SSH 密钥。在线规则更新仅下载经过签名/校验的规则包，远程服务不得下发任意 Shell 代码。支持离线报告，输出中默认脱敏主机名与私人路径。

---

## 10. 社区贡献与审核

### 10.1 渠道

- 首期：GitHub Issues Form（新公告、纠错、修复指南、规则贡献），PR 审核；站点提供明确入口。
- 后续：站点原生投稿表单（验证码/反垃圾、限速、管理员审核队列、贡献者署名可选）。
- **未公开漏洞**：引导向厂商/协调披露渠道报告，禁止平台自动公开敏感利用细节。
- **SecWatch 自身漏洞**：通过仓库 `SECURITY.md` 与 GitHub 私密漏洞报告渠道。

### 10.2 规则贡献门槛

每个检测/修复规则应包含：唯一 ID、匹配范围、受支持系统、正/负测试用例、来源、危险操作声明、维护者审核记录。不得直接执行 PR 提交的未知脚本来验证其安全性；CI 对来自 fork 的 PR 应最小权限、无生产密钥。

### 10.3 信息信誉

分级显示：`官方来源`、`社区已审核`、`社区待核实`。待审核信息不能触发生产紧急推送或自动修复。修复方法过期后保留历史版本并标注 `deprecated`。

---

## 11. 安全与运维硬性要求

- 公网仅暴露 HTTPS/必要的 HTTP 重定向；PostgreSQL、Docker Socket、采集器和内部管理服务不公开端口。
- 使用专用低权限容器用户、read-only rootfs（条件允许）、最小 Linux capabilities，敏感凭据通过环境或密钥机制注入，绝不写进 Git。
- 上游 URL 及社区来源抓取要防 SSRF：限制重定向、DNS 重绑定、内网/链路本地地址和下载体积。
- 防存储型 XSS、SQL 注入、模板注入、任意文件上传、路径穿越；社区 Markdown 必须净化。
- 发布版本提供 SBOM、依赖扫描、容器镜像固定摘要或明确版本与定期升级流程。
- Cloudflare 可提供防护与缓存，但源站仍需鉴权、限速、WAF/防火墙与自动备份。
- 数据库每天备份，保留多代，定期测试恢复；新部署支持迁移回滚（含破坏性变更保护）。
- 采集任务失败报警；监控每个来源上次成功时间、异常率、数据库容量和通知失败量。
- 用户数据最小化；若收集邮箱/Telegram 标识，提供删除和退订渠道。

---

## 12. GitHub 仓库建议结构

```text
secwatch/
├── .github/
│   ├── workflows/              # CI、构建、发布、依赖扫描
│   └── ISSUE_TEMPLATE/         # 漏洞贡献/纠错表单
├── apps/
│   └── server/                 # FastAPI + Web + API + 业务逻辑
├── collector/
│   ├── adapters/               # cvelist、KEV、NVD、GHSA、OSV、各发行版
│   ├── normalization/          # CVE/GHSA/PURL/CPE、范围与时间处理
│   └── scheduler/              # 游标、重试、限速、对账
├── scanner/                    # CLI（Go 或先行 Python）
├── rules/                      # 审核过的检测规则与测试
├── remediation/                # 修复指南模板和适用条件
├── migrations/                 # Alembic 迁移
├── docs/                       # 自部署、架构、FAQ、贡献说明
├── tests/                      # 单元/集成/模拟源测试
├── deploy/
│   ├── compose.yaml
│   ├── Caddyfile
│   └── .env.example
├── LICENSE
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
└── THIRD_PARTY_NOTICES.md
```

V0.1 允许简化目录，但不要把所有采集逻辑、Web、告警写进单个脚本。数据源适配器必须有统一接口和测试夹具。

---

## 13. 分期交付范围

### 里程碑 A：可用的开源情报站（V0.1-A）

- 单机 Docker Compose 部署；Web 检索、CVE 详情、官方来源、事件列表、RSS。
- CVE Program 全历史索引初始化与可恢复导入。
- CISA KEV + GitHub GHSA + NVD/OSV 基础增量适配（先通核心字段，再扩展）。
- PostgreSQL 迁移、健康检查、采集水位和状态页。
- 社区 GitHub Issue 模板及网站提交入口。

### 里程碑 B：真正可用的 VPS 自检（V0.1-B）

- 首批 Debian/Ubuntu OS 包检测；运行内核与已安装内核区别；容器可选扫描。
- 优先复用 Trivy/OSV-Scanner 的可靠匹配能力；输出 JSON、人类可读表格和证据链接。
- 加入官方发行版补丁状态解释与“不确定”结论。
- 修复方法只读建议；不自动升级。

### 里程碑 C：订阅及更多系统（V0.2）

- Telegram/邮件/Webhook 用户可配置订阅；P0/P1 去重、变化事件、退订。
- RHEL/Rocky/Alma/Alpine、更多上游厂商公告适配。
- 原生投稿审核、错误纠正历史、已审查检测规则。

### 里程碑 D：进阶能力（V1.0）

- 更多发行版、SBOM 导入、离线同步、组织级订阅、跨版本历史分析。
- 经授权的 GitHub 修复 PR/配置建议；**用户批准和测试通过后**才可部署。

避免以“支持所有 OS”作为 V0.1 的验收目标；以“准确披露覆盖能力、清晰标注未知、持续扩展”为交付标准。

---

## 14. 关键测试、验收与质量门槛

### 14.1 情报数据

- 同一 CVE 来自 cvelist/NVD/GHSA 时正确关联，且保留各来源描述与评分。
- 同一 delta 重复导入结果不变；网络中断后能续采；旧 CVE 新加入 KEV 必须产生新的告警事件。
- 已拒绝 CVE 不出现在有效漏洞列表，也能通过 ID 查询到状态说明。
- 数据分页不丢项；UTC 时间统一；无来源记录不允许标为已证实在野利用。

### 14.2 漏洞匹配

- Debian/Ubuntu 安全回移补丁样例：不得仅因上游版本较低而判定 `CONFIRMED_AFFECTED`。
- 宿主机无 Node、容器有 Node：能够识别容器内依赖或明确标注未扫描容器。
- 有新内核文件但正在运行旧内核：必须区分“补丁已安装”与“补丁已生效”。
- 无法执行 `php -v` 但服务为 PHP-FPM/内嵌 PHP：不得直接视为无风险。
- 规则缺失/证据冲突：显示 `UNKNOWN`，保留来源和原因。

### 14.3 安全与部署

- CI：单测、集成测试、格式检查、静态检查、依赖和容器扫描、许可证清单。
- Compose 一键部署可重复执行；迁移幂等；重启后任务水位不丢。
- 数据库仅内网可达；站点对匿名提交有限流与审核。
- 备份恢复演练至少成功一次；文档提供删除测试数据和灾备恢复步骤。
- 禁止 CI fork PR 获取生产凭据；禁止执行外部不可信规则。

### 14.4 交付验收文件

- `README.md`（中英文概要），`docs/installation.md`、`docs/architecture.md`、`docs/data-policy.md`、`docs/security-model.md`。
- `.env.example`、生产 Compose、迁移、健康检查脚本、更新与回滚指南。
- CLI 使用文档、支持矩阵、样例 JSON 结果。
- 完整来源/版权归属、开源 LICENSE、SECURITY 和贡献模板。

---

## 15. 开发执行策略（交给 Codex）

1. **先探测环境**：确认部署主机可用 CPU、磁盘、Docker/Caddy/端口、现有业务、网络出口与备份条件；不擅自覆盖已有 `/opt/ly-stack` 或其他项目。
2. **建仓前先完成基本骨架和测试**：可本地搭建完整开发目录，待仓库归属确定后推送；不要假定 GitHub `ly2u/secwatch` 已存在。
3. **按阶段提交**：数据库迁移 → cvelist 基线/增量 → KEV/GHSA 适配 → API/Web → RSS/事件提醒 → CLI 基础扫描 → 文档。
4. **先跑小样本，再跑全量**：为全量导入加入 `--limit`、批大小、速率控制、检查点与进度显示；不得在 VPS 上直接无上限拉取或构建巨大镜像。
5. **每个适配器必须测试**：保存公开数据的最小测试夹具，测试差异化的日期、拒绝记录、错误版本区间、断网、429、格式变化。
6. **禁止隐式高风险操作**：生产部署、DNS 修改、数据库重建、数据卷清理、公共推送启用，需要有清晰确认和回滚路径；开发过程可自行完成非破坏性分析和代码验证。
7. **每个里程碑产出**：变更文件、测试结果、启动命令、访问地址、已覆盖来源/未覆盖内容、剩余问题与回滚方式。

---

## 16. 尚需最终确认的少量参数（不阻塞开发骨架）

- GitHub 实际仓库 Owner 及名称是否使用 `secwatch`。
- `sec.ly2u.com` 的 DNS 和 Cloudflare 代理配置。
- 正式 VPS 部署路径（建议 `/opt/secwatch`）与磁盘/备份目标。
- Telegram 频道或 Bot 的建立与管理员身份；对外公告语言默认中文，保留英文原文和未来国际化接口。
- 是否第一期直接开放匿名社区表单（默认 GitHub Issues/PR，以减少滥用和维护成本）。

---

## 17. 参考官方资料

- CVE 官方数据：<https://github.com/CVEProject/cvelistV5>
- CISA KEV：<https://github.com/cisagov/kev-data>
- NVD CVE API：<https://nvd.nist.gov/developers/vulnerabilities>
- GitHub Global Advisories API：<https://docs.github.com/en/rest/security-advisories/global-advisories>
- OSV：<https://osv.dev/>
- Ubuntu Security API：<https://ubuntu.com/security/api/docs>
- Debian Security Tracker：<https://security-tracker.debian.org/tracker/>
- Red Hat 安全公告：<https://access.redhat.com/security/security-updates/>
- Trivy 漏洞检测文档：<https://trivy.dev/latest/docs/scanner/vulnerability/>

**注意**：上游 API 字段、免费额度、发布周期可能变化；Codex 实施时应阅读当时的官方 API/授权文档，而不是依赖本文写死任何限额或未验证的漏洞信息。
