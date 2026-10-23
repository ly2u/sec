# 给 Codex 的实施说明（V0.1）

## 先读这两个文件

1. `docs/ARCHITECTURE.md`：**最终架构依据**，必须遵守。
2. `docs/prd-v0.1.md`：长期愿景参考。与 ARCHITECTURE.md 冲突时，以 ARCHITECTURE.md 为准。

项目名为 LY2U SecWatch。站点地址为 `sec.ly2u.com`，代码仓库为 `ly2u/sec`，许可证为 Apache-2.0。你运行在**生产 VPS** 上，所以 ARCHITECTURE.md 中 D7 的隔离规则优先于一切。

---

## 硬性规则（任何阶段都适用）

1. **不碰已有服务**。不得修改、停止或重建已有的容器、网络、数据卷、反代配置、防火墙、crontab 和 systemd 单元。如果确实需要，先写出计划和回滚步骤，然后**停下来等待确认**。
2. **开发环境隔离**。开发目录为 `/opt/secwatch-dev`，Compose 项目名为 `secwatch-dev`，端口只绑定 `127.0.0.1:18xxx`。
3. **扫描器只读**。扫描器不得写系统文件、不得联网上传、不得执行修复命令。外部二进制只能通过"绝对路径 + 写死的只读参数"方式调用，不经过 shell，必须设置超时。
4. **数据包只含事实**。数据包中不得包含任何可执行文本。修复命令只能由扫描器内置模板生成，包名必须通过白名单正则校验。
5. **版本比较用成熟库**。必须使用 dpkg/rpm/apk 原生比较算法的成熟实现，禁止自己写版本比较逻辑。
6. **全量操作先小样本**。全量导入、全量下载之前，先检查磁盘余量，并用 `--limit` 小样本跑通。
7. **密钥不入库**。密钥和令牌不得进入 Git。发布签名私钥不得放在本机。
8. **镜像卫生**。SecWatch 的每个服务只保留"当前版本 + 上一个版本"两个镜像标签，旧的在新版本验证通过后删除。不要给每次试验构建都打标签。清理时只按明确的标签列表删除，**禁止使用 `docker image prune -a` 和 `docker system prune`**，因为它们会波及 ly-stack 的回滚镜像。
9. **如实汇报**。没有实际运行过的功能，不得写成"已完成"。

---

## 阶段 0：只读环境探测（完成后停下汇报）

请输出一份 `docs/host-survey.md`，**不要提交到公开仓库，因为其中包含主机信息**。内容包括：

- CPU、内存、磁盘余量（总量与可用量），Docker 和 Compose 版本
- 80/443 端口被谁占用，现有反代是什么（nginx / Caddy / Traefik / 面板），配置文件在哪里
- 现有的容器、Compose 项目、`/opt` 目录结构（只列出目录，不读取任何 `.env` 文件）
- 防火墙现状（ufw / firewalld / iptables / nftables）
- 出网是否能访问 GitHub、`storage.googleapis.com`、`www.cisa.gov`、FIRST EPSS 相关地址
- 你建议的接入方式：在现有反代中新增站点，还是新起 Caddy；理由是什么

**完成后停下，等待确认。**

---

## 阶段 1：仓库骨架与数据底座

**阶段 0 结论（已确认，2026-10-23）**

- 工作副本统一使用 `/opt/secwatch-dev`。在该目录重新 clone 仓库，然后删除 `/root/ly2u_SecWatch/sec` 这个临时副本，避免出现两份代码互相不一致。删除前先确认 `docs/host-survey.md` 已经复制过去。
- 推送凭据：站长通过 SSH agent 转发提供，机器上**不保存任何 GitHub 密钥**。remote 使用 SSH 地址（`git@github.com:ly2u/sec.git`）。推送前先用 `ssh-add -l` 检查 agent 是否可用；不可用时（站长没有连接、后台任务、定时任务等情况）**不要尝试其他凭据，也不要生成或配置任何密钥**，把提交保留在本地，并在汇报中写明"有 N 个提交待推送"。不得把 agent socket 暴露给任何容器。
- 网络和资源上限按 ARCHITECTURE.md D6 第 1、1a 条执行。Compose 文件从一开始就要写好 `secwatch-edge` 外部网络的声明（开发环境中可以先不创建这个网络，用 profile 或覆盖文件控制），并设置资源上限。

1. 按 PRD 第 12 节创建目录骨架，可以适当简化。需要包含：`apps/server`、`collector/adapters`、`scanner/`（Go）、`rules/products`、`migrations`、`deploy/`、`docs/`、`tests/`、`.github/`。
2. 编写 SQLAlchemy 模型和 Alembic 迁移。至少包括以下表：
   - `vulnerabilities`
   - `vulnerability_aliases`
   - `affected_packages`（发行版与生态的范围和状态）
   - `kev_entries`
   - `epss_scores`（只保留当日值，可选保留 30 天历史）
   - `vulnerability_events`
   - `ingestion_state`
3. **cvelistV5 适配器**：
   - 基线采用流式解压 ZIP，分批 upsert，支持断点续传，用 `--limit` 参数控制规模
   - 增量更新使用官方 delta
   - 解析 CISA ADP 容器，提取 CVSS、CWE、SSVC、KEV 标记
   - REJECTED 状态的记录保留为墓碑，RESERVED 状态的记录不展示
4. **KEV 适配器和 EPSS 适配器**：
   - EPSS 的下载地址以 FIRST 当前官方文档为准，不要写死
   - 实现事件生成逻辑。"旧 CVE 新进 KEV"必须生成 `added_to_kev` 事件
5. **测试**：
   - 每个适配器都要有离线测试夹具。夹具使用真实公开数据的最小切片
   - 必须覆盖以下场景：重复导入的幂等性、REJECTED 记录、429/5xx 错误时的退避、中断后续传

**验收标准**：用 `--limit 1000` 导入成功；KEV 和 EPSS 数据完整入库；测试全部通过。

---

## 阶段 2：OSV 与数据包

1. **OSV 适配器**：
   - 下载 `Debian/all.zip`、`Ubuntu/all.zip`、`Alpine/all.zip`、`Rocky Linux/all.zip`、`AlmaLinux/all.zip`
   - 生态的准确目录名，以 `ecosystems.txt` 为准
   - 按 `affected[].package.ecosystem`（如 `Debian:12`、`Ubuntu:24.04:LTS`）拆分到各个发行版版本
   - 增量更新使用 `modified_id.csv`
2. **数据包生成器**：
   - 按 ARCHITECTURE.md D2 中的 schema v1 生成
   - 每个发行版版本输出一个 `.json.zst` 文件
   - 文件名带内容哈希，同时生成 minisign 签名和 `manifest.json`
   - 首批支持的版本：Debian 11、12、13；Ubuntu 20.04、22.04、24.04；Rocky 8、9；Alma 8、9；Alpine 最近 3 个版本
3. **worker 调度**：
   - 每小时运行一次增量更新
   - 只重建有变化的数据包
   - 使用进程锁，防止多个实例同时运行

**验收标准**：

- 手工抽取 5 个 CVE，在 Debian Security Tracker 和 Ubuntu CVE 页面上核对它们在数据包中的状态和修复版本，并把结果记录在汇报中
- 记录每个数据包的大小

---

## 阶段 3：Go 扫描器（`secwatch`）

按以下顺序实现，每完成一层都要跑测试：

1. **OS 识别与包读取**：
   - Debian/Ubuntu 优先，然后是 RPM，最后是 APK
   - 必须做源码包映射，见 ARCHITECTURE.md D2
2. **L1 匹配**：
   - 下载数据包，校验签名，使用本地缓存，支持 `--offline --bundle <file>` 离线模式
   - 输出五种状态之一：`CONFIRMED_AFFECTED`、`POTENTIALLY_AFFECTED`、`FIXED`、`NOT_APPLICABLE`、`UNKNOWN`
3. **L3 生效状态**：
   - 内核：比较运行中的内核与已安装的内核，并检查 `reboot-required`
   - 进程：扫描 `/proc/*/maps` 中带 `(deleted)` 标记的库，并对应到具体服务
4. **L2 产品规则**：
   - 规则格式为 `rules/products/*.yaml`
   - 首批覆盖约 12 个产品，包括宝塔、`/usr/local`、nvm 等路径
   - 每条规则必须附带正例和反例测试
   - 实现 `--no-exec` 开关
5. **L4 暴露面**：通过 `/proc/net/tcp*` 建立"端口 → 进程"映射，只用于调整排序
6. **输出格式**：
   - 默认为中文表格；`--format json` 输出 JSON（JSON 带 schema 版本号）；`--lang en` 输出英文
   - 每条结果都要包含：依据、来源链接、修复命令（模板生成）、修复后的验证命令、是否需要重启
   - 主机名和私人路径默认脱敏
7. **集成测试**：
   - 使用 `debian:12`、`ubuntu:24.04`、`rockylinux:9`、`alpine` 容器
   - **必须包含至少一个真实的回移植用例**。上游版本号低于修复版本，但发行版已修复，扫描器必须判定为 `FIXED`
   - 增加 `debian:13`。本机就是 Debian 13，阶段 3 结束时要在本机（宿主机）上以只读方式实际运行一次 `secwatch scan`，作为第一个真实环境验收。运行结果中如果出现 `CONFIRMED_AFFECTED`，要逐条人工核对 Debian Security Tracker。核对结果写入汇报，**不得提交到公开仓库**。
8. **发布**：
   - 使用 GitHub Actions 和 goreleaser 构建 linux amd64/arm64 二进制
   - 附带 sha256 校验和与签名
   - 发布签名使用 GitHub Actions secret，不得放在本机

---

## 阶段 4：Web 站点

站点使用 Jinja2 服务端渲染，**V0.1 页面不含任何 JS**，并遵守 ARCHITECTURE.md D5 的前端约束和检索方式。**不实现关键词全文搜索**（站长已决定）。需要以下页面：

- **首页**：编号直达输入框、最近 7 天 KEV 新增、P0/P1 事件、产品页入口、扫描器入口
- **`/cve/{id}`**：
  - 各来源的信息
  - 发行版状态矩阵（当前操作系统各版本的修复状态）
  - 事件时间线
  - 来源署名
- **`/go?id=...`**：编号直达。校验编号格式，如果是别名则先解析，然后 302 跳转到详情页；格式不合法时显示提示页。**不得**对输入内容执行模糊查询或 `LIKE` 查询。
- **`/product/{slug}`**：产品页，内容见 ARCHITECTURE.md D5。还需要新增"产品 ↔ 漏洞"映射表的迁移，以及 worker 中构建该映射的任务。映射规则来自 `rules/products/*.yaml`，与扫描器 L2 规则共用。验收时，每个产品抽查 10 条映射，确认不存在明显的误匹配（例如 `nginx` 误匹配到 `nginx-ui` 或 `nginx-proxy-manager`），并在汇报中列出抽查结果。
- **`/products`**：产品列表
- **`/scanner`**：安装、校验、使用方法、输出示例、支持矩阵
- **`/rss.xml`**
- **`/about`、`/privacy`、`/security`**

技术要求：

- API 只读，带分页上限，提供 OpenAPI 文档
- 页面输出合适的 `Cache-Control` 头，配合 Cloudflare 缓存
- Telegram：worker 在 P0/P1 事件发生时广播到单个频道。令牌通过 `.env` 注入；未配置令牌时跳过广播

---

## 阶段 5：生产部署（需要确认后执行）

1. 根据阶段 0 的结论，写出生产部署计划，内容包括：目录 `/opt/secwatch`、反代接入方式（按 ARCHITECTURE.md D6 第 1 条的 `secwatch-edge` 方案）、备份方案、回滚步骤。**等待确认后再执行。** 计划中还必须说明以下几点：
   - 现有 Caddyfile 中的站点证书是怎么获得的（HTTP-01 / DNS-01 / 手动证书）。`sec.ly2u.com` 开启了 Cloudflare 代理，因此 TLS-ALPN-01 验证无法通过；建议改用 Cloudflare Origin Certificate，在 Caddy 中用 `tls <cert> <key>` 指定。
   - 用 `openssl s_client` 实测以下三种情况，确认第一层防护是否已经生效：直接用 IP 连接且不带 SNI、使用伪造的 SNI、使用 `sec.ly2u.com` 作为 SNI。如果 Caddyfile 中存在兜底站点（例如 `:443` 或 `https://`），要指出来。
2. 给站长列出一份 Cloudflare 操作清单，由站长手动完成：
   - SSL 模式设为 Full (strict)
   - 申请 Origin Certificate
   - 反代默认站点拒绝未知域名和直接 IP 访问（ARCHITECTURE.md D6 第一层）。这一步**修改现有反代配置，需要确认后执行**
   - 列出 `ly2u.com` 下所有指向本机 IP 的子域名，以及它们是否开启了 Cloudflare 代理
   - 防火墙只放行 Cloudflare IP 段：**站长已决定 V0.1 不实施**（本机有不走 Cloudflare 的服务），不要修改防火墙
   - 配置缓存规则和限速规则
3. 设置每日 `pg_dump` 备份，至少保留 7 份，并至少完成一次恢复演练。

---

## 每个阶段的汇报格式（中文）

- **已完成**：列出文件和功能
- **实际验证**：运行了哪些命令，结果如何，测试是否通过
- **未完成或已知缺陷**
- **需要站长确认的事项**
- **下一步计划**
