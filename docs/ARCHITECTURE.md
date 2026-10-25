# LY2U SecWatch 架构决策（V0.1）

> 本文件是 V0.1 的**最终架构依据**。`docs/prd-v0.1.md`（原 PRD）作为长期愿景参考；两者冲突时以本文件为准。
> 版本：2026-10-23 · 状态：已定稿，实施中如发现与上游事实不符，先在 Issue 中记录再修改本文件。

---

## 0. 定位与差异化

**不重复造轮子**：漏洞"匹配"本身（尤其发行版回移植）已有成熟数据与工具（OSV、发行版安全追踪、Trivy）。如果我们只是又一个匹配引擎，没有存在价值。

**我们的价值在这四件事上**：

1. **看得见"非包管理"安装**：宝塔 / 1Panel / 源码编译 / 官方二进制 / nvm 安装的 nginx、PHP、Node.js、MySQL。这正是中文 VPS 用户最常见、也是 Trivy 这类通用工具最容易漏掉的地方。
2. **区分"已安装补丁"和"补丁已生效"**：内核未重启、服务进程仍在使用已被替换的旧库。很多人升级完以为安全了，其实没有。
3. **按真实风险排序**：KEV（已在野利用）+ EPSS（利用概率）+ 是否对公网监听，而不是只看 CVSS。
4. **中文、可执行、可验证的修复建议**：修什么、怎么修、修完怎么确认、会不会导致停机。

---

## D1. 情报源：V0.1 只接 4 个

| 来源 | 用途 | 说明 |
|---|---|---|
| **CVEProject/cvelistV5** | 全历史 CVE 索引、站点详情页 | 记录中的 CISA ADP 容器（Vulnrichment）提供 CVSS 3.1、CWE、SSVC、KEV 标记，可覆盖大部分原本要找 NVD 的需求 |
| **CISA KEV** | 已在野利用 | 最高优先级信号；"旧 CVE 新进 KEV"必须生成事件 |
| **EPSS** | 未来 30 天被利用概率 | 每日全量，用于排序。**原 PRD 遗漏了它，必须补上**。下载地址实施时以 FIRST 官方文档为准，不要写死 |
| **OSV 批量导出** | 发行版包状态 + 语言生态 | 覆盖 Debian、Ubuntu、Alpine、Rocky、AlmaLinux，以及 npm/PyPI/Packagist/Go/Maven 等（**已包含 GHSA**） |

**V0.1 明确不接**：

- **NVD API**：限速严格，且 NIST 已缩减补充分析范围；cvelistV5 里的 CISA ADP 数据已覆盖主要字段。V0.2 再作为补充源。
- **GHSA API**：OSV 已包含 GitHub Advisory 数据，重复接入只会带来去重工作。
- **Debian / Ubuntu 直连**：OSV 已转换并发布。只有发现 OSV 存在具体缺口时才写直连适配器。
- **RHEL 本体**：OSV 不含 Red Hat。Rocky / AlmaLinux 已在 OSV 中，覆盖了大部分 RHEL 系 VPS 用户。RHEL 留到 V0.2，接 Red Hat CSAF。

**OSV 使用注意**：

- 按发行版版本前缀的导出（如 `Alpine:v3.17`）**已停止**。应下载基础生态包（如 `Debian/all.zip`），再按 `affected[].package.ecosystem`（如 `Debian:12`）过滤。
- 增量更新使用 `modified_id.csv`。该文件按时间倒序排列，读到已处理过的时间戳即可停止。
- 各数据源许可证不同（例如 Ubuntu 为 CC-BY-SA 4.0，GHSA 为 CC-BY 4.0），需在 `THIRD_PARTY_NOTICES.md` 和站点页脚逐一署名。

---

## D2. 扫描器：数据包下发，本地匹配

**Go 单文件**，linux amd64/arm64，静态编译（`CGO_ENABLED=0`），零运行时依赖。不使用 Python，因为目标 VPS 的 Python 版本不可控。

```text
识别 OS/版本 → 读取已安装包 → 下载该发行版数据包 + 签名 → 校验 → 本地比对 → 输出报告
```

- **不上传任何东西**：兑现隐私承诺，同时满足"用我们自己的数据库"。服务器只知道"有人下载了 debian-12 数据包"。
- **版本比较必须使用发行版原生算法**：dpkg、rpm、apk 各有自己的比较规则（epoch、`~`、`+deb12u1`、`-r0` 等）。使用成熟库（如 Trivy 所用的 `knqyf263/go-deb-version`、`go-rpm-version`、`go-apk-version`），**禁止**自己写字符串或数字比较。
- **源码包 vs 二进制包（高发坑）**：发行版公告按**源码包**发布（如 `openssl`），系统里装的是**二进制包**（如 `libssl3`）。必须做映射：
  - Debian/Ubuntu：`dpkg-query -W -f='${binary:Package}\t${source:Package}\t${source:Version}\t${Version}\n'`
  - RPM：`rpm -qa --qf '%{NAME}\t%{SOURCERPM}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n'`
  - Alpine：`/lib/apk/db/installed` 中的 `o:`（origin）字段
  - 注意 binNMU 等情况下源码版本与二进制版本可能不同，比较时用源码版本。

### 数据包只含事实，不含命令

数据包中**不得出现任何 shell 文本**。修复命令由扫描器二进制根据内置模板生成，例如 `apt-get install --only-upgrade <pkg>`，其中 `<pkg>` 必须通过包名白名单正则校验。

这样即使服务器或数据包被篡改，最坏后果是"结论错误"，而不是"在用户机器上执行了代码"。这是整个信任模型的地基。

### 两把签名密钥分离

| 密钥 | 用途 | 存放位置 |
|---|---|---|
| 数据包签名钥（ed25519 / minisign） | worker 每小时签发数据包 | 服务器 |
| 发布签名钥 | 签名扫描器二进制 Release | 仅 GitHub Actions secret 或离线保存，**永不上服务器** |

服务器被攻破时，攻击者只能伪造数据（由上一条兜底），无法伪造二进制。

### 数据包格式（schema v1）

```json
{
  "schema": 1,
  "distro": "debian",
  "release": "12",
  "package_key": "source",
  "generated_at": "2026-10-23T03:00:00Z",
  "sources": { "osv": "2026-10-23T02:41:00Z", "kev": "2026-10-22", "epss": "2026-10-22" },
  "source_packages": {
    "openssl": [
      {
        "id": "CVE-2026-XXXXX",
        "aliases": ["DSA-XXXX-1"],
        "status": "fixed",
        "fixed_version": "3.0.15-1~deb12u1",
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u1"}]}],
        "requires_subscription": false,
        "fixes": [{"version": "3.0.15-1~deb12u1", "requires_subscription": false}],
        "severity": "HIGH",
        "cvss": 7.5,
        "kev": false,
        "epss": 0.0123,
        "ref": "https://security-tracker.debian.org/tracker/CVE-2026-XXXXX"
      }
    ]
  }
}
```

- `status` 取值：`fixed` | `unfixed`（发行版尚未修复）| `wont_fix`（如 Debian no-dsa / ignored）。
- 阶段 2 实测的 Debian OSV 可以用“只有 `introduced`、没有 `fixed`”表达尚未修复，但没有保留 Security Tracker 的 `no-dsa` / `ignored` 原因；因此当前转换只能诚实输出 `unfixed`，不能推断为 `wont_fix`。阶段 3 再决定是否直连 Debian Security Tracker 补齐该语义。
- `package_key` 决定阶段 3 扫描器用什么本机包名匹配：Debian/Ubuntu 为 `source`，Alpine 为 `origin`。阶段 2 对真实 OSV 数据的抽样显示 Rocky Linux 当前也是源 RPM 名（`source`），而 AlmaLinux 是二进制 RPM 名（`binary`）；不能按发行版家族想当然地统一处理。
- `ranges` 原样保留 OSV 的 `ECOSYSTEM` 事件及 `introduced` / `fixed` / `last_affected`，服务端不将它们换算成上游版本。版本比较留给阶段 3 的 dpkg/rpm/apk 成熟实现。
- Ubuntu Pro 修复在 `requires_subscription` 和逐修复项 `fixes[].requires_subscription` 中明确标记。扫描器遇到这类修复时提示“修复仅在 Ubuntu Pro 中提供”，不得输出普通升级提示。FIPS、Realtime、Livepatch 专用生态不混入标准发行版数据包。
- `coverage.missing_package_means` 固定为 `unknown`；包名不在数据包中不能被解释为“安全”。
- 文件名带内容哈希：`bundles/debian-12.<sha256前12位>.json.zst` + `.minisig`。`manifest.json` 指向最新文件，并通过 Cloudflare 长期缓存。
- **GitHub Releases 镜像推迟到 V0.2**：如果由服务器直接上传，就需要在 VPS 上存放 GitHub 令牌，违反"服务器不持有凭据"的原则。V0.2 改由 GitHub Actions 定时从 `sec.ly2u.com` 拉取已签名的数据包，再发布到 Releases。Actions 只做搬运，签名校验由扫描器负责，所以镜像是否可信不依赖 Actions 本身。

---

## D3. 四层检测（产品核心）

### L1 发行版包

使用 D2 的数据包，正确处理回移植，可以给出 `CONFIRMED_AFFECTED` / `FIXED` 结论。

**"包不在数据包里"的含义取决于包的来源**（阶段 3 实现）：
- 包来自**发行版官方仓库**：没有对应条目，表示"发行版数据中没有已知漏洞"。这类包只计数、不逐条列出，也不称之为"安全"。
- 包来自**第三方仓库**（如 nginx.org、Docker 官方仓库、NodeSource、PHP 的 sury 源）：发行版数据不覆盖这些包，结论一律为 `UNKNOWN`，然后交给 L2 按上游版本范围判断。这类包正是 nginx、PHP、Node 高危漏洞的重灾区。包的来源通过 apt 的软件源信息（`apt-cache policy` 或 `/var/lib/apt/lists`）、RPM 的 vendor/仓库字段等进行判定；判定不了时按第三方处理。
- **Ubuntu 合并规则**：同一个 CVE 如果标准通道显示"未修复"，而 Pro 通道已有修复，报告应写成"修复仅在 Ubuntu Pro 中提供"，而不是两条互相矛盾的结论。

`unfixed` / `wont_fix` 状态需要单独说明，例如："已知受影响，发行版暂未修复或不计划修复"，并给出缓解建议。不能简单输出"请升级"，因为根本没有可升级的版本。

### L2 非包管理安装（差异化重点，已实现）

**覆盖范围**：

- 宝塔、LNMP/OneinStack 等一键脚本、源码编译、官方二进制、OpenResty 安装的程序
- nvm、fnm、volta、n，以及宝塔 Node 版本管理器安装的 Node.js
- 路径不在规则中、但正在运行的程序（通过 `/proc/*/exe` 发现，且不属于任何软件包）
- 第三方软件源的软件包（nginx.org、Docker、NodeSource、sury、PGDG 等），从包版本中提取上游版本
- 静态编译进其他程序的组件，目前支持 nginx 内置的 OpenSSL（解析 `nginx -V` 输出）
- 容器内运行的相关程序：由下文“容器”一节的容器扫描覆盖

首批覆盖 12 个产品：nginx、PHP、Node.js、OpenSSL、OpenSSH、Redis、MySQL、MariaDB、Apache httpd、PostgreSQL、Docker Engine、containerd。

**产品规则** `rules/products/<slug>.json`（使用 JSON 而非 YAML：Go 与 Python 标准库都能解析，不需要额外的解析器依赖）。字段说明见 `rules/products/README.md`。

- `identity` 段由服务端使用，用于在 CVE 记录中识别该产品。厂商名和产品名已于 2026-10-23 对照真实的 CVE 数据核实过。nginx 只匹配 NGINX Open Source，**排除 NGINX Plus**（版本号体系不同），也排除 nginx-ui、ingress-nginx 等名字相近的产品。
- `detect` 段由扫描器使用。**规则编译进扫描器，不从服务器下发**：规则决定"执行哪个程序、带什么参数"，若由服务器下发，服务器一旦被攻破，攻击者就能指挥所有用户的扫描器执行任意程序。扫描器内嵌一份副本，测试会校验它与仓库中的规则一致。

**执行安全**：

- 只执行属于 root、且路径上每一级目录都不可被其他用户写入的程序。否则，普通用户可以替换程序，让以 root 运行的扫描器执行其代码。`/tmp` 下的任何程序都不会被执行。
- 参数固定且经过校验，不经过 shell；超时 5 秒，输出上限 64 KB，环境变量清空，超时后终止整个进程组。
- 不能安全执行的程序（例如普通用户目录下的 nvm），从路径中读取版本号；读不到时如实说明原因。
- `--no-exec` 模式下只使用路径和软件包信息，不执行任何程序。

**上游漏洞数据**：`upstream-1` 数据包，签名方式与发行版数据包相同，数据存放在 `upstream_advisories` 表中。

| 来源 | 适用产品 | 说明 |
|---|---|---|
| CVE 记录中 CNA 填写的 `affected[]` | PHP、nginx、OpenSSL、Redis、MySQL 等 | CVE 入库时同步，`upstream-backfill` 用于一次性补齐历史数据。分支通配（如 `8.3.*`）转换为分支区间。开放区间（如 F5 的 `1.25.0 <*`）截断到下一个列出的分支起点，表示"已停止维护、不会修复"。老记录的文字写法（`8.0.34 and prior`、`7.3.x below 7.3.17`、`Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c)`、带产品名前缀等）只识别无歧义的形式，组合字符串须每一段都能识别才采用。`defaultStatus: affected` 时只读列出的受影响区间；若同时列有 unaffected 例外则整条跳过。只写分支（`Apache HTTP Server 2.4`）、上界只到大版本（`v9.6 to v14`）、把修复版本误填为受影响的列表一律跳过，不做猜测。 |
| Node.js 安全工作组数据库 | Node.js | Node 内置了 Brotli、OpenSSL 等依赖，这些依赖的 CVE 登记在其他厂商名下，CVE 记录里查不到 Node。逐个读取 `vuln/core/*.json`，不使用 `index.json`（实测该文件更新滞后）。204 条记录中 200 条可以解析；无法解析的 4 条都是 2018 年以前 Node 0.10–10 时代的记录。 |

**判定规则**：

- 上游版本没有回移植问题，命中版本范围即判定为 `CONFIRMED_AFFECTED`。
- 修复目标取高于当前版本的最小修复版本。如果当前版本系列已停止维护，修复目标自然落到下一个仍受支持的分支。
- 修复指引按安装方式给出（宝塔、nvm、源码编译等）。第三方源的软件包给出包管理器命令。
- 内置的 OpenSSL 会单独说明：升级系统的 OpenSSL 对它无效。

### L3 补丁是否生效

**内核**：

- 比较 `uname -r` 与已安装的最新内核包。
- Debian/Ubuntu 还要检查 `/var/run/reboot-required`。

**用户态进程**：

- 扫描 `/proc/*/maps` 中带 `(deleted)` 标记的 `.so` 库映射。出现这种情况，说明库文件已升级，但进程还在使用旧版本，原理同 `needrestart`。
- 输出示例："openssl 补丁已安装，但 nginx（pid 1234）仍在使用旧库，需要重启 nginx 才能生效。"

`FIXED` 结论必须标明属于哪一种：`已安装` 或 `已生效`。

### L4 暴露面（只影响排序，不改变判定状态）

- 读取 `/proc/net/tcp*`，建立"监听端口 → 进程 → 包"的映射。
- 在 `0.0.0.0` 或 `::` 上监听的受影响服务排在更前面。
- 不主动探测公网。

### 容器（已实现，借鉴 Trivy 的思路）

以 root 在宿主机上运行时，扫描器会检查**运行中容器内的系统软件包**，不需要 docker 命令或 API：

1. **发现**：遍历 `/proc`，挑出挂载命名空间与自身不同、且 cgroup 中带有 docker/containerd/crio/libpod 容器 ID 的进程（systemd 沙箱、snap 也有独立命名空间，但没有容器 ID，因此不算）。每个容器取 PID 最小的进程。名称和镜像从 `/var/lib/docker/containers/<ID>/config.v2.json` 读取，经白名单正则校验，不合格就只显示 ID。
2. **读取**：经 `/proc/PID/root` 访问容器的根文件系统，所有路径用 `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` 解析，效果等同于 chroot：容器里的绝对路径或 `../` 符号链接**不可能指向宿主机文件**；只接受普通文件和目录（防止 FIFO 卡住扫描）。需要 Linux 5.6 以上。不执行容器里的任何程序。
3. **判定**：识别容器的系统版本，按需下载对应发行版的数据包（同一版本只下载一次），用与宿主机相同的匹配逻辑判定。镜像通常删除了 apt 索引，此时结论标为“可能受影响”。不支持的情况如实标为“未检查”：精简镜像（无 os-release 或包数据库）、不在支持范围的系统版本、RPM 系统的容器（读取 rpmdb 需要执行 rpm）。
4. **报告**：默认视图中每个容器一行；`--container NAME` 查看单个容器（可配合 `--pkg`、`--all`）。修复建议是拉取新镜像并重建容器，**不建议在容器内升级**。容器中的 P0/P1 同样会使退出码为 3。`--no-containers` 可关闭；最多检查 50 个容器。

暂不覆盖：未运行的镜像、容器内非 Go 的手动安装程序。

### Go 编译的程序（已实现，借鉴 Trivy/Grype 的思路）

Go 程序在二进制里记录了模块列表和编译用的 Go 版本（即 `go version -m` 的内容）。扫描器用标准库 `debug/buildinfo` 读取（只读打开文件，不执行；防御异常文件导致的 panic；只看 ELF、512 MiB 以内）。

- **候选程序**：宿主机上正在运行的程序（`/proc/*/exe`，仅宿主机命名空间）、`/usr/local/bin`、`/usr/local/sbin`、`/opt/*`、`/opt/*/bin`，以及第三方源软件包安装在 bin 目录的文件；最多 400 个。属于官方软件包的文件跳过（发行版数据已覆盖）；产品规则已判定过的（如 Docker CE）跳过，避免重复。容器内则检查容器进程的 `/proc/PID/exe`，因此只有一个 Go 程序的精简镜像（distroless/scratch）也能判定。
- **数据**：采集端新增 Go 漏洞库（OSV 的 `Go/all.zip`，CC-BY-4.0），表 `go_advisories`（迁移 0005），每 6 小时同步；签名数据包 `golang-1`，`package_key` 为 `module`，范围类型为 `SEMVER`，以 CVE 补充 CVSS/EPSS/KEV。`toolchain`（go 命令本身）不计入。
- **判定**：版本比较使用原样复制的 `golang.org/x/mod/semver`（`scanner/internal/thirdparty/semver`）。程序自身的模块（主模块；xcaddy 这类构建取与程序同名的依赖，如 caddy → `github.com/caddyserver/caddy/v2`）命中为“确认受影响”；内置依赖与 Go 标准库命中为“可能受影响”，并且除非在 KEV 中，优先级最高为 P2——是否真能利用取决于程序是否用到相关代码，扫描器暂不做 govulncheck 式的符号可达性分析。
- **报告**：每个程序一行（“Go 程序 / Go 程序内置组件”）。`--pkg 程序名` 给出组件表（程序本身、Go 标准库、各依赖的当前版本、漏洞数、修复所需的最低版本）和具体步骤：从模块路径推出的项目发布页（GitHub/GitLab）、替换哪个文件、从 cgroup 读出的 systemd 服务的重启命令；第三方源的程序给包管理器命令。逐个 CVE 放在 `--pkg 程序名 --all`。离线模式用 `--go-bundle` 提供数据包。
- **secwatch 自身**不在扫描范围内：它靠新版本提示保持更新；发布流程用最新稳定版 Go 编译，并在 `govulncheck` 发现可达漏洞时停止发布；Dependabot 负责依赖升级 PR。

### 新版本提示（已实现）

worker 每小时读取 GitHub 最新正式版本（只接受 `vX.Y.Z`，忽略草稿和预发布），写入 `manifest.json` 的 `scanner.latest`。这个字段不计入数据包指纹，发布新版本不会重建数据包。扫描器每次扫描本来就要读取 manifest，较新时在报告最后提示一行安装命令。manifest 尚未签名，所以这个字段只用作提示：扫描器**从不自动更新**，用户运行的安装脚本仍会校验发布签名。v0.1.3 及以前的版本不认识这个字段，不会提示。

---

## D4. 优先级

下表的 CVSS 数值阈值基于 **CVSS 3.x**，不得把 CVSS 2.0 或 4.0 的数值直接代入这些阈值。主评分用于展示；优先级中的 CVSS 条件应从保留的 3.x 评分中选取。KEV 归属只以 `kev_entries` 中当前有效的官方目录条目为准；ADP 的 KEV 标记仅作原始事实参考。

| 级别 | 条件（阈值可配置） |
|---|---|
| **P0 立即处理** | 在 KEV 中；或 CVSS ≥ 9.0 且服务对公网监听 |
| **P1 尽快处理** | EPSS ≥ 0.1；或 CVSS ≥ 7.0 且服务对公网监听 |
| **P2 计划处理** | 其余 High/Critical |
| **P3 了解即可** | Medium/Low；默认折叠显示 |

CVSS 只是其中一个维度。不得根据评分推断"可远程提权"之类的结论。

---

## D5. 服务端：沿用 PRD 技术栈，砍掉 V0.1 不需要的部分

**技术栈**：FastAPI + PostgreSQL + Jinja2（服务端渲染，不使用前端 JS 框架）+ 独立 worker。

**前端约束（轻量优先）**：

- **页面数据**：服务端直接渲染 HTML，然后交给 Cloudflare 缓存。对访客来说，效果等同于静态站。之所以不预先生成纯静态文件，有两个原因：一是约 30 万个 CVE 详情页每天都有大量记录更新，全量或增量预生成的成本反而更高；二是 CVE 编号直达和产品页需要实时查询数据库。
- **扫描器数据**：已经是纯静态文件（签名数据包加 manifest），与网站页面完全解耦。网站即使宕机，扫描器也能照常使用。
- **不做前端工程**：没有 npm 构建步骤，不使用 React、Vue 等框架。**V0.1 页面不含任何 JS**：编号直达使用普通表单提交，由服务端校验格式后返回 302 跳转；列表筛选通过 URL 查询参数实现。将来确实需要交互时，再考虑引入 HTMX。**例外（站长要求，2026-10-24/25）**：只有一个本站脚本 `/static/site.js`（约 90 行，不发任何网络请求），做两件事：命令旁的「复制」按钮，以及页头的浅色/深色切换（选择只存在本浏览器的 localStorage）。CSP 为 `script-src 'self'`，禁止内联脚本。脚本在 `<head>` 中同步加载，使记住的主题在页面绘制前生效、不闪烁。脚本未加载时页面照常可用：主题跟随系统设置，两个按钮保持隐藏。旧地址 `/static/copy.js` 返回同一文件，兼容缓存中的旧页面。
- **不引用任何外部资源**：不使用 Google Fonts、公共 CDN 或第三方统计脚本。这些在中国大陆可能加载失败，导致页面卡住。所有 CSS、JS、图标都从本站加载，字体使用系统字体栈。
- **页面体积预算**：单个页面的 HTML、CSS、JS 合计不超过 100 KB（gzip 前）。要支持移动端，支持深色模式（使用 `prefers-color-scheme`）。

| 保留 | 推迟到 V0.2+ |
|---|---|
| cvelistV5 全历史导入（CVE 详情页是 SEO 长尾流量的主要来源） | NVD、GHSA API、RHEL CSAF |
| KEV、EPSS、OSV 增量采集 | 独立的 notifier 服务、用户订阅 |
| 事件表：新 KEV、修复版本发布、严重度变化 | 网站投稿表单、管理后台 |
| 首页、`/cve/{id}`、编号直达、产品页 `/product/{slug}`、`/scanner`、RSS | 邮件、Webhook、**关键词全文搜索**（站长决定，2026-10-23；上线后根据访客实际需求再定） |
| 单个 Telegram 频道广播（P0/P1 事件，worker 内直接发送） | AI 生成中文摘要（见下） |
| 数据包生成、签名、manifest | |

**检索方式：编号直达 + 产品页，不做关键词全文搜索**

- **编号直达**：首页和顶栏各放一个输入框，接受 `CVE-YYYY-NNNN+`、`GHSA-xxxx-xxxx-xxxx` 以及 OSV/发行版公告编号（如 `DSA-5xxx-1`、`USN-xxxx-x`），不区分大小写，自动去除首尾空格。
  - 格式合法时，跳转到对应详情页；如果输入的是别名，通过 `vulnerability_aliases` 表解析后再跳转。
  - 格式不合法时，显示提示，并列出产品页入口。**不会对输入内容执行任何模糊查询。**
- **产品页** `/product/{slug}`，展示内容：
  - 该产品近 90 天的漏洞，按 D4 优先级排序
  - 全部 KEV 记录（不限年份）
  - 各发行版的修复状态
  - 对应的扫描器规则说明
  - 分页查看历史漏洞
- **产品注册表** `rules/products/<slug>.json`：扫描器 L2 规则和产品页共用这一套产品定义。每个产品声明 cvelistV5 中 `affected[].vendor/product` 的精确匹配对、检测路径、软件包名等。
- **产品 ↔ 漏洞映射（已实现）**：直接使用 L2 的 `upstream_advisories` 表，不另建映射表。它只收录 CNA 厂商/产品名精确匹配的记录（另加 Node.js Security WG），因此不会出现 `nginx` 混入 `nginx-ui`、`ingress-nginx` 的问题；每条记录保留来源链接便于核查。代价是：只有 CNA 写明了版本范围的漏洞才出现在产品页，见 `upstream-coverage`。
- **首批产品页**与 L2 的 12 个产品一致。之后社区每贡献一条产品规则，就自动多出一个产品页。

**V0.1 服务**：`web`、`worker`、`postgres`。只有当 VPS 上没有现有反向代理时，才增加 `caddy`。

worker 是常驻进程，以 PostgreSQL advisory lock 保证同一数据库只有一个调度 leader。KEV、cvelistV5 delta、OSV delta 每小时运行，EPSS 每日运行；首次启动按不同分钟错开，失败最多重试 3 次并将每次耗时、状态和错误写入 `task_runs`。只有采集实际处理了变更时才检查数据包内容，且只替换内容指纹发生变化的发行版数据包。

**数据规模**：cvelistV5 约 30 万条记录。数据库体积以实测为准，并记录在 `docs/capacity.md` 中。

**AI 中文摘要（V0.2 候选）**：只对 P0/P1 生成；只能基于来源原文；必须标注"AI 生成，以原文为准"；不得生成修复命令。在安全产品里，幻觉的代价很高。

---

## D6. 部署与 Cloudflare

1. **接入现有 Caddy（阶段 0 实测结论）**。本机 80/443 端口由 `ly-stack` 项目中的 Caddy 容器占用，Caddyfile 位于 `/opt/ly-stack/Caddyfile`。**不另起公网 Caddy。** 由于 Caddy 运行在容器里，它访问不到宿主机的 `127.0.0.1`，因此采用以下网络方案：
   - 新建一个独立的外部网络 `secwatch-edge`（`docker network create --internal secwatch-edge`：Caddy 仍能连到 web，web 本身不能出网）。
   - 证书：`sec.ly2u.com` 与现有站点一样由 Caddy 自动申请 Let's Encrypt 证书（站长决定，2026-10-24），Caddy 运行中加入网络，不重建、不中断现有站点；Cloudflare Origin Certificate 作为备选。
   - 生产使用独立的 `deploy/compose.prod.yaml`（项目名、镜像名均为 `secwatch`，web 不映射宿主机端口），执行步骤见 `docs/DEPLOY.md`。
   - SecWatch 这边**只有 `web` 容器**加入 `secwatch-edge`，且 web 只接 `db` 与 `secwatch-edge`；`postgres` 和 `worker` 只在 SecWatch 的内部网络中。
   - 在 `ly-stack` 的 compose 文件中，给 caddy 服务追加 `secwatch-edge` 网络（声明为 `external: true`），然后在 Caddyfile 中新增 `sec.ly2u.com` 站点，反代到 `secwatch-web:8000`。
   - **不要**让 SecWatch 直接加入 `ly-stack_default` 网络。那样会让我们的容器和 ly-stack 的其他服务互通，而且两个项目的生命周期会耦合在一起。
   - 修改 ly-stack 的 compose 文件和 Caddyfile 属于生产变更，只在阶段 5 确认后执行。具体步骤：先运行 `caddy validate`，再执行 `caddy reload`（不中断服务）；如果出问题，用备份的 Caddyfile 回滚。
   - 开发阶段（阶段 1–4）完全不接触 Caddy。`web` 只绑定 `127.0.0.1:18080`，站长通过 SSH 隧道访问。
1a. **资源上限**。这台机器还在运行 ly-stack 的线上服务，所以 SecWatch 的每个容器都必须设置 `mem_limit` 和 `cpus`，防止全量导入时抢占资源。建议初始值：
   | 容器 | 内存 | CPU |
   |---|---|---|
   | postgres | 4 GB | 2 |
   | worker | 2 GB | 1.5 |
   | web | 1 GB | 1 |

   全量导入之后，根据实测数据再做调整。
2. **源站 IP 保护（分三层，成本由低到高）**。隐藏 IP 是主要防线，但 IP 可能通过以下途径泄露：全网 443 端口扫描时源站返回的证书、历史 DNS 记录、同一台机器上未开代理的其他子域名、服务器发出的邮件头。
   - **第一层，必做**：反代默认站点拒绝未知域名。nginx 使用 `listen 443 ssl default_server; ssl_reject_handshake on;`（需 nginx ≥ 1.19.4），80 端口默认站点 `return 444;`；Caddy 使用等效配置。目的是让扫描器按 IP 访问时拿不到任何证书，无法反查出域名。注意：这一层只能**防止 IP 被发现**，挡不住已经知道 IP 的攻击者，因为对方可以伪造 Host/SNI，而 SYN 洪泛等 L3/L4 攻击根本到不了 nginx。
   - **第二层，必做**：SSL 模式设为 Full (strict)，并使用 Cloudflare Origin Certificate；检查 `ly2u.com` 各子域名，凡指向本机且未开代理的记录都要处理掉。
   - **第三层，有条件时做**：源站防火墙的 80/443 端口只放行 Cloudflare IP 段。**前提是本机所有对外 443 站点都走 Cloudflare**，因为防火墙无法按域名区分流量。如果本机还有不走代理的站点，这一层就做不了，只能依靠前两层，并在汇报中注明。
   - **站长决定（2026-10-23）**：本机存在不走 Cloudflare 的服务，V0.1 **不实施第三层**，依靠第一、二层。若日后遭到针对源站的攻击，应急方案是更换 VPS IP，或把本站迁到单独 IP 并补上第三层。
3. **缓存策略（防止用户拿到旧数据）**：源站必须对每类路径显式输出 `Cache-Control`，Cloudflare 缓存规则设为"遵循源站"。不要依赖 Cloudflare 的默认行为：它会按扩展名自动缓存 `.zst`、`.gz`、`.zip` 等文件。

   | 路径 | 是否会变 | 源站 `Cache-Control` | 最大陈旧时间 |
   |---|---|---|---|
   | `/bundles/<发行版>.<哈希>.json.zst` 及签名 | 永不变（内容变化即换新文件名） | `public, max-age=31536000, immutable` | 0，不存在陈旧问题 |
   | `/bundles/manifest.json`（唯一可变的入口） | 每次发布都会变 | `public, max-age=60, must-revalidate`，并带 `ETag` | ≤ 60 秒 |
   | `/api/*` | 随数据变化 | `public, max-age=60`；`/api/v1/health` 用 `no-store` | ≤ 60 秒 |
   | `/cve/*` 等页面 | 偶尔变化 | `public, max-age=300` | ≤ 5 分钟 |
   | `/rss.xml` | 随事件变化 | `public, max-age=300` | ≤ 5 分钟 |

   - worker 发布新数据包时的顺序：**先上传新的哈希文件，再更新 manifest**。这样任何时刻 manifest 指向的文件都一定存在。旧哈希文件保留 7 天后再清理，避免正在下载的用户读取失败。
   - 扫描器请求 manifest 时带上 `If-None-Match`。数据没变时返回 304，几乎不消耗流量。
   - `/api/*` 另外配置 Cloudflare 限速规则。
   - 可选：发布后调用 Cloudflare API 清除 manifest 的缓存，把陈旧时间压到接近 0。这需要 API 令牌，V0.1 不做；60 秒的陈旧时间对每小时更新一次的数据来说可以忽略。
4. **数据库与 worker 不暴露任何端口**。

---

## D7. 开发与生产隔离（Codex 运行在生产 VPS 上）

- 开发目录：`/opt/secwatch-dev`
- Compose 项目名：`secwatch-dev`
- 端口只绑定 `127.0.0.1:18xxx`
- **不得**修改、停止或重建任何已有的容器、网络、数据卷、反代配置、防火墙规则
- 涉及以上任何一项的操作，先写出计划和回滚步骤，等待确认后再执行
- GitHub 推送使用**仅授权 `ly2u/sec` 一个仓库**的 fine-grained PAT 或 deploy key，不使用账户全权限 token
- 全量导入前先检查磁盘余量，并且必须先用 `--limit 1000` 跑通一遍

---

## V0.1 验收：可演示的端到端

1. **回移植测试**：在 Debian 12 和 Ubuntu 24.04 容器中运行 `secwatch scan`，输出中文报告。至少包含一个真实的回移植用例被正确判为 `FIXED`。用例从 Debian Security Tracker 中选取，并固化为测试夹具。
2. **宝塔场景**：在模拟的 `/www/server/nginx` 环境中，识别出非包管理安装的 nginx 及其版本。
3. **生效状态**：构造"库已升级、进程未重启"的场景，L3 能正确报出。
4. **站点**：`sec.ly2u.com` 首页显示最近 7 天的 KEV 新增和 P0/P1 事件；任意历史 CVE 都能打开详情页；RSS 可正常订阅。
5. **数据包**：每小时自动更新；签名可校验；篡改后扫描器拒绝使用。

## 分工

| 角色 | 负责 |
|---|---|
| **Claude** | 架构决策、数据包与判定规范、测试用例清单、关键代码审查 |
| **Codex（VPS）** | 实现、本机环境探测、运行测试、部署 |
| **站长（你）** | 建仓库、DNS 和 Cloudflare 设置、确认所有生产操作 |
