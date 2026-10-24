# secwatch 扫描器

只读的 Linux 漏洞自检工具。Go 静态编译单文件，无运行时依赖。

> 状态：开发中（V0.1）。尚未发布正式版本，官方数据源 `sec.ly2u.com` 尚未上线。

## 它做什么

| 层 | 内容 |
|---|---|
| L1 发行版包 | 读取 dpkg / rpm / apk 包数据库，按发行版安全数据（含回移植修复）判定，使用各包管理器原生的版本比较算法 |
| L3 补丁是否生效 | 只判断**正在运行**的内核；发现"已安装修复内核但未重启"；发现仍在使用升级前旧库的服务 |
| L4 暴露面 | 对外监听的进程加载了哪些软件包，用于提高优先级 |
| 优先级 | CISA KEV（在野利用）、FIRST EPSS、CVSS 与是否对外暴露，见 `docs/ARCHITECTURE.md` D4 |

L2（宝塔、源码编译、nvm 等非包管理安装的上游版本检测）尚未实现。来自第三方软件源（nginx.org、Docker、NodeSource、sury 等）的软件包目前会单独列出，结论为"未知"，不会套用发行版数据误判。

## 信任模型

- **只读**：不修改系统、不执行修复命令，只打印建议命令。
- **不上传**：所有比对都在本机完成。服务器只提供签名的数据包。
- **数据包必须验签**：使用编译进二进制的 minisign 公钥校验。签名绑定文件名与密钥 ID，数据包内的发行版与版本必须与本机一致。校验失败直接中止，不输出任何结论。
- **数据包只含事实**：修复命令由扫描器按模板生成，包名必须通过白名单正则校验，不合规的包名不会进入命令。
- **外部程序**：只在 RPM 系统上以固定参数调用 `/usr/bin/rpm`（不经过 shell，带超时）。`--no-exec` 可完全禁止外部程序调用。
- **缓存**：默认在 `~/.cache/secwatch` 缓存最近一次验签通过的数据包，以便离线使用和节省流量。`--no-cache` 可关闭缓存。

## 用法

```
secwatch scan                       # 一屏摘要：结论、表格、修复命令（建议以 root 运行）
secwatch scan --format json         # 机器可读输出
secwatch scan --pkg openssh         # 只看一个软件包：全部漏洞、升级与验证命令
secwatch scan --all                 # 完整报告（全部结果、每个软件包的命令与参考链接）
secwatch scan --container db        # 只看一个容器（以 root 运行时默认检查运行中的容器）
secwatch scan --fail-on P2          # 定时任务：P2 及以上就返回退出码 3
secwatch scan --pkg caddy           # Go 编译的程序也能单独查看（模块、Go 版本对应的漏洞）
secwatch scan --offline --bundle debian-12.<hash>.json.zst   # 离线
```

退出码：`0` 无紧急问题 · `3` 存在 P0/P1 问题 · `1` 扫描失败 · `2` 参数错误。可直接用于定时任务和监控告警。

支持：Debian 11–13、Ubuntu 20.04/22.04/24.04、Rocky Linux 8/9、AlmaLinux 8/9、Alpine 3.22–3.24。

## 判定状态

| 状态 | 含义 |
|---|---|
| `CONFIRMED_AFFECTED` | 软件包来自官方源，版本落在发行版公布的受影响范围内 |
| `POTENTIALLY_AFFECTED` | 版本受影响，但无法核实软件包来源（例如 apt 索引已被清理） |
| `UNKNOWN` | 版本无法解析，无法判定 |
| 第三方软件包 | 发行版数据不适用，单独列出 |

已修复的问题只计数，不逐条列出。

## 开发

```
cd scanner
go test ./...                                    # 单元测试与端到端测试
CGO_ENABLED=0 go build -trimpath -o secwatch ./cmd/secwatch
testdata/integration/run.sh ./secwatch ./mkbundle   # 真实发行版容器测试（需要 docker 与 minisign）
```

`internal/tools/mkbundle` 用一次性密钥生成签名测试数据包，仅用于测试，不随版本发布。
