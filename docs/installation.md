# 阶段 2 开发环境

本阶段提供数据底座、采集 CLI、常驻调度器、签名数据包和数据库健康接口；尚未提供漏洞站点或扫描器。工作目录固定为 `/opt/secwatch-dev`。

## 启动

需要 Docker Engine 和 Compose。复制 `.env.example` 为 `.env`，将 `POSTGRES_PASSWORD` 替换为随机密码，文件权限设为 `0600`；不得提交 `.env`。SSH agent 只用于宿主机 Git 操作，不传入容器。

```bash
cd /opt/secwatch-dev
docker compose --env-file .env -f deploy/compose.yaml config --quiet
docker compose --env-file .env -f deploy/compose.yaml build web
docker compose --env-file .env -f deploy/compose.yaml up -d --no-build
docker compose --env-file .env -f deploy/compose.yaml exec -T worker alembic upgrade head
curl --fail http://127.0.0.1:18080/api/v1/health
```

web/worker 共用 `secwatch-dev:current`，以 UID 10001 运行，根文件系统只读。PostgreSQL 使用项目独有的数据卷。只有 web 发布 `127.0.0.1:18080`，数据库和 worker 不映射宿主机端口。

OpenAPI 文档通过 `/openapi.json` 提供。按最新架构的无 JS／无外部资源要求，不启用默认 Swagger UI 或 Redoc 页面。

postgres 只加入 `internal: true` 的项目网络 `secwatch-dev_db`，不直接访问外网。worker 和 web 同时加入 `db`、`private`；`private` 允许采集器访问公开情报源。三个服务均未加入 `ly-stack_default`。开发阶段不创建 `secwatch-edge`，不改 Caddy。生产环境使用独立的 `deploy/compose.prod.yaml`（见 `docs/DEPLOY.md`），只有 web 加入外部的内部网络 `secwatch-edge`，别名为 `secwatch-web`。PostgreSQL 使用 `shared_buffers=1GB`。

| 服务 | mem_limit | cpus | memswap_limit |
| --- | --- | --- | --- |
| postgres | 4g（4 GiB） | 2.0 | 4g |
| worker | 2g（2 GiB） | 1.5 | 2g |
| web | 1g（1 GiB） | 1.0 | 1g |

## 常驻 worker 与有上限的手工采集

worker 默认运行 PostgreSQL advisory lock 保护的常驻调度器。KEV、`cve:delta`、OSV 每小时一次，EPSS 每日一次，首次启动分别错开 2 分钟；每轮结果写入 `task_runs`。手工采集默认上限仍为 1000，`--limit` 必须为正数；全量必须显式使用 `--all`。

```bash
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli cve-baseline --limit 1000
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli kev --limit 1000
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli epss --limit 1000
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli osv-baseline --ecosystem Debian --limit 1000
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli status
```

- CVE 基线从官方 Releases 元数据发现 ZIP，使用 `stream-unzip` 流式处理普通或嵌套 ZIP，不落盘解压。到达上限即关闭下载；不先下载完整基线。
- 数据和记录偏移在同一事务中每 100 条提交。重跑相同命令会从已提交的记录偏移继续，因此下一次会处理后续记录。使用 `--restart --limit 1000` 可重放同一快照的前 1000 条，验证幂等性。
- 断点恢复是记录级：网络中断时重新打开固定快照，重读并跳过已提交的记录，不是压缩 ZIP 的字节范围续传。失败批次整体回滚；已经提交的批次保留。
- CVE 基线锁定 URL 和 revision，未完成时继续读取固定快照；显式切换快照仍需 `--restart`。KEV、EPSS 无法锁定历史 URL，未完成时若 revision 改变，会记录警告并自动从零重启，避免混用快照。
- 增量使用官方 `cves/deltaLog.json`。第一次调用 `cve-delta` 必须显式给出 `--since <ISO UTC 时间>`，以后使用持久化水位。超过滚动日志覆盖窗口时明确报错，要求重建基线，不静默漏采。
- EPSS 每次依据 FIRST 官方文档发现日更 CSV 地址，支持 `--url` 显式覆盖受允许的公开来源。保留评分日期和模型版本；旧日期不能覆盖新分数。仅在完整日快照处理完成后清理旧日期分数。
- 429 和常见 5xx 最多重试 4 次，指数退避，遵守有上限的 `Retry-After`；每次重定向重新验证 HTTPS 和来源主机。
- 仅 KEV/EPSS 出现的编号先建立 `UNKNOWN` 占位，不能假冒已公开 CVE。CVE 查询作用域只返回 `PUBLISHED`；REJECTED 保留拒绝原因，RESERVED 不进入公开结果。
- 每个采集流首次完整导入前生成的事件全部为 `is_baseline=true`。`has_completed` 独立记录是否曾完成过导入，后续轮次中断或自动重启不会丢失这段历史。首页/RSS 共用 `visible_events()`，Telegram 共用 `telegram_events()`，均排除基线事件；实际页面和发送任务仍属于阶段 4。
- 官方 KEV 身份只根据 JOIN `kev_entries` 且 `is_active=true` 判断，`adp_kev_flag` 仅保留 CISA ADP 原始事实。只有完整目录导入完成后，才将已撤回项标为非活跃、保留原记录并生成 P2 `removed_from_kev` 事件。
- CVSS 保留全部评分及来源，主评分优先 CNA 3.1、CISA-ADP 3.1、CNA 4.0、CISA-ADP 4.0、3.0、2.0；严重度从主评分数值推导。优先级阈值按架构 D4 使用 CVSS 3.x。
- 官方 delta 条目带有源端错误时，记录警告、继续处理其中可用的记录，并将条目保存在 `ingestion_state.cursor.warnings`，供后续核查。
- OSV 基线下载基础生态 ZIP，并按 `affected[].package.ecosystem` 拆分；增量使用时间倒序的 `modified_id.csv`。发行版范围只接受 `ECOSYSTEM`，原样保存 `introduced`、`fixed`、`last_affected`。
- 数据包私钥只存在宿主机 `secrets/bundle-signing.key`（`0600`，被 Git 忽略），仅以只读挂载给 worker；公钥在 `keys/bundle-signing.pub`。私钥必须另做离线备份，禁止经 Git 或聊天传输。
- worker 对独立 `bundles` 卷可写，web 只读。发布顺序是哈希 `.json.zst`、`.minisig`，最后原子替换 `manifest.json`；未引用的旧哈希文件保留 7 天。
- `manifest.json` 返回 `public, max-age=60, must-revalidate` 与 ETag；哈希文件和签名返回 `public, max-age=31536000, immutable`。

全量导入显式使用 `--all`，与 `--limit` 互斥；执行前检查磁盘和负载。按 KEV、EPSS、CVE 顺序运行：

```bash
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli kev --all
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli epss --all
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli cve-baseline --all
for ecosystem in Debian Ubuntu Alpine 'Rocky Linux' AlmaLinux; do
  docker compose --env-file .env -f deploy/compose.yaml exec -T worker \
    python -m collector.cli osv-baseline --ecosystem "$ecosystem" --all
done
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli bundles
```

## 测试与迁移检查

离线夹具取自真实公开数据，测试本身无需外网。测试清空的是专用 `secwatch_test` 数据库，绝不清空 `secwatch` 数据库。

```bash
# 宿主机开发虚拟环境中已安装 requirements.lock 和本项目时：
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pytest -q

# PostgreSQL 真实方言；首次执行时创建独立测试数据库：
docker compose --env-file .env -f deploy/compose.yaml exec -T postgres createdb -U secwatch secwatch_test
docker compose --env-file .env -f deploy/compose.yaml exec -T -e SECWATCH_TEST_POSTGRES=1 worker pytest -q -p no:cacheprovider
docker compose --env-file .env -f deploy/compose.yaml exec -T worker alembic check
```

迁移测试覆盖 upgrade、downgrade、再次 upgrade；数据测试覆盖重复导入、墓碑、RESERVED 隐藏、CISA ADP、旧 CVE 新进 KEV、重试、断点恢复、事务回滚、CSV 校验及过期水位。Compose 测试检查端口、内存、CPU 和网络配置。

## 镜像卫生与回退

开发应用只保留 `secwatch-dev:current` 和 `secwatch-dev:previous`，不为每次试验创建新标签。更新时保留上一版可运行镜像，验证新版本后才处理更旧版本；删除必须使用明确的 SecWatch 标签列表和非强制 `docker rmi`。不使用全局 image/system prune，也不清理 ly-stack 镜像。

若需回退，先停止采集并备份本项目数据库，使用 previous 镜像恢复本项目的 web/worker。应用回退不应自动降级数据库；破坏性迁移必须先评估并确认。停止开发环境只操作 `secwatch-dev` 项目，不删除数据卷，不修改任何 ly-stack 服务。

Git remote 使用 `git@github.com:ly2u/sec.git`。每次推送前执行 `ssh-add -l`，只使用站长转发的 agent；不可用时保留本地提交并汇报，不生成密钥、不改用其他凭据。
