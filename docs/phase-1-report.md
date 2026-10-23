# 阶段 1 交付报告

## 已完成

- 从 SSH 地址完整 clone，确认以 `c2aa3b3` 为起点；推送前又同步了远端 `4fc100e` 的最新架构约束。工作副本统一为 `/opt/secwatch-dev`。迁移私有报告并检查忽略规则后，已删除临时副本。
- 建立 `apps/server`、`collector/adapters`、Go 模块占位、产品规则占位、Alembic、开发部署、测试及 CI 骨架。
- 建立七张情报业务表及 `0001` 迁移。真实 PostgreSQL 导出结构见 [database-schema.sql](database-schema.sql)，不是未执行的设计草图。
- 实现流式 CVE 基线、官方 delta、KEV 和 EPSS 采集，具备幂等 upsert、事务检查点、有限重试、CISA ADP 提取、REJECTED 墓碑、RESERVED 隐藏及事件去重。
- 开发 web/worker 共用当前镜像，另保留 previous；仅 web 发布环回端口，三个容器均设内存和 CPU 上限。没有创建 `secwatch-edge`，没有加入 `ly-stack_default`。
- 遵守最新的无 JS／无外部资源约束：关闭框架默认 Swagger/Redoc 页面，保留 `/openapi.json`；没有创建前端构建链或关键词全文搜索。
- SSH agent 在仓库 clone 时可用；未生成或保存任何 GitHub 密钥，未把 agent socket 暴露给容器。实际推送状态以本次会话最终汇报为准。

## 实际验证

| 验证 | 结果 |
| --- | --- |
| `.venv/bin/ruff check .` | 通过 |
| `.venv/bin/ruff format --check .` | 通过 |
| `.venv/bin/pytest -q` | SQLite：29 passed |
| `docker compose --env-file .env -f deploy/compose.yaml exec -T -e SECWATCH_TEST_POSTGRES=1 worker pytest -q -p no:cacheprovider` | PostgreSQL：29 passed |
| `alembic upgrade head`、`alembic check` | 已实际建表；无模型与迁移差异 |
| 三个源分别 `--limit 1000` | CVE 基线、KEV、EPSS 各 1000 条 |
| 同样三个源分别 `--restart --limit 1000` | 重放后记录数和事件数不增加 |
| `cve-delta --since 2026-10-23T03:30:00Z --limit 1000` | 实际处理 1 条官方增量 |
| `GET /api/v1/health` | HTTP 200，`Cache-Control: no-store` |
| Docker inspect | 实际内存、CPU、网络、端口均符合 Compose |
| 生产隔离 | 原有容器 ID、启动时间、重启次数及两个生产配置文件哈希均未变化 |

初次容器测试曾发现测试镜像未携带 Compose 文件，已修复并重建；最终 SQLite 和 PostgreSQL 测试均通过。测试依赖的 Starlette TestClient 发出 1 条 httpx 兼容性弃用警告，不影响测试通过。

| 容器 | 实际内存上限 | 实际 CPU 上限 | 对外端口 |
| --- | --- | --- | --- |
| postgres | 4 GiB | 2.0 | 无 |
| worker | 2 GiB | 1.5 | 无 |
| web | 1 GiB | 1.0 | 仅 `127.0.0.1:18080` |

数据库实测样本为 3001 个编号：978 个 PUBLISHED、23 个 REJECTED、2000 个仅由 KEV/EPSS 建立的 UNKNOWN 占位；1000 个 KEV 条目、1000 个 EPSS 分数、1000 个 `added_to_kev` 事件。CVE 基线和两种评分/目录源的 `completed` 均为 false，明确表示不是全量数据。

## 实际生成的表结构

| 表 | 主键／约束 | 主要字段 |
| --- | --- | --- |
| vulnerabilities | `id`；状态和 CVSS 范围约束 | 状态、标题、描述、发布时间、修改时间、CVSS、severity、CWE JSONB、SSVC JSONB、CISA ADP JSONB、KEV 标记、来源、内容哈希、原始记录 JSONB |
| vulnerability_aliases | `(vulnerability_id, alias)`；外键 | 别名、来源；alias 索引 |
| affected_packages | `id`；`(vulnerability_id, source, entry_hash)` 唯一；外键和状态约束 | 生态、发行版、版本、包名、源码包、范围 JSONB、状态、修复版本、来源及哈希 |
| kev_entries | `vulnerability_id` 外键主键 | 加入日期、期限、厂商、产品、名称、说明、行动建议、勒索利用标记、目录版本、哈希 |
| epss_scores | `vulnerability_id` 外键主键；分数范围约束 | 评分日期、EPSS 与 percentile `NUMERIC(10,9)`、模型版本 |
| vulnerability_events | `id`；`dedup_key` 唯一；外键 | 事件类型、来源、发生／观察时间、优先级、payload JSONB |
| ingestion_state | `source` | 快照版本、检查点 JSONB、累计处理数、完成标记、成功时间及最近错误 |
| alembic_version | `version_num` | 当前迁移为 `0001` |

`affected_packages` 和 `vulnerability_aliases` 已实际创建，本阶段尚无 OSV 导入，暂没有对应数据。

## 未完成或已知缺陷

- 遵守本次指令，只验证小样本；没有完整导入 KEV、EPSS 或历史 CVE，不宣称达到原说明中全量入库的验收项。
- ZIP 为记录级恢复，会重新读取此前压缩字节；没有实现 ZIP 字节范围续传。
- worker 当前等待显式命令，每小时调度和进程锁属于阶段 2；不存在自动全量采集任务。
- 扫描器、产品规则、OSV、数据包签名、完整网页和生产接入尚未实施。
- 未测试全量导入的容量或峰值。数据库容量仅为本次小样本实测，见 [capacity.md](capacity.md)。

## 需要站长确认的事项

确认本阶段的小样本验收结果；进入阶段 2 前另行确认，不扩大导入规模、不接入生产反代。

## 下一步计划

按要求在阶段 1 完成后停下。获得下一阶段确认后，再实现 OSV、签名数据包、增量调度和相应核对测试。
