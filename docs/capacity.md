# 容量实测

## 阶段 2：OSV 与签名数据包

测量时间：2026-10-23 06:17–07:05 UTC。PostgreSQL 17.11，迁移 `0003`。先对每个生态导入 1000 条样本，再从同一固定 generation 续传到 EOF；以下不是样本外推。

| OSV 基础生态 | 完整记录数 | 全量续传耗时 | 目标发行版受影响包行数 |
| --- | ---: | ---: | ---: |
| Debian | 72,020 | 169 秒 | 121,848 |
| Ubuntu | 71,490 | 1,479 秒 | 2,201,602 |
| Alpine | 4,774 | 16 秒 | 10,072 |
| Rocky Linux | 4,532 | 17 秒 | 14,464 |
| AlmaLinux | 6,206 | 51 秒 | 68,214 |

Ubuntu 的公告记录会展开为大量“源码包 × 发行版/渠道”事实，因此公告数和 `affected_packages` 行数不能直接比较。五个基线均为 `completed=true`；紧接其后的首轮 `modified_id.csv` 增量均处理 0 条并成功完成。

| 数据库项目 | 实测值 |
| --- | ---: |
| 数据库总大小 | 6,523,500,211 字节（6.08 GiB） |
| `vulnerabilities` | 423,284 行 |
| `osv_advisories` | 159,022 行 |
| `affected_packages` | 2,416,200 行 |
| `vulnerability_events` | 651,819 行；全部为基线事件 |
| CVE `raw_record` 存储值 / 逻辑文本 | 887,850,978 / 1,638,316,583 字节 |
| OSV `raw_record` 存储值 / 逻辑文本 | 1,907,809,316 / 8,840,198,444 字节 |

阶段 2 前五大表（`pg_total_relation_size`）：

| 表 | 表及 TOAST | 索引 | 总大小 |
| --- | ---: | ---: | ---: |
| `affected_packages` | 1,739.61 MiB | 512.70 MiB | 2,252.31 MiB |
| `osv_advisories` | 1,935.51 MiB | 9.96 MiB | 1,945.47 MiB |
| `vulnerabilities` | 1,512.59 MiB | 42.33 MiB | 1,554.92 MiB |
| `vulnerability_events` | 242.87 MiB | 141.18 MiB | 384.05 MiB |
| `epss_scores` | 28.84 MiB | 17.18 MiB | 46.02 MiB |

阶段 2 前五大索引：

| 索引 | 大小 |
| --- | ---: |
| `uq_affected_source_entry` | 403.75 MiB |
| `vulnerability_events_dedup_key_key` | 78.06 MiB |
| `affected_packages_pkey` | 51.77 MiB |
| `ix_affected_packages_advisory_id` | 23.82 MiB |
| `vulnerabilities_pkey` | 21.31 MiB |

13 个数据包首次生成耗时 222 秒。初版内存聚合实现触及 2 GiB 上限并退出 137；改成流式 JSON 和流式 zstd 后，成功生成时人工点测 worker 约 110 MiB。整个阶段的 15 秒监控同时包含失败尝试，观测到 worker job 最高 1,634.30 MiB、PostgreSQL 最高 2,643.97 MiB。线上 sites/civilflow 和 SecWatch 健康接口的采样异常数为 0，最低可用磁盘 167.54 GiB。

## 阶段 1.1：CVE / KEV / EPSS 全量

测量时间：2026-10-23T04:36:27.743178+00:00。PostgreSQL 17.11，迁移 `0002`。以下数据来自实际开发数据库，不是样本线性外推。阶段 1 的样本测量为 14,751,411 字节（14.07 MiB）；本次按 KEV → EPSS → CVE 的顺序导入至 EOF。

## 导入结果

| 数据源 | 完整快照记录数 | 本轮新处理数 | 命令耗时 |
| --- | ---: | ---: | ---: |
| KEV | 1,754 | 754 | 2.68 秒 |
| EPSS | 394,415 | 393,415 | 154.00 秒 |
| CVE 基线 | 413,350 | 413,350（重放并补齐旧样本） | 445.52 秒 |

KEV、EPSS 从阶段 1 已提交的 1000 条继续，耗时不包含早前样本导入；均使用 `--all`，没有 `--limit`。CVE 使用 `--restart --all` 从头重放以补齐新增的 CVSS 字段，中断后用 `--all` 恢复。CVE 耗时是两段命令时间之和，包含重新下载、重读已提交前缀的时间。

- KEV revision：`2026.10.21`；活跃 1,754，历史撤回 0。
- EPSS 日期：`2026-10-22`；模型：`v2026.06.15`。
- CVE 固定 URL：https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-10-23_0300Z/2026-10-23_all_CVEs_at_midnight.zip.zip
- CVE revision：`sha256:2ff9cbf82ff965a12a7290fb8a7938dd8a5d34c51667c78c99b281106a5b31fc`。
- 三个全量采集流均为 `completed=true`、`has_completed=true`、`last_error=null`。

## 断点续传

手动执行 `docker compose --env-file .env -f deploy/compose.yaml stop worker`；停止后数据库保存 offset **59,600**、`completed=false`。原采集进程以 137 退出是这次人为中断的预期结果。随后执行 `start worker` 和 `python -m collector.cli cve-baseline --all`，不加 `--restart`。

恢复后抽查 offset **75,200**，最终 **413,350**，原 URL/revision 始终一致。最终不同 raw_record 记录数为基线 offset 加 1（保留阶段 1 较新增量 `CVE-2026-115638`，其发布时间晚于固定基线发布），主键无重复。该增量用保存的原文回填新增 CVSS 字段，没有用较旧基线覆盖。续传命令成功读到 EOF。CVE 从首次启动到最终完成的墙钟时间为 453.52 秒，其中命令运行合计 445.52 秒。

恢复为记录级续传：重新打开固定 ZIP，解析并跳过已提交前缀；不是压缩文件的字节范围续传。每 100 条将数据与游标在同一事务提交。

## 数据库与 raw_record

| 项目 | 实测值 |
| --- | ---: |
| 数据库总大小 | 1,689,114,291 字节（1,610.86 MiB） |
| 漏洞主表行数 | 413,351 |
| PUBLISHED | 394,721 |
| REJECTED | 18,630 |
| raw_record 非空行数 | 413,351 |
| raw_record 存储值字节数之和 | 887,753,184 字节（846.63 MiB） |
| raw_record JSON 文本逻辑大小 | 1,638,189,643 字节（1,562.30 MiB） |

数据库总大小用 `pg_database_size(current_database())`，包含系统目录、索引和空闲页。raw_record 存储值用 `sum(pg_column_size(raw_record))`，反映 PostgreSQL 存储值（含压缩），不包含行头、TOAST 分块/页和索引开销；逻辑大小用 `sum(octet_length(raw_record::text))`，两者不能混用。多个大字段可能共用漏洞表的 TOAST 存储，不能将整张 TOAST 表都归为 raw_record。

## 前 5 大的表

按 `pg_total_relation_size` 降序；表大小 `pg_table_size` 包含 TOAST，索引大小为 `pg_indexes_size`。

| 表 | 表及 TOAST | 索引 | 总大小 |
| --- | ---: | ---: | ---: |
| `vulnerabilities` | 1,512.09 MiB | 41.83 MiB | 1,553.91 MiB |
| `epss_scores` | 28.84 MiB | 17.18 MiB | 46.02 MiB |
| `kev_entries` | 1.66 MiB | 0.17 MiB | 1.84 MiB |
| `vulnerability_events` | 0.61 MiB | 0.48 MiB | 1.09 MiB |
| `affected_packages` | 0.01 MiB | 0.02 MiB | 0.03 MiB |

## 前 5 大的索引

范围为 public 业务表的独立索引，用 `pg_relation_size(indexrelid)` 排序；TOAST 内部索引不在此表中重复列出。

| 索引 | 所属表 | 大小 |
| --- | --- | ---: |
| `ix_vulnerabilities_status_modified` | `vulnerabilities` | 20.93 MiB |
| `vulnerabilities_pkey` | `vulnerabilities` | 20.88 MiB |
| `epss_scores_pkey` | `epss_scores` | 14.73 MiB |
| `ix_epss_scores_score_date` | `epss_scores` | 2.45 MiB |
| `vulnerability_events_dedup_key_key` | `vulnerability_events` | 0.20 MiB |

## 事件与资源

基线事件 **1,755**，非基线事件 **0**。首次完整 KEV 后非基线事件为 0；“第二轮增加一条只生成一个非基线事件”由 SQLite 和 PostgreSQL 回归测试分别验证，没有往开发数据库注入伪造 KEV。

| 来源 | 类型 | 基线 | 非基线 |
| --- | --- | ---: | ---: |
| cvelistV5 | severity_changed | 1 | 0 |
| kev | added_to_kev | 1,754 | 0 |

| 容器 | 内存上限 | CPU 上限 | 采样最高内存 | 采样最高 CPU |
| --- | ---: | ---: | ---: | ---: |
| postgres | 4 GiB | 2 | 1,167.36 MiB | 89.14% |
| worker | 2 GiB | 1.5 | 122.70 MiB | 82.87% |
| web | 1 GiB | 1 | 63.56 MiB | 30.25% |

使用 `docker stats --no-stream` 约每 15 秒采样，共 43 个定时样本，并辅以手工点测；以上为观测到的最大值，不是连续采样的绝对峰值。导入前已检查磁盘余量，导入中持续记录可用磁盘。线上服务和开发健康接口的 HTTP 采样异常数为 0；受保护线上容器 ID、StartedAt、RestartCount 和配置哈希前后一致。原始主机测量、采集日志和数据库备份只保留在本地忽略目录，未提交公开仓库。

PostgreSQL 仅加入 `internal: true` 的 db 网络，`shared_buffers=1GB`；worker/web 加入 db 和 private。未接入线上反代或生产网络。

测量口径参考 [PostgreSQL 数据库对象大小函数](https://www.postgresql.org/docs/17/functions-admin.html#FUNCTIONS-ADMIN-DBOBJECT) 与 [TOAST 存储](https://www.postgresql.org/docs/17/storage-toast.html)。
