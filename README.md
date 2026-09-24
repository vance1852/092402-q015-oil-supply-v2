# 油气供应韧性与现场准入服务

本项目是一套可直接运行的 Python 服务端系统，用于记录原油基准报价、油田与终端设施、输送线路、库存批次、日提名和供应情景，并保留油田巡检机器人统计准入流程。系统面向价格连续波动、关键输油线路恢复、库存调拨和现场设备验证同时发生的运营环境，让调度、风险和审计人员在同一个 SQLite 数据库中获得可追溯结论。

供应调度子域提供以下能力：

- 原油基准报价按交易日和来源修订登记，历史版本不会被覆盖；
- 油田、储罐、终端与炼厂设施建档，线路保存日能力、在途时间和损耗规则；
- 线路停运或降容事件按 UTC 时间区间生效，日分配会计算实际可用能力；
- 库存批次保留油品、牌号、数量、单位成本和接收时间，可计算加权库存成本；
- 托运提名支持载荷级幂等、优先级分配、库存扣减和在途交接；
- 供应情景保存价格变化、线路能力变化和需求变化，审批后产生可重放的确定性结果；
- 关键写操作进入哈希串联审计日志，可离线验证事件顺序和内容完整性；
- 调度决定（分配运行、转运、情景结果）可一键生成**审计证据包**：沿真实引用收集报价修订链、设施与线路、停运记录、库存批次版本、提名与转运决定及对应审计片段，规范化 JSON 逐项与整包摘要，可离线复核并验出篡改。

现场准入子域位于 `robot_trials` 包，负责油田巡检机器人的设备构建登记、不可变试验协议、观测分片导入、异常观测复核、统计任务租约、准入决定和审计报告。该子域不连接机器人硬件，只处理已经结构化的试验记录。

## 目录

- `src/oil_supply/`：报价、设施、线路、库存、提名、供应情景、HTTP API 与离线验收；
- `src/robot_trials/`：油田巡检机器人试验与统计准入；
- `fixtures/`：现场准入演示协议和结构化观测；
- `tests/`：核心规则、错误边界、API 和端到端验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 无第三方运行依赖

在依赖已经准备好的容器中安装：

```bash
python3 -m pip install --no-index --no-deps .
```

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

测试使用内存数据库和临时目录，不访问公网，也不会启动常驻服务。

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m oil_supply.acceptance --workspace .
```

该命令会在内存数据库中登记六个交易日的布伦特报价，创建油田、终端和输送线路，完成库存入账、提名分配、发运及供应情景分析，最后输出一行 JSON。成功时退出码为 `0` 且 `status` 为 `ok`。

现场准入子域也保留独立验收入口：

```bash
PYTHONPATH=src python3 -m robot_trials.acceptance --workspace .
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m oil_supply.api --database oil_supply.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查为 `GET /health`。除健康检查外，请求通过 `X-Actor-Id` 携带操作者编号。可用接口覆盖报价、设施、线路、停运事件、库存批次、提名、能力分配、发运、供应情景和审计链。服务重启后，SQLite 中的业务状态和历史版本会继续保留。

## 审计证据包

内审需要的是可离线复核、能验出篡改的证据，而不是一串临时接口响应。审计员（`auditor` 角色）选定一个根对象后，后台任务沿数据库中的真实引用收集证据：

- 根对象三选一：分配运行（`allocation`）、转运（`transfer`）或情景结果（`scenario_run`）；
- 闭包内容：报价修订链（`supersedes_quote_id`）、设施与线路、停运记录、库存批次（含锚点可用数量重建）、提名、所属分配运行、同批次关联转运、情景定义与审批，以及每条记录对应的哈希链审计片段；
- **锚点围栏**：以根对象登记审计事件的 `event_id` 为截止点，任务启动之后（甚至同一秒内）的新写入绝不进入包，同一根版本重复申请得到同一整包摘要；
- **脱敏**：操作者只保留 `user_id` 与角色，`display_name` 不出包；
- **稳定序列化**：全部使用键排序、无空白的规范化 JSON，逐项 SHA-256 与整包 SHA-256 写入清单（manifest）；
- **可续作**：任务和条目状态在 `evidence_jobs` / `evidence_items` 中逐条提交，进程中断后再次执行即可从 SQLite 续作。

HTTP 接口（均需 `X-Actor-Id` 且为 auditor）：

- `POST /evidence/packages`：`{"root_kind":"allocation","allocation_id":1}`（transfer 用 `transfer_id`，情景用 `run_id`），返回 `202` 并在后台执行；
- `GET /evidence/jobs/<job_id>`：查询任务状态与清单；
- `POST /evidence/jobs/<job_id>/run`：同步续作/完成任务；
- `GET /evidence/jobs/<job_id>/package`：下载 `{manifest, package}` 证据束；
- `POST /evidence/verify`：请求体放证据束（`{"bundle": {...}}`），返回验证报告。

命令行：

```bash
# 生成证据束文件
PYTHONPATH=src python3 -m oil_supply.evidence build --database oil_supply.sqlite3 \
    --root transfer=trx --out evidence-trx.json

# 纯离线验证（不连库）；通过退出码 0，发现问题退出码 2
PYTHONPATH=src python3 -m oil_supply.evidence verify --file evidence-trx.json

# 同时与当前数据库的审计链和根对象交叉核验
PYTHONPATH=src python3 -m oil_supply.evidence verify --file evidence-trx.json --database oil_supply.sqlite3

# 中断后续作
PYTHONPATH=src python3 -m oil_supply.evidence run --database oil_supply.sqlite3 --job ev-transfer-trx
```

验证报告把问题归为三个**互相独立**的类别并分别计数：

- `missing_reference`：条目引用的记录或对应审计片段缺失（含被删除）；
- `digest_mismatch`：条目摘要或整包摘要与清单不符（内容被改动）；
- `audit_chain`：审计片段编号不连续、`previous_hash` 断链或事件重算摘要不符。

`valid` 为真当且仅当三类计数都为零。
