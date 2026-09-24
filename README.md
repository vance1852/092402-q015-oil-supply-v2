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
- 审计证据包把一次分配运行、转运或情景结果连同其引用链固化为可离线复核、可验篡改的清单。

## 审计证据包

内审选定分配运行、转运或情景结果之一后，后台任务沿真实引用收集报价修订、设施与线路版本、停运记录、库存批次、操作决定和对应审计片段：

- 任务创建时在事务内记录各表高水位线与主键清单，任务启动后的新写入不会混入；
- 证据内容只取不可变列，用户资料按审计权限脱敏为跨包稳定的假名；
- 清单为规范化 JSON 并按条目键稳定排序，逐项与整包计算 SHA-256，同一根版本重复申请返回同一逻辑内容；
- 任务游标与条目持久化在 SQLite，进程中断后可从上次步骤续作；
- 验证时分别报告缺失引用、摘要不符与审计断链。

证据接口（仅 `auditor` 角色）：`POST /evidence/tasks` 申请、`GET /evidence/tasks/{id}` 查看状态、`POST /evidence/tasks/{id}/run` 执行、`GET /evidence/tasks/{id}/package` 导出、`POST /evidence/verify` 验证请求体中的证据包。

命令行同样覆盖申请、执行、导出与验证：

```bash
PYTHONPATH=src python3 -m oil_supply.evidence --database oil_supply.sqlite3 request --actor audit --root-type allocation --root-id 1
PYTHONPATH=src python3 -m oil_supply.evidence --database oil_supply.sqlite3 run
PYTHONPATH=src python3 -m oil_supply.evidence --database oil_supply.sqlite3 export --task evidence-XXXX > package.json
PYTHONPATH=src python3 -m oil_supply.evidence --database oil_supply.sqlite3 verify --package package.json
```

`verify` 在证据包有效时退出码为 `0`，发现缺失引用、摘要不符或审计断链时退出码为 `1` 并在输出中分别列出。

现场准入子域位于 `robot_trials` 包，负责油田巡检机器人的设备构建登记、不可变试验协议、观测分片导入、异常观测复核、统计任务租约、准入决定和审计报告。该子域不连接机器人硬件，只处理已经结构化的试验记录。

## 目录

- `src/oil_supply/`：报价、设施、线路、库存、提名、供应情景、审计证据包、HTTP API 与离线验收；
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

健康检查为 `GET /health`。除健康检查外，请求通过 `X-Actor-Id` 携带操作者编号。可用接口覆盖报价、设施、线路、停运事件、库存批次、提名、能力分配、发运、供应情景、审计链和审计证据包。服务重启后，SQLite 中的业务状态、历史版本和证据任务会继续保留。
