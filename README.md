# 飞行数据链路规则隔离审计

上线隔离规则前，按**优先级顺序**逐条核对报文规则是否被更早规则完全遮蔽，避免看似生效的允许/阻断项从未匹配任何流量。

## 核心语义

- 每条规则是五维空间 **协议 × 源 IPv4 × 目的 IPv4 × 源端口 × 目的端口** 中的一个轴对齐**闭区间盒**（协议轴：TCP=0、UDP=1，"两者"=[0,1]；地址为 uint32；端口 0–65535）。
- 服务将先前规则的并集维护为**不相交盒列表**，对当前规则做**精确盒差集**得到剩余区域——不抽样地址、不枚举端口、不以 CIDR 字符串重叠替代判定。
- 裁决：
  - `hit`（仍可命中）：返回按 **协议 → 源地址 → 目的地址 → 源端口 → 目的端口** 字典序的**最小报文见证**（TCP 排在 UDP 前）。
  - `shadowed`（完全遮蔽）：返回 `covered_by` —— 所有与该规则区域相交的更早规则标识（按优先级升序），其并集完全覆盖该规则。
- 结论一经提交即**冻结**：同一审计标识重放相同载荷返回既有结论（HTTP 200，幂等）；**同标识不同载荷**返回 HTTP 409 且不改写既有结论。
- 校验拒绝（HTTP 422，且不留痕）：非法 IPv4 CIDR（含主机位非 0、非法前缀、IPv6）、端口区间越界或下界大于上界、规则标识重复、规则数 0 或超过 18、非法审计标识。

## 发布顺序复核

对已冻结的审计可提交**复核**：给定稳定复核标识与至多 6 组「规则甲必须早于规则乙」的发布约束，判定是否**任意**满足约束的发布顺序都能让每条规则保有首先命中的报文。

- 求解枚举约束允许的**优先级前缀状态**（约束偏序的前缀闭集），以协议 × 源 IPv4 × 目的 IPv4 × 源端口 × 目的端口的精确区域维护前缀并集；一旦某候选规则被此前区域完全覆盖，即构造**按规则标识稳定**的完整反例顺序与覆盖依据（所有与被遮蔽规则区域相交的更早规则，按顺序列出）。不以 CIDR 字符串交叠、端口抽样或随机排列替代精确判定。
- 结论：`robust`（稳健——所有合法顺序均安全）或 `not_robust`（不稳健——返回 `counterexample`：导致遮蔽的完整发布顺序 `order`、被遮蔽规则 `shadowed_rule`、覆盖它的更早规则 `covered_by`）。
- 复核同样**冻结**来源规则与约束：同标识同载荷重放返回原结论（HTTP 200）；**同标识改换来源或约束**返回 HTTP 409 且不改写既有结论。
- 拒绝（且不留痕）：来源审计不存在（HTTP 404）；约束引用未知规则、两端为同一规则、重复约束、约束成环、约束超过 6 组（HTTP 422）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康端点，返回 `{"status":"ok"}` |
| POST | `/api/audits` | 提交审计；201 创建 / 200 幂等重放 / 409 标识冲突 / 422 校验失败 |
| GET | `/api/audits/{audit_id}` | 按审计标识复查冻结结论；404 不存在 |
| POST | `/api/reviews` | 提交发布顺序复核；201 创建 / 200 幂等重放 / 404 来源不存在 / 409 标识冲突 / 422 约束非法 |
| GET | `/api/reviews/{review_id}` | 按复核标识重开冻结结论；404 不存在 |
| GET | `/` | 录入与复查页面 |

请求体示例：

```json
{
  "audit_id": "audit-2026-09-29",
  "rules": [
    {"id": "r1", "protocol": "tcp",
     "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
     "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 85}}
  ]
}
```

`protocol` 取值 `tcp` / `udp` / `both`；端口为闭区间；规则至多 18 条，顺序即优先级。

响应体：`{"audit_id", "created_at", "rules": [...], "verdicts": [...]}`，其中 `verdicts[i]` 对应 `rules[i]`：

```json
{"rule_id": "r2", "status": "hit",
 "witness": {"protocol": "tcp", "src_ip": "10.0.0.128", "dst_ip": "192.168.0.0",
             "src_port": 0, "dst_port": 86}}
```
```json
{"rule_id": "r3", "status": "shadowed", "covered_by": ["r1"]}
```

复核请求体示例：

```json
{
  "review_id": "review-2026-09-29",
  "audit_id": "audit-2026-09-29",
  "constraints": [{"before": "r3", "after": "r1"}]
}
```

复核响应体：`{"review_id", "audit_id", "created_at", "constraints", "rules", "status", "states_explored", "counterexample"}`，其中 `rules` 为冻结的来源规则快照，`status` 为 `robust` 或 `not_robust`；不稳健时 `counterexample` 形如：

```json
{"order": ["r1", "r3", "r2"], "shadowed_rule": "r3", "covered_by": ["r1"]}
```

## 运行（Docker）

```bash
docker compose up --build app          # 默认映射宿主机 8080
HOST_PORT=9000 docker compose up --build app   # 配置宿主机访问端口
docker compose ps                      # app 健康检查基于 /healthz
```

打开 `http://localhost:8080/`（或所配端口）录入审计标识与规则、提交并查看逐规则裁决与见证，也可按审计标识复查冻结结论；对已冻结的审计可进一步提交发布顺序复核（至多 6 组「必须早于」约束），查看稳健结论或反例顺序，并按复核标识重开。

## 验证（verify 服务）

`verify` 服务在 `app` 健康后执行：**构建检查**（compileall）→ **代码测试**（pytest：区域代数精确性、引擎裁决、复核求解器、API 生命周期与拒绝路径）→ **HTTP 冒烟**（一条部分遮蔽、一条完全遮蔽、同标识不同载荷的非法重传、非法 CIDR、幂等重放与冻结复查；复核的稳健结论、反例顺序、约束成环拒绝与来源审计回归），并以退出码报告结果：

```bash
docker compose up --build --exit-code-from verify verify
echo $?    # 0 = 全部通过
docker compose down
```

## 本地开发

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q                              # 代码测试
uvicorn app.main:app --port 8080       # 起服务
APP_URL=http://127.0.0.1:8080 python -m verify.run   # 完整验证门禁
```

## 说明与限制

- 审计结论保存在服务内存中，进程重启后清空；冻结语义（同标识拒绝改写）在进程生命周期内严格成立。
- 差集运算对典型 CIDR/端口规则开销可忽略；理论上 18 条规则的病态碎裂场景会增大计算量，但结果始终精确。
