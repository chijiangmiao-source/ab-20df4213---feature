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

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康端点，返回 `{"status":"ok"}` |
| POST | `/api/audits` | 提交审计；201 创建 / 200 幂等重放 / 409 标识冲突 / 422 校验失败 |
| GET | `/api/audits/{audit_id}` | 按审计标识复查冻结结论；404 不存在 |
| POST | `/api/reviews` | 对来源审计提交发布顺序稳健性复核；201 创建 / 200 幂等重放 / 409 标识冲突 / 422 校验失败 |
| GET | `/api/reviews/{review_id}` | 按复核标识重开冻结复核（含来源快照）；404 不存在 |
| GET | `/` | 录入、复核与重开页面 |

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

## 发布顺序稳健性复核

安全工程师打开一份已冻结的审计（至多 18 条规则），给出稳定的**复核标识**和至多 6 组“规则甲必须早于规则乙”的发布约束，
确认**任意**满足约束的发布顺序是否都让每条规则保有首先命中的报文。

- 求解器**枚举约束允许的全部优先级前缀状态**（约束 DAG 的下闭集），对每个状态以协议、两个 IPv4 地址和两个端口的**精确不相交盒并集**
  维护已发布规则的覆盖区域；候选规则盒与此区域作精确差集。不做 CIDR 交叠判断、不抽样端口、不随机排列。
- 一旦某个可发布候选被此前区域完全覆盖，即构造**按规则标识字典序稳定的完整反例顺序**（贪心补全后缀，亦满足全部约束），
  给出被遮蔽规则、其在顺序中的位置与全部更早相交规则（覆盖依据为精确差集为空）。
- 所有合法顺序均安全时给出稳健结论，响应同时携带枚举的前缀状态数。
- 冻结与拒绝语义（与审计一致）：来源审计不存在、约束引用未知规则或引用相同规则、重复约束、先后环一律 **422 且不留痕**；
  同一复核标识改换来源或约束返回 **409 且不改写既有复核**；相同载荷重传返回 **200 原结论**。
- 复核响应内嵌来源审计快照（规则与逐规则裁决），因此来源审计的逐规则裁决始终可按审计标识查看，也可随复核一起重开。

请求体示例：

```json
{
  "review_id": "review-2026-10-02",
  "source_audit_id": "audit-2026-09-29",
  "constraints": [
    {"before": "r2", "after": "r1"},
    {"before": "r3", "after": "r1"}
  ]
}
```

`constraints` 可省略或为空（此时检验全部排列），至多 6 组；约束集合经去重与排序后冻结，约束顺序无关。

响应体（稳健）：

```json
{"review_id": "review-2026-10-02", "source_audit_id": "audit-2026-09-29",
 "constraints": [["r2", "r1"], ["r3", "r1"]],
 "robust": true, "counterexample": null, "states_explored": 5,
 "source": {"audit_id": "...", "rules": [...], "verdicts": [...]}}
```

响应体（不稳健）：

```json
{"robust": false,
 "counterexample": {
   "order": ["r1", "r2", "r3"],
   "position": 1,
   "shadowed_rule": "r3",
   "covered_by": ["r1"]}}
```

## 运行（Docker）

```bash
docker compose up --build app          # 默认映射宿主机 8080
HOST_PORT=9000 docker compose up --build app   # 配置宿主机访问端口
docker compose ps                      # app 健康检查基于 /healthz
```

打开 `http://localhost:8080/`（或所配端口）录入审计标识与规则、提交并查看逐规则裁决与见证，也可按审计标识复查冻结结论。

## 验证（verify 服务）

`verify` 服务在 `app` 健康后执行：**构建检查**（compileall）→ **代码测试**（pytest：区域代数精确性、引擎裁决、稳健性枚举与暴力预言机比对、API 生命周期与拒绝路径）→ **HTTP 冒烟**（一条部分遮蔽、一条完全遮蔽、同标识不同载荷的非法重传、非法 CIDR、幂等重放与冻结复查；以及复核 API 的稳健结论、反例顺序、约束成环等拒绝与来源审计回归），并以退出码报告结果：

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
