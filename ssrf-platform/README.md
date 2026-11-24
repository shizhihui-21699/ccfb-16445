# SSRF 自动化检测平台

面向公司内部数百个"会根据用户输入访问外部地址"的服务（网址预览、图片抓取、Webhook 回调等），
提供从探测注入、带外（OOB）回连接收、到漏洞精确定位的完整 Go 实现。

## 解决的四个核心问题

| 难点 | 本平台的做法 |
| --- | --- |
| **重定向 / 域名重绑定 / 地址变形** | 自带权威 DNS（含 per-token 重绑定状态机，首次公网 IP、后续内网 IP、1s TTL）；可控多跳重定向器；payload 生成器覆盖十进制/八进制/十六进制/IPv4-mapped IPv6/`0.0.0.0`/`127.1`/userinfo 混淆等写法 |
| **异步触发、回连很晚** | token 自描述且 HMAC 保护，不依赖扫描进程存活；事件落 JSONL 日志；`reconcile` 子命令在数小时/数天后补关联迟到回连 |
| **参数格式五花八门** | 声明式 manifest，每个注入点显式登记，支持 `query` / `json`(JSONPath) / `form` / `header` 四种位置；每次请求只让被测参数携带探针，其余填良性占位值 |
| **扫描不能破坏内网** | 双模式（`safe` 纯带外零内网接触；`full` 才发只读内网探针）；扫描器自身拨号有 dial-time 策略守卫（默认硬拦截 `169.254.0.0/16` 等链路本地/组播段，支持目标 CIDR 白名单）；永不跟随重定向；全局限速 + 内网请求硬预算；采集器默认禁止跳出 OOB 域名的重定向 |
| **精确定位** | 每个 job 的 token 编码 `service/endpoint/param/variant`，finding 直接给出这四元组、严重级别、置信度和完整证据事件链 |

## 架构

```
manifest ──► scanner ──注入唯一 token 化探针──► 被测内部服务
                │                                  │
                │ 注册 rebind 计划 / 轮询事件        │ DNS 解析、HTTP(S) 回连、跟随重定向
                ▼                                  ▼
        ┌──────────────── oobd ────────────────┐
        │ 权威 DNS(rebind 状态机) + HTTP/HTTPS   │
        │ 采集器 + 重定向器 + /api 关联接口       │
        └──────────────────┬────────────────────┘
                           ▼
              关联引擎 → 分级判定 → report.json
```

## 目录结构

```
cmd/
  oobd/          带外服务器（DNS + HTTP/HTTPS + API）
  scanner/       扫描器（scan / reconcile 两个子命令）
  demo-target/   故意脆弱的演示服务（仅实验用）
  tokgen/        手工冒烟用的 token 生成器
internal/
  token/         HMAC 自描述 token 编解码、DNS label 切分
  types/         领域类型
  store/         事件内存索引 + JSONL 持久化（重启可回放）
  dnssrv/        权威 DNS 服务器与重绑定状态机
  collector/     HTTP/HTTPS 采集器、重定向器、关联 API
  payload/       全部 payload 变体与地址变形
  manifest/      目标声明格式与校验
  injector/      四种参数位置的请求构造
  safeclient/    带拨号策略守卫的 HTTP 客户端
  oob/           采集器 API 客户端
  engine/        任务编排、限速预算、轮询关联、判定与报告
manifests/
  example.json   示例 manifest
```

## 快速开始（本机演练）

```bash
go build ./...

# 1) 启动带外服务器
./bin/oobd -domain oob.example.test \
  -dns-udp 127.0.0.1:5354 -dns-tcp 127.0.0.1:5354 \
  -http 127.0.0.1:8080 -https 127.0.0.1:8443 \
  -public-ip 127.0.0.1 -data-dir ./oob-data

# 2) 启动演示脆弱服务（-dns-server 模拟生产环境的 NS 委派）
./bin/demo-target -addr 127.0.0.1:9099 -delay 7s -dns-server 127.0.0.1:5354

# 3) 安全模式扫描（只接触 OOB 基础设施，不碰任何内网地址）
./bin/scanner scan -manifest manifests/example.json \
  -domain oob.example.test -oob-url http://127.0.0.1:8080 \
  -http-port 8080 -https-port 8443 -public-ip 127.0.0.1 \
  -mode safe -window 30s -poll 5s -rate 10 -out runs/$(date +%Y%m%d-%H%M)

# 4) 异步服务迟到回连后，补关联（可反复执行）
./bin/scanner reconcile -manifest manifests/example.json \
  -domain oob.example.test -oob-url http://127.0.0.1:8080 \
  -http-port 8080 -https-port 8443 -out runs/<同一目录>
```

## 生产部署要点

1. **DNS 委派**：注册一个专用域名（如 `oob.corp`），在企业 DNS 把该 zone 的 NS 记录指到
   `oobd` 所在主机；`-public-ip` 填采集器真实可达 IP。这是 token 主机名能在任意被测服务上解析的前提。
2. **密钥**：`-secret`（token HMAC）与 `-api-key`（关联 API）必须通过环境变量
   `OOB_SECRET` / `OOB_API_KEY` 注入，不要用默认值；两者轮换后旧 token 会以 `untrusted` 记录但不再参与自动判定。
3. **网络位置**：`oobd` 放在被测服务能访问到的网段；扫描器与 `oobd` 之间的 `/api` 走内网或 mTLS 代理。
4. **扫描模式**：日常巡检用 `safe`；`full` 仅在授权窗口使用，配合 `-intranet-budget`、
   `-allow-cidrs`（把扫描器出站限制在目标服务网段）和较低 `-rate`。
5. **HTTPS**：生产环境把 `-https` 换成正式证书（当前实现默认签发临时自签证书，适合实验）。
6. **水平扩展**：事件存储目前是单机 JSONL；多实例部署时把 `internal/store` 换成
   Postgres/Redis 实现（接口很小），DNS 与采集器均可无状态多副本（rebind 计划需共享存储）。

## Payload 变体矩阵

`safe` 模式（7 类，全部只与 OOB 基础设施交互）：

- `oob-http` / `oob-https`：直连回连
- `dns-only`：裸主机名，只观测 DNS 解析（盲 SSRF / URL 解析器）
- `redirect-1hop` / `redirect-3hop`：同信任域内可控重定向链
- `rebind-first-public`：DNS 重绑定（首答公网、其后内网）
- `url-userinfo-confusion`：`http://allowed@host/` 解析混淆

`full` 模式追加（只读 GET，受预算约束）：

- `redirect-to-metadata` / `redirect-to-internal`：带 OOB 证据的重定向落点
- 元数据 `169.254.169.254`：直连、AWS IMDS 路径、十进制/八进制/十六进制/IPv4-mapped IPv6
- 内网/环回：`127.0.0.1`、`127.1`、`0.0.0.0`、`[::1]`、十进制、八进制

## 判定逻辑

| 证据 | 结论 |
| --- | --- |
| 同步响应体含本 token 的 marker | high / confirmed（目标回抓并嵌入了页面） |
| rebind 变体出现 HTTP 回连 | critical / confirmed（重绑定后打到内网） |
| rebind 变体只有 DNS 解析 | high / likely（窗口内未观测到翻转后行为） |
| 重定向变体 HTTP 回连 | high / confirmed |
| 内网类变体出现 OOB 交互 | critical / confirmed |
| `dns-only` 出现 DNS 查询 | medium / confirmed（盲 SSRF） |
| 内网探针有非拒绝 HTTP 状态但无 OOB 证据 | 进入 `unconfirmed_jobs` 人工复核，不自动定罪 |

## 测试

```bash
go test -race ./...
```

包含 token HMAC 防篡改、地址变形数值、拨号策略拦截、注入器参数隔离、DNS 重绑定状态机、
采集器重定向门禁，以及 5 个端到端场景（同步/重定向 SSRF、异步 reconcile、rebind、
allow-list 绕过面、内网预算）。

## 安全边界与免责

- 本工具仅限对**自有且已授权**的资产进行安全测试。
- `demo-target` 是刻意脆弱的演练服务，禁止部署到实验环境之外。
- `full` 模式的内网探针只发 GET、不带破坏性 payload，但任何内网扫描都应在变更窗口与限速下进行。
