# Loon Forge

自托管的小工具：拉取一份 Mihomo/Clash YAML 配置，转换成 Loon `.conf`，并把你自己维护的 Loon 模板（插件、Rewrite、Mitm、General、Remote Proxy 等）固定拼进配置，最终对外提供一条**可以直接在 Loon 里订阅的固定链接**。

Mihomo 里的节点、策略组、规则会跟着源配置自动变化；Loon 特有的模板部分由你在网页上管理、永远保留——这是这个工具唯一要解决的问题。

> **⚠️ 自用声明**：本项目为个人自用工具，不对任何第三方订阅内容负责。请确保你拥有合法使用源配置和各类插件/规则的权利。
>
> **🤖 人工智能成分声明**：本项目代码在开发过程中使用了大型语言模型（LLM）辅助生成与修改，包括但不限于架构设计、代码实现、文档撰写和调试建议。代码已人工 review 并部署验证，但使用前请自行判断适用性。

## 快速开始

```bash
cd loon-forge
docker compose up -d --build
```

打开 `http://你的地址:8787`：

1. **配置源** — 填你的 Mihomo YAML 订阅链接
2. **插件模板** — 添加 Loon 插件/模块链接，可开关
3. **Rewrite** — 可视化添加 URL 重写规则
4. **Mitm** — 管理 hostname、ca-passphrase
5. **其他模板** — General / Remote Proxy / Proxy Chain / Remote Rule / Host / Script 按需填写
6. **订阅链接** — 复制 `http://你的地址:8787/loon.conf`，在 Loon 里作为远程配置添加

以后不管 Mihomo 源怎么换节点、加规则，`/loon.conf` 始终有效；插件/Rewrite/Mitm 是否生效由网页上的配置决定，不受源配置变化影响。

## 目录结构

```
loon-forge/
├── server.js          # Express 服务：设置/插件/Rewrite/Mitm 管理 API + /loon.conf
├── lib/convert.js      # Mihomo -> Loon 转换核心 + 模板渲染
├── public/index.html   # 管理网页（纯前端，无构建步骤）
├── data/settings.json  # 持久化存储，挂载卷
├── Dockerfile
└── docker-compose.yml
```

## 转换覆盖范围

**节点**：ss / vmess / trojan / hysteria2 / socks5。其他类型（比如 `relay` 链式代理）没有 Loon 对应写法，会被跳过并在预览页里列出来，不会静默丢失。

**策略组**：select / url-test / fallback / load-balance。如果策略组使用了 `use: [provider]` + `filter`，会自动生成对应的 Loon `[Remote Filter]`。

**规则**：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`、`GEOIP`、`MATCH`→`FINAL` 进入 `[Rule]` section；`RULE-SET`（Mihomo rule-provider）自动转换为 Loon `[Remote Rule]` 格式 `URL, policy=xxx, tag=xxx, enabled=true`。

**Proxy Chain**：Mihomo 节点上的 `dialer-proxy` 字段会自动生成 Loon `[Proxy Chain]` 两跳链路（`name-Chain = dialer, node, udp=true`），策略组中引用该节点的地方自动替换为 chain 名称。

**明确不支持、会在预览里标注跳过的**：
- `DOMAIN-REGEX`、逻辑规则（`AND`/`OR`/`NOT`）、`SCRIPT` 规则 —— Loon 本身没有这些能力
- 编译过的 `.mrs` 二进制 rule-provider —— 没有 `url` 字段的无法转换
- DNS（fake-ip）、TUN 等 —— Mihomo 特有机制，Loon 没有对应概念

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `8787` | 服务监听端口 |
| `DATA_DIR` | `/app/data`（容器内）| 设置文件存放目录，务必挂载卷持久化 |

## 数据迁移

`settings.json` 会随版本自动补齐新字段；旧版的纯文本模板字段也会自动迁移到 `advancedTemplates` 中作为高级模板保留。

## 许可与免责

本项目按"原样"提供，仅供个人学习和自用。使用本工具生成的配置文件需自行承担风险与责任。
