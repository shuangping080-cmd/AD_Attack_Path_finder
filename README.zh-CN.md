# AD-Attack-Path-Finder

[English README](README.md)

AD-Attack-Path-Finder 是一个分析型工具，用于从 BloodHound.py / SharpHound 采集结果中快速提取、推理 Active Directory 攻击链路。

它不是为了替代 BloodHound。它要解决的是 BloodHound 不一定能直接展示成一条明确路线的部分：权限语义解释、缺失前置条件、HTB 靶机历史链路知识关联，以及结合本地知识库和 LLM 对可能路线进行合理推测。

整体流程可以理解为：

```text
BloodHound zip
    -> 规范化 AD 图
    -> 基于规则的 Relationship / Primitive 分析
    -> 候选权限路径
    -> HTB 历史知识库关联
    -> LLM 复核 Prompt
    -> 按权重输出推荐路线和待验证条件
```

## 项目目的

在 HTB 风格的 AD 域靶机中，BloodHound 图里通常已经包含了很多原始关系，但最终利用路线不一定能直接显示出来。有些路径需要进一步做语义分析：

- `GenericWrite` 根据目标对象不同，可能对应多种不同攻击 Primitive。
- `WriteSPN` 可能指向 SPN 操作和 targeted Kerberoast，但 hash 获取、破解和凭据恢复仍是额外条件。
- `AdminTo` 是主机本地管理权限，不等于域权限。
- OU / GPO / dMSA / ADCS 相关边很多时候只是前置条件，需要补充更多证据。
- 历史 WP 中出现过的链路只能作为参考，不能直接当成当前环境事实。

本项目的目标就是补上这层分析。它会先运行项目中已经写好的确定性规则；如果规则没有找到强路径，再生成结构化上下文，供 Hermes 或其他本地 LLM 结合 HTB 知识库继续推理可能路线，并给出需要验证的条件。

## 能做什么

- 导入 BloodHound zip、JSON 文件夹或已规范化图数据。
- 生成 `nodes.json`、`edges.json`、`graph.json`。
- 将原始 BloodHound 关系映射为可能的攻击 Primitive。
- 区分 `Confirmed Path`、`Candidate Path`、`Incomplete Path`。
- 明确 `Relationship != Primitive`。
- 明确 `HighValue != Domain Admin`。
- 将 HTB 历史案例和当前图证据分开处理。
- 根据证据质量、权限提升、缺失信息、历史支持和路径质量进行评分。
- 输出 next best investigations，即下一步最值得收集或验证的信息。
- 在规则分析不完整时，生成可交给本地 LLM / Hermes 的复核 Prompt。

## 安全边界

本项目只用于授权 AD 实验环境、HTB 靶机、安全训练和授权评估。

它只分析已经采集到的数据，不执行利用动作，不进行密码修改、RBCD 写入、证书申请、DCSync、横向移动、Kerberoasting 或权限提升操作。

## 安装

开发环境建议使用 editable install：

```bash
python -m pip install -e .
```

查看 CLI：

```bash
python -m adpath --help
```

## 一键链路分析

当你已经有 BloodHound zip，并且知道初始低权限账户时，优先使用 `investigate`：

```bash
python -m adpath investigate path/to/bloodhound.zip --start "USER@DOMAIN.LOCAL" -o data/current --top-n 10 --markdown
```

示例：

```bash
python -m adpath investigate path/to/vintage_bloodhound.zip --start "P.ROSA@VINTAGE.HTB" -o data/vintage --top-n 10 --markdown
```

输出 JSON：

```bash
python -m adpath investigate path/to/bloodhound.zip --start "USER@DOMAIN.LOCAL" -o data/current --json
```

这条命令会完成：

1. 必要时导入 BloodHound 数据。
2. 运行 ACL、Kerberos、delegation、gMSA、dMSA、ADCS、OU、GPO 检测器。
3. 构建用于分析的 semantic edges，但不修改原始图事实。
4. 运行 candidate path 和 privilege path 搜索。
5. 将当前图结构与 HTB 历史知识库进行匹配。
6. 对推荐路径进行排序。
7. 输出缺失信息和下一步最值得验证的内容。
8. 生成用于知识库辅助分析的 LLM / Hermes Prompt。

## LLM / Hermes 使用方式

工具本身不会直接调用外部 LLM。它会在 `LLM Review` 部分输出结构化 Prompt。

如果在 Kali 或其他本地环境中使用 Hermes，建议提供：

- BloodHound zip 或规范化图输出；
- 初始用户，例如 `P.ROSA@VINTAGE.HTB`；
- `investigate` 的输出结果；
- 本仓库中的公开知识库文件：
  - `knowledge-base/htb/public-index.json`
  - `knowledge-base/htb/structured/`
  - `knowledge-base/attack-patterns/`
  - `knowledge-base/pattern-cards/`

建议 Prompt：

```text
你正在分析一个授权的 HTB 风格 AD 靶机。
当前 BloodHound 图中的边是事实证据。
HTB 知识库只能作为历史参考。
不要把历史链路当成当前环境已经确认的事实。

根据下面的 adpath investigate 输出，从 START_USER 出发，按可能性和价值排序推荐权限路线。
每条路线需要区分：
1. 当前图中已确认的证据
2. 语义解释
3. 历史 HTB 类似案例
4. 缺失条件
5. 下一步应收集或验证的信息

请按权重输出推荐路线，并说明在把路线视为可行之前必须验证什么。
```

## 常用命令

仅导入数据：

```bash
python -m adpath import path/to/bloodhound.zip -o data/current
```

查看图内容：

```bash
python -m adpath nodes -g data/current --type User
python -m adpath nodes -g data/current --type Group
python -m adpath nodes -g data/current --type Computer
python -m adpath edges -g data/current --relationship MemberOf
```

运行专项检测器：

```bash
python -m adpath kerberos -g data/current
python -m adpath delegation -g data/current
python -m adpath gmsa -g data/current
python -m adpath dmsa -g data/current
python -m adpath adcs -g data/current
python -m adpath ou -g data/current
python -m adpath gpo -g data/current
```

运行证据感知的候选路径搜索：

```bash
python -m adpath candidate-path "USER@DOMAIN.LOCAL" -g data/current --max-depth 6 --top-n 10 --markdown
python -m adpath candidate-path "USER@DOMAIN.LOCAL" -g data/current --show-evidence
python -m adpath candidate-path "USER@DOMAIN.LOCAL" -g data/current --json
```

运行原始权限图路径搜索：

```bash
python -m adpath privilege-path "USER@DOMAIN.LOCAL" -g data/current --max-depth 5 --top-n 10
```

发现可能的初始 foothold：

```bash
python -m adpath foothold-candidates -g data/current --top-n 20 --markdown
```

在本地记录人工验证证据：

```bash
python -m adpath evidence add -g data/current \
  --principal "HOST01$@DOMAIN.LOCAL" \
  --type credential_valid \
  --method kerberos_ldap \
  --note "authorized validation succeeded"
```

从 `evidence.json` 中所有已控制主体继续扩展路径：

```bash
python -m adpath candidate-path -g data/current --controlled --show-evidence
```

## 证据模型

项目使用严格的证据边界：

- 原始 BloodHound edge：当前图事实。
- Semantic primitive：对当前图证据的解释。
- HTB 历史链路：参考模式。
- Candidate path：可能路线，但仍需验证条件。
- Incomplete path：缺失信息阻止进一步确认。

示例：

```text
当前图：
alice --GenericWrite--> svc_sql

语义解释：
GenericWrite 可能带来身份控制或 SPN 操作，具体取决于目标对象属性。

历史支持：
类似 HTB 链路曾出现过，但不能证明当前环境已经满足条件。

缺失：
SPN 状态、可写属性、服务账户下游主机影响、Session、凭据、ADCS/delegation 上下文。
```

## 知识库

公开仓库中包含经过脱敏整理的 HTB 历史知识层：

- `knowledge-base/htb/public-index.json`
- `knowledge-base/htb/structured/*.yaml`
- `knowledge-base/attack-patterns/*.yaml`
- `knowledge-base/pattern-cards/*.yaml`
- `knowledge-base/primitives/*.yaml`
- `knowledge-base/relationships/*.yaml`

公开知识库存放的是结构化链路摘要和可复用模式，不包含私有 WP 原文、本地 BloodHound 采集数据或私有 SQLite 数据库。

知识整理目标流程：

```text
WP 原文，本地私有
    -> 域渗透部分提取
    -> 链路 / Primitive / 机制 YAML
    -> 可复用攻击模式
    -> Skill 与 LLM 辅助推理
```

## 当前支持的分析范围

- ACL：`GenericAll`、`GenericWrite`、`WriteDACL`、`WriteOwner`、`ForceChangePassword`、`WriteSPN`
- 组成员关系和高权限组区分
- 本地管理员权限与域权限区分
- Kerberos：ASREPRoast、Kerberoast、TargetedKerberoast、Silver Ticket candidate、Golden Ticket candidate
- Delegation：非约束委派、约束委派、RBCD、S4U 风格推理
- gMSA / dMSA，包括 BadSuccessor 候选检查
- ADCS ESC 风格模板和 CA 信号
- OU / GPO 控制路径
- Pre-Windows 2000 compatible computer account foothold 假设
- HTB 历史模式匹配，不依赖用户名相同

## 仓库结构

```text
src/adpath/
  __main__.py, cli.py        CLI 入口，包括 import、investigate、candidate-path 和各类 detector
  investigate.py             BloodHound zip -> 规则分析 -> 知识库关联 -> LLM Prompt 的一键流程
  parsers/                   BloodHound JSON/zip 解析和规范化
  graph/                     AD 图模型，以及 normalized graph 读写
  models/                    node、edge、primitive、evidence、missing-info、privilege、path 数据模型
  detectors/                 ACL、Kerberos、delegation、gMSA、dMSA、ADCS、OU、GPO、privilege 检测器
  pathfinder/                shortest path、privilege path、candidate path、路径评分和解释
  knowledge/                 YAML 知识加载、Primitive Catalog、Relationship Catalog、Pattern Matching
  signal/                    foothold 和 interesting-object 假设引擎
  collectors/                collector 抽象层
  visualization/             后续可视化功能占位

knowledge-base/
  relationships/             公开 Relationship 定义和兼容信息
  primitives/                公开攻击 Primitive、前置条件和后续验证问题
  attack-patterns/           可复用的结构化攻击模式，用于图匹配
  pattern-cards/             更高层的 interesting-signal / hypothesis 卡片
  htb/structured/            脱敏后的 HTB 历史链路摘要
  htb/public-index.json      公开 HTB 知识记录索引
  schemas/                   知识记录 YAML schema

skill/ad-attack-path/
  SKILL.md                   Codex skill 入口，用于使用和继续演进项目
  references/                workflow、evidence model、historical knowledge 说明
  agents/                    skill 元数据

tests/                       parser、semantics、paths、knowledge、reports、signals 回归测试
scripts/                     公开安全的导出和校验辅助脚本
docs/                        不含敏感信息的验证记录和项目 checklist
data/                        本地图工作区，默认忽略；仓库只保留 .gitkeep
web/                         后续本地可视化资源占位
references/                  公开参考说明
```

本地 BloodHound 数据、人工验证 evidence、私有 SQLite 知识库文件不应提交到 Git。

## 后续方向

长期方向是提升 AD 靶机链路分析效率：

1. 使用 BloodHound 作为图证据来源。
2. 使用确定性规则识别已知关系和 Primitive。
3. 使用本地知识库识别历史链路形状。
4. 使用 LLM 对缺口进行推理，提出下一步验证建议。
5. 输出简洁、加权、证据边界清晰的推荐路线。

最终希望回答的问题是：

```text
我有一个初始低权限账户和一个 BloodHound zip。
哪些路线是已确认的？
哪些路线是合理猜测的？
还缺什么信息？
下一条最值得验证的路线是什么？
哪些 HTB 链路在结构上相似？
```
