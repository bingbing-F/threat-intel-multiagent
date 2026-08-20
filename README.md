# 基于多智能体协作的自动化网络威胁情报监控与预警系统

一个基于多智能体（Multi-Agent）协作的自动化网络威胁情报监控与预警系统 MVP。系统通过 7×24 小时自动采集公开 OSINT 威胁情报，经大模型提取、多维度校验后生成结构化报告并推送告警。

## 核心能力

**多智能体协作管线（LangGraph 编排）**：采集 → 多领域监测 → 分析 → 校验 → 跨源关联 → 报告，
以有向图建模节点与条件边（是否生成日报 / 是否推送告警），而非硬编码 for 循环；
无 LangGraph 环境自动退化为线性执行。

- **感知 Agent（Collector）**：自动采集 CVE/NVD、GitHub Security Advisory、安全博客 RSS 等公开 OSINT 源，
  并发抓取 + 哈希去重入库。
- **监测 Agent（DomainMonitor）**：多领域关键词切片统计（卫星/航天、勒索软件、APT、供应链、IoT 僵尸网络），
  逐域产出 hit 数 / 独立来源数 / 暗网来源数，并持久化到 `domain_metrics`。
- **分析 Agent（Analyzer）**：基于大模型提取威胁类型、IoC（IP/域名/URL/Hash）、涉及资产、置信度。
- **对抗协作评审（Reviewer + Coordinator）**：独立评审 Agent 对每条分析结果做规则 / 语义审查，
  协调 Agent 依据反馈自动修复并复评，产出一条可审计的 **问题清单修复记录**（争议率 / 修复数 / 残留数）。
- **校验 Agent（Validator）**：关键词匹配 + AI 语义理解 + IOC 可解析性 + 置信度阈值多维断言。
- **跨源关联 Agent（Correlator）**：按共享 IoC 聚类情报，多个**独立来源**印证同一威胁时判定为
  **corroborated** 并提升置信度（证据驱动，演示模式下 11 条样本可印证出 1 个 CVE 事件）。
- **报告 Agent（Reporter）**：自动生成日报 / 实时告警，支持邮件与飞书 Webhook 推送。

**可量化的 Agent 评估体系（AI 测试方法论）**：
- **Prompt A/B 测试**：v1.0 → v1.3 迭代，固定 benchmark 评估准确率 / 召回率 / F1，显著优于基线（v1.2）即获胜；
- **运行时部署 + 回归护栏**：获胜版本写入 `runtime_prompt.json` 自动生效，不足基线自动拦截并告警；
- **对抗评审争议率 / 修复率 / 残留率** 与 **跨源印证率 / 置信度增益** 作为协作有效性的量化指标。

- **Dashboard**：Streamlit 可视化情报列表、评审记录、关联事件、趋势、告警与 A/B 评估 / 部署结果。

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置环境变量（真实 LLM 模式）
cp .env.example .env
# 编辑 .env，填入 LLM_API_KEY；不配置则自动进入演示模式

# 3. 初始化数据库
python scripts/init_db.py

# 4. 运行完整工作流一次
python scripts/run_pipeline.py            # 真实模式（需 LLM_API_KEY）
python scripts/run_pipeline.py --demo     # 演示模式（Deterministic DemoLLM，无需额度）
python scripts/run_pipeline.py --limit 5  # 限制本次分析条数，控制真实模式下 LLM 成本

# 5. 启动 Dashboard
streamlit run dashboard/app.py
```

## 多智能体协作机制

| 阶段 | Agent | 产出 | 可量化指标 |
|------|-------|------|-----------|
| 1. 采集 | Collector | 原始情报（raw intel） | 采集条数 |
| 2. 多领域监测 | DomainMonitor | 专题监测指标 | 每域命中数、独立来源数、暗网来源数 |
| 3. 分析 + 对抗评审 | Analyzer → Reviewer/Coordinator | 结构化威胁情报 + 评审记录 | 争议率、修复数、残留数、评审记录落库数 |
| 4. 校验 | Validator | 有效/无效判定，推送告警 | 有效 / 无效条数 |
| 5. 跨源关联 | Correlator | 聚合威胁事件 | 事件数、co-occurrence 印证率、置信度增益 |
| 6. 报告 | Reporter | Markdown 日报 | 报告字节数 |

评审争议率 = 需 ≥2 轮评审的情报占比；跨源印证 = 同一 IoC 被 ≥2 个独立来源独立报告。
示例演示（demo 模式）：11 条样本 → 2 条评审争议（TYPE_IRRELEVANT_WITH_IOC，含置信度 0.89→0.35 校准）→
8 有效 / 3 无效 → 1 个 corroborated 事件（CVE-2025-6601，2 来源印证，置信度 0.97→1.00）。

## 演示模式说明

- 无 `LLM_API_KEY` 时 Dashboard 自动进入**演示模式**：使用确定性 DemoLLM 替代真实大模型，
  但采集→分析→校验→报告→入库整条链路与真实模式完全一致，可零成本完成任务级端到端演示。
- 恢复额度 / 配置 `LLM_API_KEY` 后，侧边栏关闭「演示模式」即切换到**真实模式**，
  实时分析 NVD / GitHub Advisory / 安全博客 RSS 等 OSINT 源；LLM 结果自动缓存（`data/llm_cache`）以降低成本。
- `run_pipeline.py`、Dashboard「运行工作流」页均支持真实模式限量运行（`--limit` / 页内条数上限）。

## 项目结构

```
├── config/              # 配置与 Prompt 版本
├── src/                 # 核心源码
│   ├── agents/          # 感知/分析/校验/关联/报告/评审/协调/监测 Agent
│   ├── graph/           # LangGraph 状态机工作流编排（含 Monitor 节点）
│   ├── sources/         # 数据源适配器（RSS/API/Demo/本地数据集/合规暗网源）
│   ├── storage/         # 数据库模型与 CRUD
│   ├── llm/             # LLM 统一客户端（含演示器 DemoLLM）
│   ├── evaluation/      # Prompt 注册、A/B 测试、运行时部署与回归护栏
│   └── utils/           # 工具函数
├── dashboard/           # Streamlit 前端（含专题监测页）
├── tests/               # 单元测试与集成测试
├── scripts/             # 运行脚本
├── data/                # 本地数据存储（含 benchmark、评估结果、暗网种子数据集）
└── docs/                # 开发记录、面试准备、归档 PRD
```

## 合规声明

本项目仅使用公开 OSINT 数据源与**合成标注样本**，用于学习、研究与安全防御目的。禁止用于非法爬取、未授权访问或任何违法行为。
暗网监测采用合规限域设计：默认关闭、显式白名单 URL、强制 SOCKS5 代理（fail-closed）、关键词过滤，详见 `docs/面试准备.md` 红线清单。

## 文档

- `项目设计文档_v2.1.0.docx`：当前 PRD（多智能体对抗评审 / 跨源关联 / LangGraph 编排 / 运行时部署与回归护栏 / 多领域专题监测）。
- `docs/项目设计文档_v1.0_1318初版.docx`：v1.0 初版设计，原样保留。
- `docs/开发记录.md`：全部关键变更、bug 修复名单与新版本发布流程。
- `docs/面试准备.md`：求职问答速查（项目定位 / 技术要点 / 高频疑问 / 合规叙事）。
- `docs/项目学习与面试追问清单.md`：模块学习顺序（一句话讲法）+ 面试官追问应答 + 暗网真实验证步骤。
- 重新生成 PRD：`node docx-scripts/generate_doc.js`。

## 版本发布

- 远端：`origin`=GitHub、`gitee`=Gitee，主干 `master`；发布流程封装在
  `.opencode/skills/git-release/SKILL.md`（直接说"发布/打版本/推送"即可触发）。
- 详细规则（版本号、清单、命令）见 `docs/开发记录.md` 顶部「版本管理与发布流程」。
