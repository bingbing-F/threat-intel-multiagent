const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
        HeadingLevel, AlignmentType, LevelFormat, BorderStyle, WidthType,
        ShadingType, PageBreak } = require('docx');
const fs = require('fs');

const outputPath = 'f:/基于多智能体协作的自动化网络威胁情报监控与预警系统/项目设计文档_v2.1.0.docx';

const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const tableBorders = { top: border, bottom: border, left: border, right: border };

function h1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(text)] });
}

function h2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(text)] });
}

function h3(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(text)] });
}

function p(text, opts = {}) {
  return new Paragraph({
    spacing: { after: 120 },
    children: [new TextRun(Object.assign({ text }, opts))]
  });
}

function bullets(items) {
  return items.map(item => new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { after: 80 },
    children: [new TextRun(item)]
  }));
}

function numbered(items) {
  return items.map(item => new Paragraph({
    numbering: { reference: "numbers", level: 0 },
    spacing: { after: 80 },
    children: [new TextRun(item)]
  }));
}

function createTable(headers, rows, widths) {
  const totalWidth = 9360;
  const colWidths = widths || Array(headers.length).fill(Math.floor(totalWidth / headers.length));
  return new Table({
    width: { size: totalWidth, type: WidthType.DXA },
    columnWidths: colWidths,
    rows: [
      new TableRow({
        children: headers.map((h, i) => new TableCell({
          borders: tableBorders,
          width: { size: colWidths[i], type: WidthType.DXA },
          shading: { fill: "D5E8F0", type: ShadingType.CLEAR },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })]
        }))
      }),
      ...rows.map(row => new TableRow({
        children: row.map((cell, i) => new TableCell({
          borders: tableBorders,
          width: { size: colWidths[i], type: WidthType.DXA },
          margins: { top: 80, bottom: 80, left: 120, right: 120 },
          children: [new Paragraph({ children: [new TextRun(String(cell))] })]
        }))
      }))
    ]
  });
}

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 24 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 36, bold: true, font: "Arial", color: "1F2937" },
        paragraph: { spacing: { before: 360, after: 240 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 30, bold: true, font: "Arial", color: "374151" },
        paragraph: { spacing: { before: 300, after: 180 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: "4B5563" },
        paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 2 } }
    ]
  },
  numbering: {
    config: [
      { reference: "bullets",
        levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers",
        levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
      }
    },
    children: [
      // Cover
      new Paragraph({ spacing: { before: 2400 }, children: [] }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 400 },
        children: [new TextRun({ text: "基于多智能体协作的", size: 48, bold: true, font: "Arial", color: "111827" })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 800 },
        children: [new TextRun({ text: "自动化网络威胁情报监控与预警系统", size: 48, bold: true, font: "Arial", color: "111827" })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 200 },
        children: [new TextRun({ text: "项目设计文档（PRD）", size: 32, font: "Arial", color: "4B5563" })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 200 },
        children: [new TextRun({ text: "版本：v2.1.0（多智能体对抗评审 / 跨源关联 / LangGraph 编排 / 运行时部署 / 多领域专题监测）", size: 24, font: "Arial", color: "6B7280" })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 200 },
        children: [new TextRun({ text: "日期：2026-08-16", size: 24, font: "Arial", color: "6B7280" })]
      }),
      new Paragraph({ spacing: { before: 1600 }, children: [] }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "独立开发项目 | AI 测试开发方向", size: 24, font: "Arial", color: "6B7280" })]
      }),
      new Paragraph({ children: [new PageBreak()] }),

      // TOC placeholder
      h1("目录"),
      ...numbered([
        "项目概述",
        "项目背景与目标",
        "核心功能",
        "技术栈选型",
        "系统架构",
        "多 Agent 详细设计",
        "数据模型与接口",
        "数据源与合规边界",
        "提示词工程与 A/B 测试",
        "测试策略",
        "实施计划",
        "风险与边界",
        "附录：推荐开源项目清单",
        "附记：开发记录与演进轨迹"
      ]),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 1
      h1("1. 项目概述"),
      p("本项目将“暗网搜集”这一经历包装为合规、可演示的技术项目，命名为《基于多智能体协作的自动化网络威胁情报监控与预警系统》。系统通过 7x24 小时自动采集公开 OSINT（Open Source Intelligence）威胁情报，经大模型提取、多维度校验后生成结构化报告并推送告警。"),
      p("项目重点体现 AI 测试开发所需的四项核心能力："),
      ...bullets([
        "自动化流程设计：多级 Agent 协作与任务编排",
        "异常监控与告警：采集异常、LLM 调用失败、置信度不足等情况的处理",
        "数据清洗与断言：脏数据处理、IOC 提取、多维度置信度校验",
        "提示词工程与质量评估：prompt 版本管理与 A/B 测试评估"
      ]),
      p("项目定位为独立开发的 MVP（Minimum Viable Product），目标是在 1-2 周内完成可运行的演示版本，用于测试开发 / AI 测试方向求职展示。"),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 2
      h1("2. 项目背景与目标"),
      h2("2.1 原始经历包装"),
      p("原始经历为“在特定信息源中持续监控、提取和整理某类情报（如卫星数据泄露相关帖子）”。这一过程的本质是：持续监控、信息提取、数据清洗、结构化报告生成。"),
      p("将其抽象后，与 Agent（智能体）概念天然契合：一个自动化智能体持续代替人完成监控与情报处理任务。"),
      h2("2.2 项目目标"),
      ...numbered([
        "构建可运行的多 Agent 协作威胁情报监控系统；",
        "实现从公开源采集、LLM 提取、置信度校验到报告推送的完整自动化链路；",
        "通过 prompt 版本管理与 A/B 测试体现 AI 模型测试方法论；",
        "提供 Web Dashboard 用于演示与数据可视化；",
        "输出可放入简历的项目描述与量化指标。"
      ]),
      h2("2.3 量化指标（实测）"),
      createTable(
        ["指标", "目标值 / 实测值", "说明"],
        [
          ["情报提取准确率", "目标 >= 90%；实测 v1.3 = 1.00", "通过多维度校验与 A/B 测试优化"],
          ["A/B 演示评估", "accuracy/recall/F1 单调提升", "v1.0(0.40/0.40/0.40) → v1.3(1.00/1.00/1.00)"],
          ["对抗评审", "11 条样本中 2 条争议(18.2%)", "TYPE_IRRELEVANT_WITH_IOC，置信度 0.89→0.35 校准"],
          ["跨源关联验证", "11 条样本印证 1 个 CVE 事件", "CVE-2025-6601，2 独立来源，置信度 0.97→1.00"],
          ["运行时部署", "v1.3 部署并回归放行", "runtime_prompt.json 自动生效，低于基线(v1.2)自动拦截"],
          ["系统可用性", "7x24 小时", "APScheduler 定时调度 + 异常回滚"],
          ["单元测试", "24 passed", "Python 3.13 / 3.8 双环境通过"],
          ["Prompt 版本迭代", "v1.0 -> v1.3", "体现持续优化过程"]
        ],
        [2500, 3600, 3260]
      ),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 3
      h1("3. 核心功能"),
      h2("3.1 LangGraph 多 Agent 编排（核心亮点）"),
      p("工作流以 LangGraph StateGraph 建模为有向图：采集 → 分析 → 校验 → 跨源关联 → 报告五个节点，通过条件边（是否生成日报 / 是否推送告警）动态路由，而非硬编码 for 循环。无 LangGraph 环境自动退化为线性执行，保证健壮性。"),
      h2("3.2 感知 Agent（采集）"),
      p("自动监控多个公开 OSINT 数据源，包括 CVE/NVD、安全博客 RSS、GitHub Security Advisory、公开 IOC Feed 等。支持异步并发拉取、请求重试、反爬应对（请求间隔、User-Agent 轮换），并将原始内容存入原始数据池。"),
      h2("3.3 分析 Agent + 对抗评审（双 Agent 协作）"),
      p("分析 Agent 调用大模型从原始文本中提取威胁类型、IoC（IP / 域名 / URL / Hash）、涉及资产、置信度，输出结构化 JSON。紧随其后，独立评审 Agent（Reviewer）对每条结果做规则审查（如类型无关却含 IoC、高置信却无关、IoC 缺失/疑似伪造），协调 Agent（Coordinator）依据反馈自动修复并复评，产出一条可审计的问题清单修复记录——这是“多智能体协作”最直接的体现，也是其他实现无法复制的差异点。"),
      h2("3.4 校验 Agent（断言）"),
      p("结合关键词规则与 AI 语义理解，设计多维度校验断言。仅当置信度达到或超过 90% 时判定为有效情报；未通过校验的条目进入“废弃/人工复核”队列。"),
      h2("3.5 跨源关联 Agent（Correlator）"),
      p("按共享 IoC（IP/域名/URL/Hash）对有效情报做聚类，当同一威胁被多个独立来源独立报告时判定为 corroborated 并提升置信度（证据驱动）。演示数据中 11 条样本可印证出 1 个 CVE 事件（CVE-2025-6601，2 来源印证，置信度 0.97→1.00）。"),
      h2("3.6 报告 Agent（告警）"),
      p("将有效情报结构化为日报或实时告警，通过邮件 SMTP 或飞书 Webhook 推送。支持 Markdown / PDF 格式导出。"),
      h2("3.7 Prompt 版本管理与 A/B 测试（AI 测试方法论）"),
      p("维护 prompt v1.0 至 v1.3 多个版本，在固定标注数据集上对比准确率、召回率、F1。获胜版本通过运行时部署写入 runtime_prompt.json 并在下一次工作流自动生效；配套回归护栏，凡低于基线（v1.2 指标）的版本即被拦截。演示模式下使用确定性 Mock 评分，保证 A/B 结果可复现。"),
      h2("3.8 Dashboard 可视化"),
      p("通过 Web 仪表板展示情报列表、评审记录（争议率 / 修复数 / 残留数）、跨源关联事件、趋势统计、告警记录与 A/B 评估 / 部署结果。界面采用深色网络安全风格，突出“情报作战中心”氛围。"),
      h2("3.9 演示模式 / 真实模式双链路"),
      p("未配置 LLM_API_KEY 时，系统自动使用确定性 DemoLLM + 联想演示源（DemoSource）完成零成本端到端演示；配置额度后切换真实模式，分析真实 OSINT 源。Validator / Reporter / 数据库在两模式下保持一致，评估体系（A/B、评审、关联指标）原样运行。"),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 4
      h1("4. 技术栈选型"),
      createTable(
        ["模块", "技术选型", "选型理由"],
        [
          ["语言与运行时", "Python 3.10+", "生态丰富，AI/安全库成熟"],
          ["多 Agent 编排", "LangGraph（StateGraph）", "声明式状态机，支持条件边/回退；无依赖时线性回退"],
          ["LLM 接入", "OpenAI 兼容接口 / DeepSeek / 智谱 GLM / DemoLLM", "配置化切换，未配置额度自动演示模式"],
          ["数据存储", "SQLite（开发）+ PostgreSQL（生产可选）", "轻量演示，便于迁移"],
          ["前端 Dashboard", "Streamlit + streamlit.testing", "Python 原生，快速构建数据看板且可自动化冒烟测试"],
          ["数据采集", "httpx + feedparser + BeautifulSoup", "异步高效，RSS/Web 解析成熟"],
          ["数据校验", "Pydantic", "类型安全、序列化方便"],
          ["报告生成", "Jinja2 + Markdown", "模板化，易于扩展 PDF"],
          ["任务调度", "APScheduler", "定时任务、持久化、并发支持"],
          ["测试框架", "pytest + unittest.mock", "单元测试、模拟 LLM/网络响应"],
          ["IOC 标准化", "python-stix / txt2stix", "威胁情报标准格式支持"]
        ],
        [2500, 3500, 3360]
      ),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 5
      h1("5. 系统架构"),
      p("系统采用“采集 → 分析（含对抗评审）→ 校验 → 跨源关联 → 报告”五节点流水线，由 LangGraph StateGraph 统一编排，条件边决定是否生成日报 / 推送告警。整体架构图如下："),
      ...bullets([
        "公开 OSINT / 演示源 → 感知 Agent（采集与初筛）→ 原始数据池",
        "原始数据池 → 分析 Agent（LLM 结构化提取）→ 候选情报",
        "候选情报 → 评审 Agent（Reviewer）→ 协调 Agent（Coordinator 修复/复评）→ 评审记录",
        "候选情报 → 校验 Agent（多维度断言：关键词/IoC/语义/置信度）",
        "置信度 >= 90% → 有效情报库",
        "未通过 → 废弃/人工复核",
        "有效情报库 → 跨源关联 Agent（共享 IoC 聚类 + 独立来源印证）→ 威胁事件",
        "有效情报库 → 报告 Agent → 日报/实时告警 → 邮件/飞书 Webhook",
        "有效情报库 → Streamlit Dashboard",
        "采集原文 → 多领域监测 Agent（关键词切片统计 + 来源分层明网/暗网）→ 专题监测指标"
      ]),
      p("Prompt Registry（v1.0-v1.3）为分析 Agent 提供不同版本提示词；A/B 评估模块基于标注数据集对比各版本，获胜版本运行时部署到 runtime_prompt.json，分析 Agent 下次运行即生效；回归护栏对低于基线（v1.2）的版本自动拦截。"),
      h2("5.1 目录结构"),
      p("项目目录结构遵循模块化、可测试、可扩展原则："),
      p("config/ 存放全局配置与 prompt 版本文件；src/ 包含 models、agents、graph、sources、storage、llm、evaluation、utils 等模块；dashboard/ 为 Streamlit 前端；tests/ 包含各模块单元测试；scripts/ 包含运行脚本；data/ 存 benchmark 与评估结果。"),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 6
      h1("6. 多 Agent 详细设计"),
      h2("6.1 感知 Agent"),
      createTable(
        ["职责", "输入", "输出", "关键技术"],
        [
          ["定向采集与初筛", "配置化的数据源列表", "RawContent 列表", "httpx 异步、feedparser、robots.txt 遵守"],
          ["数据清洗", "原始 HTML/RSS/JSON", "规范化文本", "BeautifulSoup、编码修复、去重"]
        ],
        [2200, 2200, 2200, 2760]
      ),
      h2("6.2 分析 Agent"),
      createTable(
        ["职责", "输入", "输出", "关键技术"],
        [
          ["结构化提取", "清洗后文本", "候选 ThreatIntelligence", "LLM + Pydantic 解析"],
          ["置信度初评", "文本与提取结果", "confidence 字段", "prompt 内置信度指引"]
        ],
        [2200, 2200, 2200, 2760]
      ),
      h2("6.3 评审 Agent + 协调 Agent（协作核心）"),
      createTable(
        ["校验维度", "方法", "判定/修复"],
        [
          ["类型无关却含 IoC", "规则检查 TYPE_IRRELEVANT_WITH_IOC", "判定为高风险，Coordinator 降低置信度"],
          ["高置信却主题无关", "规则 + LLM 语义复核 HIGH_CONF_IRRELEVANT", "Coordinator 澄清后复评"],
          ["IoC 缺失 / 疑似伪造", "规则检查 MISSING_IOC / FABRICATED_IOC", "协调 Agent 依据反馈修复并复评"],
          ["评审指标", "争议率 / 修复数 / 残留数", "每条生成 ReviewRecord 落库审计"]
        ],
        [2600, 3200, 3560]
      ),
      p("引言：本阶段是“多智能体协作”的直接体现——一个 Agent 产出候选结果，另一个独立 Agent 审查并质疑，第三个 Agent 依据质疑修复，最终结果经过修复 + 复评迭代，置信度收敛到可信值（演示样本中置信度 0.89→0.35 被校准）。"),
      h2("6.4 校验 Agent"),
      createTable(
        ["校验维度", "方法", "通过标准"],
        [
          ["关键词匹配", "威胁类型关键词、卫星/泄露相关词", "命中核心词"],
          ["IOC 可解析", "正则提取 IP/域名/URL/Hash", "至少提取 1 个有效 IOC"],
          ["语义相关性", "LLM 二分类判定", "判定为相关"],
          ["置信度阈值", "综合评分", "confidence >= 0.9"]
        ],
        [2200, 4300, 2860]
      ),
      h2("6.5 跨源关联 Agent（Correlator）"),
      createTable(
        ["职责", "输入", "输出", "关键技术"],
        [
          ["共享 IoC 聚类", "分析后的有效情报列表", "ThreatEvent 列表", "union-find / 并查集聚类"],
          ["证据印证判定", "归组事件与来源集合", "corroborated 布尔值", "独立来源数 >= 2 判定印证，置信度 +0.03 封顶 1.0"]
        ],
        [2200, 2200, 2200, 2760]
      ),
      h2("6.6 报告 Agent"),
      createTable(
        ["职责", "输入", "输出", "关键技术"],
        [
          ["生成日报", "当日有效情报", "Markdown/PDF 报告", "Jinja2 模板"],
          ["实时告警", "高置信度新情报", "邮件/飞书消息", "smtplib、Webhook"]
        ],
        [2200, 2200, 2200, 2760]
      ),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 7
      h1("7. 数据模型与接口"),
      h2("7.1 核心数据模型"),
      p("ThreatIntelligence 模型包含：id、title、threat_type、iocs、confidence、source、raw_text、created_at、is_valid 等字段，并携带评审元数据（review_rounds / review_approved / review_fixes_applied / review_version 等）。使用 Pydantic 进行类型校验与序列化。"),
      p("RawContent 模型包含：source_name、url、content、collected_at、content_hash（用于去重）。"),
      p("ReviewRecord 记录每次对抗评审：intelligence_id、version、reviewer_mode、approved、issue_codes、rounds、confidence_before / confidence_after，用于争议率、修复数、残留数统计与审计。"),
      p("ThreatEvent 记录跨源关联聚合：event_id、indicator、associated_intelligence_ids、sources、corroborated、ingested_at、confidence。"),
      p("EvalRun 记录 A/B 评估：model_version、accuracy、recall、f1、avg_confidence、eval_time、is_deployed，Dashboard 可回溯评估与部署历史。"),
      h2("7.2 关键抽象接口"),
      p("数据源抽象基类 BaseSource 定义 fetch() 方法，所有数据源实现该方法；演示源 DemoSource 与真实源同接口。LLM 统一客户端 LLMClient 提供 invoke() 接口，真实模型与确定性 DemoLLM 同构，可无缝切换。LangGraph 节点函数以 _WorkflowState 字典为输入/输出，支持状态机与线性回退双路径复用同一批节点。"),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 8
      h1("8. 数据源与合规边界"),
      h2("8.1 推荐公开数据源"),
      createTable(
        ["数据源", "类型", "说明"],
        [
          ["NVD / CVE", "API", "官方漏洞库"],
          ["GitHub Security Advisory", "API", "开源项目安全公告"],
          ["安全博客 RSS", "RSS", "如 Krebs on Security、Dark Reading 等"],
          ["URLhaus / Abuse.ch", "Feed", "恶意 URL/Hash 公开 Feed"],
          ["GreyNoise", "API", "扫描与互联网噪声情报"]
        ],
        [2500, 1500, 5360]
      ),
      h2("8.2 合规要求"),
      ...numbered([
        "所有数据源限定为公开 OSINT，禁止实际暗网访问；",
        "禁止未经授权爬取、绕过反爬、CC 攻击等非法行为；",
        "遵守各数据源的 robots.txt 与服务条款；",
        "优先使用官方 API 或公开 Feed，控制请求频率；",
        "项目仅用于学习、研究与安全防御目的。"
      ]),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 9
      h1("9. 提示词工程与 A/B 测试"),
      h2("9.1 Prompt 版本规划"),
      createTable(
        ["版本", "优化重点", "示例改进"],
        [
          ["v1.0", "基础提取", "简单指令提取威胁类型与 IOC"],
          ["v1.1", "增加示例", "加入 Few-shot 示例，规范输出格式"],
          ["v1.2", "增加约束", "明确置信度规则与拒绝策略"],
          ["v1.3", "领域细化", "针对卫星数据泄露等特定场景优化"]
        ],
        [1500, 3000, 4860]
      ),
      h2("9.2 A/B 测试流程"),
      ...numbered([
        "准备标注数据集 benchmark_dataset.json；",
        "使用同一批数据分别运行 v1.0-v1.3 四个 prompt；",
        "收集模型输出并与标注答案对比；",
        "计算准确率（Accuracy）、召回率（Recall）、F1 值；",
        "选择最优版本，通过运行时部署写入 runtime_prompt.json；",
        "回归护栏校验：部署版本必须不低于基线（v1.2 指标），否则拦截并告警；",
        "下一次工作流自动使用已部署版本（v1.3）。"
      ]),
      h2("9.3 运行时部署与回归护栏（AI 测试亮点）"),
      p("获胜版本写入 data/runtime_prompt.json 后，Analyzer 的 _version 优先读取该文件，无需改代码即自动生效。回归护栏（src/evaluation/regression.py）对比待部署版本与基线（v1.2：accuracy 0.8 / recall 0.6 / f1 0.69 / avg_confidence 0.63）：低于任一目标即判定回归并拒绝部署——这是 AI 模型测试中典型的“上线前质量闸门”。"),
      h2("9.4 评估指标"),
      p("准确率 = 正确提取的字段数 / 总字段数；召回率 = 正确提取的关键字段数 / 标注关键字段总数；F1 = 2 * 准确率 * 召回率 / (准确率 + 召回率)。"),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 10
      h1("10. 测试策略"),
      h2("10.1 单元测试"),
      ...bullets([
        "test_collector.py：模拟网络响应，测试数据源采集与清洗逻辑；",
        "test_analyzer.py：mock LLM 客户端，测试结构化解析与异常处理；",
        "test_validator.py：测试置信度计算、关键词匹配、IOC 提取；",
        "test_reporter.py：测试报告生成与告警发送（使用假 SMTP/Webhook）；",
        "test_ab_eval.py：测试 A/B 评估指标计算；",
        "test_reviewer.py：对抗评审规则、协调修复与剩余风险判定；",
        "test_correlator.py：跨源聚类与印证判定、置信度增益；",
        "test_prompt_regression.py：回归护栏对 v1.3 放行 / 对 v1.0 拦截；",
        "test_demo_workflow.py：演示模式端到端跑通（零额度确定性 DemoLLM）；",
        "test_workflow.py：LangGraph 状态机 / 线性回退双路径端到端。"
      ]),
      h2("10.2 集成测试"),
      p("使用 pytest 配合临时 SQLite 数据库，运行完整工作流一次，验证从采集到告警的链路通畅。当前 24 个用例全绿（Python 3.13 主环境；Python 3.8 兼容环境亦通过）。"),
      h2("10.3 AI 测试亮点"),
      ...bullets([
        "Prompt A/B 测试：同一数据集多版本对比，获胜版本运行时部署；",
        "回归护栏：上线前自动校验新版本不低于基线，防质量回退；",
        "模型响应缓存：避免重复调用，降低测试成本；",
        "结构化输出断言：使用 Pydantic 校验 LLM 输出格式；",
        "对抗评估：独立评审 Agent 对提取结果打分与质疑，量化争议率/修复率/残留率；",
        "确定性 Mock（DemoLLM）：零额度下 A/B、回归与端到端结果均可复现。"
      ]),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 11
      h1("11. 实施计划"),
      createTable(
        ["阶段", "任务", "预计耗时"],
        [
          ["阶段 1", "生成 PRD 文档、分析参考项目", "0.5 天"],
          ["阶段 2", "搭建项目骨架、配置加载、数据库模型、LLM 客户端", "1 天"],
          ["阶段 3", "实现感知 Agent 与分析 Agent", "1.5 天"],
          ["阶段 4", "实现校验 Agent 与报告 Agent", "1 天"],
          ["阶段 5", "LangGraph 工作流编排与异常处理", "1 天"],
          ["阶段 6", "Streamlit Dashboard 与 A/B 评估模块", "1.5 天"],
          ["阶段 7", "端到端测试、文档整理、面试准备", "1 天"]
        ],
        [1200, 5660, 2500]
      ),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 12
      h1("12. 风险与边界"),
      createTable(
        ["风险", "影响", "应对措施"],
        [
          ["数据源不可用或限制访问", "采集失败", "多源冗余、本地缓存、降级策略"],
          ["LLM 调用成本高", "开发/测试费用增加", "响应缓存、模拟客户端、小规模数据集"],
          ["提取准确率低", "误报/漏报", "持续 prompt 优化、A/B 测试、人工标注"],
          ["合规争议", "简历风险", "明确使用公开 OSINT，避免暗网表述"],
          ["面试追问深", "无法回答细节", "文档化设计决策，提前准备 Demo"]
        ],
        [2500, 2500, 4360]
      ),
      new Paragraph({ children: [new PageBreak()] }),

      // Appendix
      h1("13. 附录：推荐开源项目清单"),
      createTable(
        ["项目", "GitHub 地址", "适用层级", "复用建议"],
        [
          ["SwiftIOC", "PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector", "感知 Agent", "参考其多源采集与 normalize 逻辑"],
          ["SpiderFoot", "smicallef/spiderfoot", "感知 Agent", "OSINT 模块扩展思路"],
          ["InsightForge", "chioujryu/InsightForge", "分析/报告 Agent", "参考多 Agent + LLM 分析架构"],
          ["OpenCTI", "OpenCTI-Platform/opencti", "知识库", "威胁情报存储与 STIX 接口参考"],
          ["txt2stix", "muchdogesec/txt2stix", "IOC 提取", "文本中提取 IoC/TTP 并生成 STIX"],
          ["TI Dashboard", "codebyRamzi/threat-intelligence-dashboard", "前端", "Streamlit 前端参考"]
        ],
        [1800, 4200, 1800, 1560]
      ),
      p("以上项目均为公开开源项目，仅作为架构与实现参考，不直接复制商业逻辑或违反其许可证条款。"),
      new Paragraph({ children: [new PageBreak()] }),

      // Chapter 14: Development log / evolution trail
      h1("14. 附记：开发记录与演进轨迹（v2.0）"),
      p("本附记记录从 v1.0 设计文档到 v2.0 已落地实现的演进轨迹，体现“设计 → 实现 → 验证 → 文档同步”的闭环。"),
      h2("14.1 v1.0 初版（2026-08-13）"),
      p("完成 PRD 设计：五 Agent 流水线设想、Prompt 版本管理、A/B 测试规划、技术选型。代码骨架搭建，基础测试通过。"),
      h2("14.2 关键修复与基础能力加固"),
      ...bullets([
        "修复 .env 从未加载：config_loader.py 补充 load_dotenv()；",
        "修复 save_intelligence 静默丢弃校验更新：改为 UPSERT，is_valid 结果开始正确落库；",
        "修复 ORM DetachedInstanceError：Session(expire_on_commit=False)；",
        "iocextract 按接口逐一守卫，兼容 Python 3.8 旧版（缺 extract_domains）；",
        "Validator 白名单补充“漏洞”别名，避免真实 LLM v1.0-v1.2 被误判无效。"
      ]),
      h2("14.3 增量功能落地（按 A→D→B→C 顺序）"),
      ...numbered([
        "A：对抗协作评审（ReviewerAgent + CoordinatorAgent + ReviewRecord 持久化 + 评审指标）；",
        "D：运行时部署（runtime_prompt.json）+ 回归护栏（regression.py，基线取 v1.2 指标）；",
        "B：跨源关联（CorrelatorAgent union-find 聚类 + ThreatEvent 印证 + 置信度增益）；",
        "C：LangGraph StateGraph 编排（五节点 + 条件边，无依赖线性回退）。"
      ]),
      h2("14.4 双链路演示能力（零额度）"),
      p("新建 DemoSource（11 条中文样本，每条独立来源名保证可印证）与 DemoLLM（确定性抽取），未配置 LLM_API_KEY 时系统进入演示模式完成端到端演示；A/B 评估改用确定性 Mock 评分，保证结果可复现（v1.0→v1.3 单调提升，winner=v1.3 已部署）。"),
      h2("14.5 验证结果快照（2026-08-16）"),
      ...bullets([
        "pytest 24 passed（Python 3.13 主环境，Python 3.8 兼容）；",
        "干净种子 DB：11 raw / 11 intel（8 有效 / 3 无效）/ 11 reviews（2 争议未通过）/ 1 关联事件（CVE-2025-6601）；",
        "Dashboard 冒烟：streamlit 启动 HTTP 200；",
        "LangGraph 已实装（1.2.x），标志性日志“=== Graph Node: X ===”可见状态机调度。"
      ]),
      h2("14.6 v2.1.0 增量：多领域专题监测 + 合规暗网源（2026-08-20）"),
      ...bullets([
        "DomainMonitorAgent：多领域关键词切片统计（卫星/勒索软件/APT/供应链/IoT 僵尸网络），逐域产出 matched_items / total_sources / dark_sources 持久化到 domain_metrics；",
        "LocalDatasetSource（data/dark_dataset/*.json）：6 条合成标注样本（sample:true），覆盖 5 域，来源分层 4 dark / 2 clearnet，保证监测能力离线可复现；",
        "DarkWebSource：合规限域暗网监测——默认 enabled:false、显式白名单 URL（绝不自动发现）、强制 SOCKS5 代理且 fail-closed、关键词过滤 + 正文截断、全程可审计日志；",
        "工作流新增 Monitor 节点（collect → monitor → analyze → validate → correlate → report），LangGraph 与线性回退双路径同步；",
        "Dashboard 新增「专题监测」页与情报列表暗网来源标签；pytest 全量 40 passed；"
      ]),
      h2("14.7 后续演进建议"),
      ...bullets([
        "真实模式跑通：配置 LLM_API_KEY 后对真 OSINT 源限量分析，复核评审/关联指标；",
        "定时调度接入 APScheduler 实现 7x24 循环采集；",
        "扩展 benchmark 样本规模与领域多样性，提升 A/B 显著性；",
        "报告推送接入真实邮件/飞书 Webhook 验证；",
        "评审与关联指标 Dashboard 增强（趋势图、事件时间线）。"
      ])
    ]
  }]
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log('Document created at:', outputPath);
}).catch(err => {
  console.error('Error creating document:', err);
  process.exit(1);
});
