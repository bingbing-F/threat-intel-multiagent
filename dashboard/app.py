"""Streamlit dashboard for the threat intelligence system."""
import json
import os
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config_loader import get_settings
from src.evaluation.ab_tester import ABTester
from src.evaluation.regression import run_regression
from src.evaluation.runtime import load_active_version, save_active_version
from src.graph.workflow import ThreatIntelWorkflow
from src.storage.db import Database, init_db

# Page config
st.set_page_config(
    page_title="威胁情报监控系统",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def has_api_key() -> bool:
    settings = get_settings()
    return bool(settings.get("llm.api_key") or os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY"))


# Dark theme custom CSS
st.markdown(
    """
    <style>
    .stApp {
        background-color: #0B1120;
        color: #F9FAFB;
    }
    .metric-card {
        background: rgba(31, 41, 55, 0.7);
        border-radius: 12px;
        padding: 20px;
        border: 1px solid rgba(75, 85, 99, 0.4);
        backdrop-filter: blur(10px);
    }
    .metric-value {
        font-size: 32px;
        font-weight: 700;
        color: #06B6D4;
    }
    .metric-label {
        font-size: 14px;
        color: #9CA3AF;
    }
    h1, h2, h3 {
        color: #F9FAFB !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_database():
    init_db()
    return Database()


def render_overview(db: Database):
    st.title("🛡️ 威胁情报监控总览")

    total = db.count_intelligence()
    valid = db.count_intelligence(is_valid=True)
    invalid = db.count_intelligence(is_valid=False)
    raw_total = db.count_raw_contents()
    events_total = db.count_events()
    events_corroborated = db.count_events(corroborated=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            f'<div class="metric-card"><div class="metric-value">{total}</div><div class="metric-label">总情报数</div></div>',
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f'<div class="metric-card"><div class="metric-value">{valid}</div><div class="metric-label">有效情报</div></div>',
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f'<div class="metric-card"><div class="metric-value">{invalid}</div><div class="metric-label">待复核</div></div>',
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f'<div class="metric-card"><div class="metric-value">{raw_total}</div><div class="metric-label">已采集原文</div></div>',
            unsafe_allow_html=True,
        )

    st.divider()

    events = db.list_events(limit=20)
    if events:
        st.subheader(f"🕸️ 跨源关联事件（{events_total}，印证 {events_corroborated}）")
        ev_rows = []
        for ev in events:
            ev_rows.append(
                {
                    "事件": ev.title,
                    "关联情报数": len(ev.intel_ids),
                    "独立来源数": ev.source_count,
                    "关键指标": ", ".join(ev.key_indicators[:4]) or "-",
                    "置信度": f"{ev.confidence:.2f}",
                    "印证": "✅多源印证" if ev.corroborated else "单源",
                    "最近时间": ev.last_seen.strftime("%m-%d %H:%M"),
                }
            )
        st.dataframe(pd.DataFrame(ev_rows), use_container_width=True)

    items = db.list_intelligence(is_valid=True, limit=50)
    if items:
        df = pd.DataFrame(
            [
                {
                    "时间": item.created_at,
                    "置信度": item.confidence,
                    "类型": item.threat_type,
                    "来源": item.source,
                }
                for item in items
            ]
        )
        st.subheader("最近有效情报置信度")
        st.line_chart(df.set_index("时间")["置信度"])

        st.subheader("威胁类型分布")
        type_counts = df["类型"].value_counts()
        st.bar_chart(type_counts)
    else:
        st.info("暂无情报入库。请前往「运行工作流」页面运行一次演示或真实工作流后刷新查看。")


def render_intelligence(db: Database):
    st.title("📋 情报列表")

    col1, col2 = st.columns([1, 3])
    with col1:
        status = st.selectbox("状态", ["全部", "有效", "待复核"])
    with col2:
        threat_type = st.text_input("威胁类型过滤", "")

    is_valid = None if status == "全部" else (status == "有效")
    items = db.list_intelligence(is_valid=is_valid, limit=200)

    if threat_type:
        items = [item for item in items if threat_type.lower() in item.threat_type.lower()]

    if not items:
        st.info("没有匹配的情报")
        return

    data = []
    for item in items:
        data.append(
            {
                "标题": item.title,
                "类型": item.threat_type,
                "IoC": ", ".join(item.iocs_json) or "-",
                "置信度": f"{item.confidence:.2f}",
                "来源": item.source,
                "时间": item.created_at.strftime("%Y-%m-%d %H:%M"),
                "有效": "✅" if item.is_valid else "❌",
            }
        )
    st.dataframe(pd.DataFrame(data), use_container_width=True)

    with st.expander("查看校验原因"):
        for item in items:
            st.markdown(f"**{item.title}** — {item.validation_reason or '（无）'}")


def render_evaluation(db: Database, demo_mode: bool):
    st.title("🧪 Prompt A/B 评估")

    active = load_active_version()
    st.caption(f"运行时生效提示词版本：`{active or '未部署（默认使用最新版本）'}`")

    if demo_mode:
        st.info("当前处于演示模式：使用确定性模拟评分评估提示词版本，无需 LLM API。")
    else:
        st.warning("真实评估会对每个版本的基准样本调用大模型，结合 LLM 缓存复用可降低成本。")

    benchmark_path = st.text_input("Benchmark 路径", "data/benchmark_dataset.json")

    c1, c2 = st.columns([1, 1])
    with c1:
        run = st.button("运行 A/B 评估", type="primary", disabled=(not demo_mode and not has_api_key()))
    if not demo_mode and not has_api_key():
        st.error("未配置 LLM API Key。请设置 .env 中的 LLM_API_KEY 后启用真实评估，或切换演示模式。")

    if run:
        with st.spinner("正在评估各版本提示词..."):
            tester = ABTester(mock_mode=demo_mode)
            try:
                result = tester.evaluate(benchmark_path)
            except Exception as e:
                st.error(f"评估失败：{e}")
                return

        st.success(f"评估完成，最佳版本：{result.winner}")

        metrics_data = []
        for version, metrics in result.results.items():
            metrics_data.append(
                {
                    "版本": version,
                    "准确率": metrics.accuracy,
                    "召回率": metrics.recall,
                    "F1": metrics.f1,
                    "平均置信度": metrics.avg_confidence,
                    "样本数": metrics.samples_count,
                }
            )
        df = pd.DataFrame(metrics_data)
        st.dataframe(df, use_container_width=True)
        st.bar_chart(df.set_index("版本")[["准确率", "召回率", "F1"]])

        # Save result to JSON (kept for backward compat) and to database.
        output_path = Path("data/ab_eval_result.json")
        output_path.write_text(
            json.dumps(
                {
                    "winner": result.winner,
                    "notes": result.notes,
                    "results": {v: m.model_dump() for v, m in result.results.items()},
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        record_id = db.save_evaluation_record(result)
        st.info(f"结果已保存到 {output_path}（DB 记录 id: {record_id}）")

        st.divider()
        dep1, dep2 = st.columns(2)
        with dep1:
            if st.button(f"🚀 将 {result.winner} 设为生产默认版本"):
                save_active_version(result.winner)
                st.success(f"已部署 {result.winner}，运行时分析将使用该提示词版本")
        with dep2:
            if st.button("🛡️ 运行回归护栏检查", disabled=not demo_mode and not has_api_key()):
                report = run_regression(version=result.winner, mock_mode=demo_mode)
                st.success(f"回归护栏：{'✅ PASS' if report.passed else '⛔ FAIL'}（{report.version}）")
                st.code(report.summary)

    st.divider()
    st.subheader("历次评估记录")
    records = db.list_evaluation_records(limit=10)
    if records:
        for rec in records:
            st.markdown(
                f"- **{rec.run_at.strftime('%Y-%m-%d %H:%M')}** · {rec.benchmark_path} · "
                f"winner: `{rec.winner}` — {rec.notes}"
            )
    else:
        st.caption("暂无评估记录，运行一次评估后写入。")

    if Path("data/ab_eval_result.json").exists():
        st.divider()
        with st.expander("最近一次本地结果（data/ab_eval_result.json）"):
            st.json(json.loads(Path("data/ab_eval_result.json").read_text(encoding="utf-8")))


def render_run_workflow(db: Database, demo_mode: bool):
    st.title("▶️ 运行工作流")

    active = load_active_version()
    st.caption(f"运行时生效提示词版本：`{active or '未部署（默认使用最新版本）'}`   ·   "
               f"对抗协作评审：分析 → 独立评审 → 协调修复 → 再校验")

    real_ready = has_api_key()
    send_alerts = False
    generate_report = True

    if demo_mode:
        st.info("演示模式：使用Deterministic DemoLLM 跑完整链路（采集→分析→校验→报告→入库），无需 LLM API。")
        run = st.button("运行演示工作流（无需 LLM API）", type="primary")
        limit = None
    else:
        if not real_ready:
            st.error("未配置 LLM API Key。请设置 .env 中的 LLM_API_KEY 后启用真实模式，或切换回演示模式。")
            return
        st.success("真实模式：使用真实 LLM 分析实时 OSINT 源。建议先设置条数上限控制成本。")
        cola, colb = st.columns([1, 2])
        with cola:
            limit = st.number_input("本次分析条数上限（控成本）", min_value=1, max_value=200, value=5)
        with colb:
            send_alerts = st.toggle("发送告警", value=False)
            generate_report = st.toggle("生成日报", value=True)
        run = st.button("执行一次完整工作流（真实 LLM）", type="primary")

    if run:
        with st.spinner("正在运行..."
                        if demo_mode
                        else "正在运行（真实 LLM，可能需要较长时间）..."):
            workflow = ThreatIntelWorkflow(demo=demo_mode)
            result = workflow.run(
                send_alerts=send_alerts,
                generate_report=generate_report,
                limit=limit,
            )

        st.success(f"工作流执行完成{'（演示模式）' if demo_mode else '（真实模式）'}")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("原始情报", result.raw_count)
        with col2:
            st.metric("分析成功", result.analyzed_count)
        with col3:
            st.metric("有效", result.valid_count)
        with col4:
            st.metric("待复核", result.invalid_count)

        if result.analyzed_count:
            st.divider()
            st.subheader("🕵️ 对抗协作评审（Analyzer ↔ Reviewer ↔ Coordinator）")
            r1, r2, r3, r4 = st.columns(4)
            with r1:
                st.metric("评审条数", result.reviews_persisted)
            with r2:
                st.metric("争议率（被标记）", result.review_flagged)
            with r3:
                st.metric("已修复问题", result.review_resolved_fixes)
            with r4:
                st.metric("修复后仍待复核", result.review_residual)

            st.subheader("🕸️ 跨源关联（Correlator）")
            e1, e2, e3 = st.columns(3)
            with e1:
                st.metric("关联事件", result.event_count)
            with e2:
                st.metric("多源印证事件", result.corroborated_events)
            with e3:
                st.metric("待复核（未印证）", result.event_count - result.corroborated_events)

        # Adversarial review detail from the freshly persisted records.
        review_rows = db.list_reviews(limit=result.analyzed_count)
        if review_rows:
            with st.expander("评审明细（争议条目）"):
                for rec in review_rows:
                    if rec.approved:
                        continue
                    codes = ", ".join(rec.issue_codes) or "-"
                    st.markdown(
                        f"- {rec.intelligence_id[:8]} · `{codes}` · "
                        f"置信度 {rec.confidence_before:.2f} → {rec.confidence_after:.2f} · "
                        f"rounds={rec.rounds} · {'通过' if rec.approved else '未通过'}"
                    )

        if result.valid_items:
            with st.expander("📄 生成的当日日报（Markdown）", expanded=True):
                report_md = workflow.reporter.generate_daily_report(result.valid_items)
                st.markdown(report_md)
        elif result.analyzed_count:
            st.info("本次无有效情报（置信度未达阈值或 IoC 过少）。")

        if result.errors:
            with st.expander("错误详情"):
                for err in result.errors:
                    st.error(err)


def main():
    db = get_database()

    st.sidebar.title("导航")

    api_ready = has_api_key()
    if api_ready:
        st.sidebar.success("已检测到 LLM API Key，可运行真实模式。")
    else:
        st.sidebar.warning("未检测到 LLM API Key，已默认开启演示模式（无需额度）。")

    demo_mode = st.sidebar.toggle("演示模式（无需 LLM API）", value=not api_ready)

    with st.sidebar.expander("运行模式说明", expanded=False):
        st.markdown(
            """
- **演示模式**：Deterministic DemoLLM 提取 + 真实校验/报告/入库，端到端无需 API。
- **真实模式**：真实大模型分析 NVD/GitHub/Krebs 等 OSINT 源，可设条数上限控成本。
- 配置 `.env` 的 `LLM_API_KEY` 后自动出现真实模式选项。
            """
        )

    page = st.sidebar.radio(
        "选择页面",
        ["总览", "情报列表", "A/B 评估", "运行工作流"],
    )

    if page == "总览":
        render_overview(db)
    elif page == "情报列表":
        render_intelligence(db)
    elif page == "A/B 评估":
        render_evaluation(db, demo_mode)
    elif page == "运行工作流":
        render_run_workflow(db, demo_mode)


if __name__ == "__main__":
    main()