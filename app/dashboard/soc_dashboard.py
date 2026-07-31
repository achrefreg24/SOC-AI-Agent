"""
soc_dashboard.py
----------------
Enterprise SOC Analytics Dashboard built with Streamlit + Plotly.
Connects to the PostgreSQL database and visualizes AI performance in real-time.

Run with:
    streamlit run soc_dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, text
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from app import database

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC AI Agent Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: linear-gradient(135deg, #1e2130, #252b40);
        border-radius: 12px;
        padding: 20px;
        border-left: 4px solid #4f8ef7;
    }
    .critical-card { border-left-color: #ff4b4b !important; }
    .safe-card     { border-left-color: #00d26a !important; }
    .warn-card     { border-left-color: #ffa726 !important; }
    h1, h2, h3     { color: #e0e0e0; }
    .stMetric label { color: #9aa5b1 !important; }
</style>
""", unsafe_allow_html=True)

# ── DB Connection ─────────────────────────────────────────────────────────────
DB_URL = "postgresql+psycopg2://soc_user:soc_secret@localhost:5432/soc_db"

@st.cache_data(ttl=30)  # Refresh every 30 seconds automatically
def load_data():
    try:
        engine = create_engine(DB_URL)
        df = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp DESC", engine)
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        return df, None
    except Exception as e:
        return pd.DataFrame(), str(e)


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=80)
    st.title("SOC AI Agent")
    st.caption("Real-time Security Analytics")
    st.divider()

    time_filter = st.selectbox(
        "Time Window",
        ["Last 1 Hour", "Last 6 Hours", "Last 24 Hours", "Last 7 Days", "All Time"],
        index=2
    )
    st.divider()
    auto_refresh = st.checkbox("Auto-refresh (30s)", value=True)
    if st.button("🔄 Refresh Now"):
        st.cache_data.clear()

# ── Load Data ─────────────────────────────────────────────────────────────────
df, error = load_data()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ SOC AI Agent — Analytics Dashboard")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if error:
    st.error(f"❌ Cannot connect to PostgreSQL: {error}")
    st.code("docker run --name soc-postgres -e POSTGRES_PASSWORD=soc_secret -e POSTGRES_DB=soc_db -e POSTGRES_USER=soc_user -p 5432:5432 -d postgres:15")
    st.stop()

if df.empty:
    st.warning("⚠️ No alerts in database yet. Run the test script or start the live integration!")
    st.code("python test_blue_team.py")
    st.stop()

# ── Apply Time Filter ─────────────────────────────────────────────────────────
now = datetime.now(timezone.utc)
time_map = {
    "Last 1 Hour":   timedelta(hours=1),
    "Last 6 Hours":  timedelta(hours=6),
    "Last 24 Hours": timedelta(hours=24),
    "Last 7 Days":   timedelta(days=7),
    "All Time":      timedelta(days=36500)
}
df_filtered = df[df["timestamp"] >= (now - time_map[time_filter])].copy()

# ── KPI Metrics Row ───────────────────────────────────────────────────────────
st.subheader("📊 Key Performance Indicators")
col1, col2, col3, col4, col5 = st.columns(5)

total      = len(df_filtered)
critical   = len(df_filtered[df_filtered["ai_classification"].isin(["Critical", "Critique"])])
suspicious = len(df_filtered[df_filtered["ai_classification"].isin(["Suspicious", "Suspect"])])
false_pos  = len(df_filtered[df_filtered["ai_classification"].isin(["False Positive", "Faux positif"])])
avg_conf   = df_filtered["ai_confidence"].mean() if "ai_confidence" in df_filtered and not df_filtered["ai_confidence"].isna().all() else 0

col1.metric("Total Alerts",      total)
col2.metric("🔴 Critical",       critical,   delta=f"{critical/total*100:.0f}%" if total else "0%")
col3.metric("🟠 Suspicious",     suspicious, delta=f"{suspicious/total*100:.0f}%" if total else "0%")
col4.metric("✅ False Positives", false_pos,  delta=f"{false_pos/total*100:.0f}%" if total else "0%")
col5.metric("🎯 Avg Confidence", f"{avg_conf:.1f}%" if avg_conf else "N/A")

st.divider()

# ── Charts Row 1: Timeline + Classification Pie ───────────────────────────────
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("📈 Alert Volume Over Time")
    df_time = df_filtered.copy()
    df_time["hour"] = df_time["timestamp"].dt.floor("h")
    timeline = df_time.groupby(["hour", "ai_classification"]).size().reset_index(name="count")

    color_map = {
        "Critical": "#ff4b4b", "Critique": "#ff4b4b",
        "Suspicious": "#ffa726", "Suspect": "#ffa726",
        "Informational": "#4f8ef7", "Informatif": "#4f8ef7",
        "False Positive": "#00d26a", "Faux positif": "#00d26a"
    }
    fig_timeline = px.bar(
        timeline, x="hour", y="count", color="ai_classification",
        color_discrete_map=color_map,
        title="Alerts per Hour by Classification",
        template="plotly_dark"
    )
    fig_timeline.update_layout(
        plot_bgcolor="#1e2130", paper_bgcolor="#1e2130",
        legend_title_text="Classification"
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

with col_right:
    st.subheader("🥧 Classification Split")
    class_counts = df_filtered["ai_classification"].value_counts().reset_index()
    class_counts.columns = ["Classification", "Count"]
    fig_pie = px.pie(
        class_counts, names="Classification", values="Count",
        color="Classification", color_discrete_map=color_map,
        template="plotly_dark", hole=0.4
    )
    fig_pie.update_layout(paper_bgcolor="#1e2130")
    st.plotly_chart(fig_pie, use_container_width=True)

# ── Charts Row 2: Attack Types + Confidence + MITRE ──────────────────────────
col_a, col_b = st.columns(2)

with col_a:
    st.subheader("⚔️ Top Attack Types")
    attack_counts = df_filtered["ai_attack_type"].dropna().value_counts().head(10).reset_index()
    attack_counts.columns = ["Attack Type", "Count"]
    fig_attacks = px.bar(
        attack_counts, x="Count", y="Attack Type", orientation="h",
        color="Count", color_continuous_scale="Reds",
        template="plotly_dark",
        title="Top 10 Attack Types Detected"
    )
    fig_attacks.update_layout(paper_bgcolor="#1e2130", plot_bgcolor="#1e2130", yaxis=dict(autorange="reversed"))
    st.plotly_chart(fig_attacks, use_container_width=True)

with col_b:
    st.subheader("🎯 AI Confidence Score Distribution")
    if "ai_confidence" in df_filtered.columns and not df_filtered["ai_confidence"].isna().all():
        fig_conf = px.histogram(
            df_filtered.dropna(subset=["ai_confidence"]),
            x="ai_confidence", nbins=20,
            color_discrete_sequence=["#4f8ef7"],
            template="plotly_dark",
            title="LLM Confidence Score Distribution"
        )
        fig_conf.add_vline(x=85, line_dash="dash", line_color="#ff4b4b",
                           annotation_text="Safety Threshold (85%)")
        fig_conf.update_layout(paper_bgcolor="#1e2130", plot_bgcolor="#1e2130")
        st.plotly_chart(fig_conf, use_container_width=True)
    else:
        st.info("Confidence data not available yet.")

# ── MITRE ATT&CK Heatmap ─────────────────────────────────────────────────────
st.subheader("🗺️ MITRE ATT&CK Tactics Distribution")
mitre_counts = df_filtered["mitre_tactic"].dropna().value_counts().reset_index()
mitre_counts.columns = ["Tactic", "Count"]
if not mitre_counts.empty:
    fig_mitre = px.treemap(
        mitre_counts, path=["Tactic"], values="Count",
        color="Count", color_continuous_scale="RdYlGn_r",
        template="plotly_dark",
        title="MITRE ATT&CK Tactics Seen in This Window"
    )
    fig_mitre.update_layout(paper_bgcolor="#1e2130")
    st.plotly_chart(fig_mitre, use_container_width=True)
else:
    st.info("No MITRE data available yet.")

# ── Top Attackers Table ───────────────────────────────────────────────────────
st.subheader("🎯 Top Attacking IPs")
top_ips = (
    df_filtered[df_filtered["src_ip"] != "UNKNOWN"]
    .groupby("src_ip")
    .agg(
        attack_count=("src_ip", "count"),
        classifications=("ai_classification", lambda x: ", ".join(x.unique())),
        last_seen=("timestamp", "max")
    )
    .sort_values("attack_count", ascending=False)
    .head(15)
    .reset_index()
)
st.dataframe(
    top_ips,
    use_container_width=True,
    column_config={
        "src_ip":        st.column_config.TextColumn("Source IP"),
        "attack_count":  st.column_config.NumberColumn("# Attacks", format="%d 🔥"),
        "classifications": st.column_config.TextColumn("Classifications"),
        "last_seen":     st.column_config.DatetimeColumn("Last Seen", format="DD/MM/YY HH:mm"),
    }
)

# ── Raw Data Explorer ─────────────────────────────────────────────────────────
with st.expander("📋 Raw Alert Log (Last 50 alerts)"):
    st.dataframe(
        df_filtered.head(50)[[
            "timestamp", "src_ip", "description", "ai_classification",
            "ai_attack_type", "ai_confidence", "mitre_tactic", "action_executed"
        ]],
        use_container_width=True
    )
