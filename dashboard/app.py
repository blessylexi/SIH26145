"""
SIH 2026 - Behavioral Threat Monitor
Presentation-ready Streamlit dashboard.

The dashboard uses the existing detection pipeline:
    Behavioral Features
        -> Baseline Detector
        -> Ghost Response Model
        -> Score Fusion

All demo scenarios are controlled synthetic behavioral samples.
"""

from pathlib import Path
import sys

import streamlit as st


# ---------------------------------------------------------------------
# Project import path
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from src.detection.baseline_detector import detect_baseline_anomaly
from src.detection.ghost_response import ghost_response
from src.detection.score_fusion import fuse_scores


# ---------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------

st.set_page_config(
    page_title="Behavioral Threat Monitor | SIH 2026",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------

st.markdown(
    """
    <style>
        .stApp {
            background: #07090d;
        }

        [data-testid="stHeader"] {
            background: rgba(0, 0, 0, 0);
        }

        [data-testid="stSidebar"] {
            background: #0b0e14;
            border-right: 1px solid #252b36;
        }

        [data-testid="stSidebar"] > div:first-child {
            padding-top: 1.5rem;
        }

        .main-title {
            font-size: 2.65rem;
            font-weight: 800;
            letter-spacing: -0.04em;
            margin-bottom: 0.15rem;
        }

        .subtitle {
            color: #9ca7b5;
            font-size: 1.02rem;
            margin-bottom: 1.2rem;
        }

        .eyebrow {
            color: #7f8a99;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.14em;
            text-transform: uppercase;
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 750;
            margin-top: 1.2rem;
            margin-bottom: 0.65rem;
        }

        .status-strip {
            border: 1px solid #29313d;
            background: #0c1017;
            border-radius: 12px;
            padding: 0.8rem 1rem;
            margin-bottom: 1.25rem;
        }

        .status-dot {
            display: inline-block;
            width: 9px;
            height: 9px;
            border-radius: 50%;
            background: #4ade80;
            margin-right: 8px;
        }

        .status-text {
            color: #cbd5e1;
            font-size: 0.9rem;
        }

        .hero-card {
            border: 1px solid #303846;
            background: linear-gradient(135deg, #0d121a, #090c12);
            border-radius: 16px;
            padding: 1.1rem 1.2rem;
            margin-bottom: 1rem;
        }

        .hero-label {
            color: #8e99a8;
            font-size: 0.76rem;
            font-weight: 700;
            letter-spacing: 0.11em;
            text-transform: uppercase;
        }

        .hero-score {
            font-size: 3.4rem;
            font-weight: 850;
            line-height: 1;
            margin: 0.35rem 0;
        }

        .hero-classification {
            font-size: 1.05rem;
            font-weight: 700;
        }

        .hero-note {
            color: #8e99a8;
            font-size: 0.82rem;
            margin-top: 0.25rem;
        }

        .pipeline {
            border: 1px solid #2a313d;
            background: #0b0f15;
            border-radius: 14px;
            padding: 1rem;
        }

        .pipeline-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .pipeline-node {
            border: 1px solid #303846;
            background: #10151d;
            border-radius: 10px;
            padding: 0.55rem 0.75rem;
            font-size: 0.84rem;
            font-weight: 650;
            text-align: center;
        }

        .pipeline-arrow {
            color: #677384;
            font-size: 1.1rem;
        }

        .evidence-card {
            border: 1px solid #2a313d;
            background: #0b0f15;
            border-radius: 12px;
            padding: 0.8rem 0.9rem;
            margin-bottom: 0.55rem;
        }

        .evidence-source {
            color: #aab4c1;
            font-size: 0.72rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 0.2rem;
        }

        .evidence-text {
            color: #e5e7eb;
            font-size: 0.9rem;
        }

        .explain-box {
            border: 1px solid #303846;
            background: #0c1017;
            border-radius: 14px;
            padding: 1rem 1.1rem;
            line-height: 1.55;
        }

        .demo-note {
            color: #7f8a99;
            font-size: 0.75rem;
            line-height: 1.45;
            margin-top: 0.8rem;
        }

        .feature-name {
            color: #d7dee8;
            font-weight: 650;
        }

        .small-muted {
            color: #7f8a99;
            font-size: 0.78rem;
        }

        footer {
            visibility: hidden;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Controlled synthetic scenarios
# ---------------------------------------------------------------------

SCENARIOS = {
    "Normal": {
        "description": "Expected baseline traffic with stable interaction behavior.",
        "behavior": {
            "packets_per_second": 10.0,
            "bytes_per_second": 5000.0,
            "syn_ratio": 0.10,
            "unique_destination_ips": 3.0,
            "unique_destination_ports": 5.0,
            "source_ip_entropy": 1.0,
            "destination_concentration": 0.70,
            "average_packet_size": 500.0,
            "average_inter_arrival": 0.10,
            "tcp_ratio": 0.70,
            "udp_ratio": 0.30,
        },
    },
    "Mild Deviation": {
        "description": "Small behavioral drift that should not automatically become a high-severity alert.",
        "behavior": {
            "packets_per_second": 15.0,
            "bytes_per_second": 7500.0,
            "syn_ratio": 0.18,
            "unique_destination_ips": 5.0,
            "unique_destination_ports": 8.0,
            "source_ip_entropy": 1.30,
            "destination_concentration": 0.60,
            "average_packet_size": 600.0,
            "average_inter_arrival": 0.07,
            "tcp_ratio": 0.75,
            "udp_ratio": 0.25,
        },
    },
    "Suspicious": {
        "description": "Multiple features move away from the expected behavioral profile.",
        "behavior": {
            "packets_per_second": 40.0,
            "bytes_per_second": 20000.0,
            "syn_ratio": 0.45,
            "unique_destination_ips": 10.0,
            "unique_destination_ports": 25.0,
            "source_ip_entropy": 2.50,
            "destination_concentration": 0.30,
            "average_packet_size": 850.0,
            "average_inter_arrival": 0.025,
            "tcp_ratio": 0.90,
            "udp_ratio": 0.10,
        },
    },
    "SYN Heavy": {
        "description": "Traffic dominated by SYN activity and elevated packet rate.",
        "behavior": {
            "packets_per_second": 60.0,
            "bytes_per_second": 30000.0,
            "syn_ratio": 0.90,
            "unique_destination_ips": 4.0,
            "unique_destination_ports": 8.0,
            "source_ip_entropy": 1.00,
            "destination_concentration": 0.75,
            "average_packet_size": 500.0,
            "average_inter_arrival": 0.0167,
            "tcp_ratio": 0.98,
            "udp_ratio": 0.02,
        },
    },
    "Port Scan Like": {
        "description": "A controlled scan-like pattern with high destination-port diversity.",
        "behavior": {
            "packets_per_second": 22.0,
            "bytes_per_second": 11000.0,
            "syn_ratio": 1.00,
            "unique_destination_ips": 1.0,
            "unique_destination_ports": 22.0,
            "source_ip_entropy": 0.00,
            "destination_concentration": 1.00,
            "average_packet_size": 500.0,
            "average_inter_arrival": 0.045,
            "tcp_ratio": 0.95,
            "udp_ratio": 0.05,
        },
    },
    "High Rate": {
        "description": "Elevated packet and byte rates with compressed inter-arrival time.",
        "behavior": {
            "packets_per_second": 100.0,
            "bytes_per_second": 50000.0,
            "syn_ratio": 0.20,
            "unique_destination_ips": 5.0,
            "unique_destination_ports": 6.0,
            "source_ip_entropy": 1.00,
            "destination_concentration": 0.70,
            "average_packet_size": 500.0,
            "average_inter_arrival": 0.01,
            "tcp_ratio": 0.70,
            "udp_ratio": 0.30,
        },
    },
    "Low Concentration": {
        "description": "Traffic spread across many destinations rather than concentrated on the usual targets.",
        "behavior": {
            "packets_per_second": 25.0,
            "bytes_per_second": 12500.0,
            "syn_ratio": 0.15,
            "unique_destination_ips": 20.0,
            "unique_destination_ports": 8.0,
            "source_ip_entropy": 3.00,
            "destination_concentration": 0.10,
            "average_packet_size": 500.0,
            "average_inter_arrival": 0.04,
            "tcp_ratio": 0.70,
            "udp_ratio": 0.30,
        },
    },
    "Combined Abnormal": {
        "description": "Multiple abnormal dimensions appear together, producing the strongest controlled demonstration.",
        "behavior": {
            "packets_per_second": 80.0,
            "bytes_per_second": 40000.0,
            "syn_ratio": 0.85,
            "unique_destination_ips": 20.0,
            "unique_destination_ports": 30.0,
            "source_ip_entropy": 3.00,
            "destination_concentration": 0.15,
            "average_packet_size": 900.0,
            "average_inter_arrival": 0.0125,
            "tcp_ratio": 0.95,
            "udp_ratio": 0.05,
        },
    },
}


FEATURE_LABELS = {
    "packets_per_second": "Packets / second",
    "bytes_per_second": "Bytes / second",
    "syn_ratio": "SYN ratio",
    "unique_destination_ips": "Unique destination IPs",
    "unique_destination_ports": "Unique destination ports",
    "source_ip_entropy": "Source IP entropy",
    "destination_concentration": "Destination concentration",
    "average_packet_size": "Average packet size",
    "average_inter_arrival": "Average inter-arrival",
    "tcp_ratio": "TCP ratio",
    "udp_ratio": "UDP ratio",
}


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------

def pct(value):
    return f"{float(value) * 100:.1f}%"


def format_feature_value(name, value):
    if name == "packets_per_second":
        return f"{value:.1f} pkt/s"
    if name == "bytes_per_second":
        return f"{value:.1f} B/s"
    if name in {"syn_ratio", "tcp_ratio", "udp_ratio", "destination_concentration"}:
        return f"{value:.2f}"
    if name == "average_inter_arrival":
        return f"{value:.4f} s"
    if name == "average_packet_size":
        return f"{value:.1f} B"
    if name == "source_ip_entropy":
        return f"{value:.2f}"
    return f"{value:.0f}"


def severity_word(severity):
    return {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO",
    }.get(severity, str(severity))


def build_clean_explanation(fusion_result):
    """Create a concise, presentation-friendly explanation."""
    classification = fusion_result.get("classification", "Unknown")
    threat_score = float(fusion_result.get("final_threat_score", 0.0))
    baseline_score = float(fusion_result.get("baseline_score", 0.0))
    ghost_deviation = float(fusion_result.get("ghost_deviation", 0.0))
    evidence = fusion_result.get("evidence", [])

    if not evidence:
        return (
            f"{classification}. "
            f"Final threat score={threat_score:.2f}. "
            f"Baseline anomaly={baseline_score:.2f}. "
            f"Ghost deviation={ghost_deviation:.2f}. "
            "No significant behavioral deviations were detected."
        )

    baseline_count = sum(
        1 for item in evidence
        if item.get("source") == "Baseline"
    )
    ghost_count = sum(
        1 for item in evidence
        if item.get("source") == "Ghost Response"
    )

    baseline_word = (
        "behavioral deviation"
        if baseline_count == 1
        else "behavioral deviations"
    )
    ghost_word = (
        "Ghost behavioral inconsistency"
        if ghost_count == 1
        else "Ghost behavioral inconsistencies"
    )

    reasons = []
    if baseline_count:
        reasons.append(f"{baseline_count} baseline {baseline_word}")
    if ghost_count:
        reasons.append(f"{ghost_count} {ghost_word}")

    reason_text = " and ".join(reasons)

    return (
        f"{classification}. "
        f"Final threat score={threat_score:.2f}. "
        f"Baseline anomaly={baseline_score:.2f}. "
        f"Ghost deviation={ghost_deviation:.2f}. "
        f"Detection was supported by {reason_text}."
    )


def render_evidence(evidence):
    if not evidence:
        st.markdown(
            """
            <div class="evidence-card">
                <div class="evidence-text">
                    No significant behavioral deviations were detected.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    for item in evidence:
        source = item.get("source", "Detector")
        description = item.get("description", "Behavioral deviation detected.")

        st.markdown(
            f"""
            <div class="evidence-card">
                <div class="evidence-source">{source}</div>
                <div class="evidence-text">{description}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------

with st.sidebar:
    st.markdown("## CONTROLLED DEMO")
    st.caption("SIH 2026 behavioral threat detection prototype")

    scenario_name = st.selectbox(
        "Select traffic scenario",
        list(SCENARIOS.keys()),
        index=0,
    )

    st.divider()

    st.markdown("### Detection pipeline")

    st.markdown(
        """
        **1. Behavioral Features**  
        Extracted traffic behavior

        **2. Baseline Detector**  
        Measures deviation from normal profile

        **3. Ghost Response Model**  
        Measures counterfactual behavioral mismatch

        **4. Score Fusion**  
        Combines both signals into one threat score
        """
    )

    st.divider()

    st.markdown("### Score interpretation")
    st.caption("0–19%  → Normal")
    st.caption("20–44% → Low Suspicion")
    st.caption("45–74% → Moderate Threat")
    st.caption("75–100% → High Threat")

    st.markdown(
        """
        <div class="demo-note">
            Demo scenarios are controlled synthetic behavioral samples.
            They demonstrate the detection pipeline and explainability;
            they are not a claim of real-world attack accuracy.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------
# Run actual detection pipeline
# ---------------------------------------------------------------------

scenario = SCENARIOS[scenario_name]
behavior = scenario["behavior"]

baseline_result = detect_baseline_anomaly(behavior)
ghost_result = ghost_response(behavior)
fusion_result = fuse_scores(
    baseline_result,
    ghost_result,
)


final_score = float(fusion_result.get("final_threat_score", 0.0))
baseline_score = float(fusion_result.get("baseline_score", 0.0))
ghost_deviation = float(fusion_result.get("ghost_deviation", 0.0))
ghost_consistency = float(
    ghost_result.get("ghost_consistency", 1.0)
)
baseline_confidence = float(
    baseline_result.get("confidence", 0.0)
)


# ---------------------------------------------------------------------
# Main header
# ---------------------------------------------------------------------

st.markdown(
    """
    <div class="eyebrow">SIH 2026 • Behavioral Network Security</div>
    <div class="main-title">🛡️ Behavioral Threat Monitor</div>
    <div class="subtitle">
        Baseline Detection + Ghost Response + Explainable Score Fusion
    </div>

    <div class="status-strip">
        <span class="status-dot"></span>
        <span class="status-text">
            Detection pipeline operational • Controlled demonstration mode
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Scenario description
# ---------------------------------------------------------------------

st.markdown(
    f"""
    <div class="hero-card">
        <div class="hero-label">Current traffic scenario</div>
        <div style="font-size:1.45rem;font-weight:800;margin-top:0.25rem;">
            {scenario_name}
        </div>
        <div class="hero-note">{scenario["description"]}</div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Threat assessment
# ---------------------------------------------------------------------

st.markdown(
    '<div class="section-title">THREAT ASSESSMENT</div>',
    unsafe_allow_html=True,
)

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown(
        f"""
        <div class="hero-card" style="height:100%;">
            <div class="hero-label">Final threat score</div>
            <div class="hero-score">{pct(final_score)}</div>
            <div class="hero-classification">
                {fusion_result.get("classification", "Unknown")}
            </div>
            <div class="hero-note">Score Fusion Decision</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c2:
    st.markdown(
        f"""
        <div class="hero-card" style="height:100%;">
            <div class="hero-label">Severity</div>
            <div class="hero-score" style="font-size:2.5rem;">
                {severity_word(fusion_result.get("severity", "INFO"))}
            </div>
            <div class="hero-classification">
                Behavioral risk level
            </div>
            <div class="hero-note">
                Final classification is derived from the fused score.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c3:
    st.markdown(
        f"""
        <div class="hero-card" style="height:100%;">
            <div class="hero-label">Baseline confidence</div>
            <div class="hero-score">{pct(baseline_confidence)}</div>
            <div class="hero-classification">
                {baseline_result.get("severity", "INFO")}
            </div>
            <div class="hero-note">
                Confidence reported by the baseline detector.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------
# Behavioral signal cards
# ---------------------------------------------------------------------

st.markdown(
    '<div class="section-title">BEHAVIORAL ANALYSIS</div>',
    unsafe_allow_html=True,
)

b1, b2, b3 = st.columns(3)

with b1:
    st.metric(
        "Baseline anomaly",
        pct(baseline_score),
        help="Deviation from the normal behavioral baseline.",
    )

with b2:
    st.metric(
        "Ghost deviation",
        pct(ghost_deviation),
        help="Counterfactual mismatch with the expected interaction pattern.",
    )

with b3:
    st.metric(
        "Ghost consistency",
        pct(ghost_consistency),
        help="Expected behavioral consistency; lower means stronger mismatch.",
    )


# ---------------------------------------------------------------------
# Pipeline visualization
# ---------------------------------------------------------------------

st.markdown(
    '<div class="section-title">DETECTION PIPELINE</div>',
    unsafe_allow_html=True,
)

st.markdown(
    f"""
    <div class="pipeline">
        <div class="pipeline-row">
            <div class="pipeline-node">Behavioral Features</div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-node">Baseline<br><b>{pct(baseline_score)}</b></div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-node">Ghost Response<br><b>{pct(ghost_deviation)}</b></div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-node">Score Fusion<br><b>55% + 45%</b></div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-node">FINAL<br><b>{pct(final_score)}</b></div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Explainability
# ---------------------------------------------------------------------

st.markdown(
    '<div class="section-title">WHY WAS THIS FLAGGED?</div>',
    unsafe_allow_html=True,
)

explanation = build_clean_explanation(fusion_result)

st.markdown(
    f"""
    <div class="explain-box">
        {explanation}
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("#### Detection evidence")
render_evidence(fusion_result.get("evidence", []))


# ---------------------------------------------------------------------
# Observed behavior
# ---------------------------------------------------------------------

st.markdown(
    '<div class="section-title">OBSERVED BEHAVIOR</div>',
    unsafe_allow_html=True,
)

feature_names = list(behavior.keys())

for start in range(0, len(feature_names), 3):
    cols = st.columns(3)

    for col, feature_name in zip(
        cols,
        feature_names[start:start + 3],
    ):
        with col:
            st.metric(
                FEATURE_LABELS.get(feature_name, feature_name),
                format_feature_value(
                    feature_name,
                    behavior[feature_name],
                ),
            )


# ---------------------------------------------------------------------
# Ghost feature analysis
# ---------------------------------------------------------------------

with st.expander("Ghost Response — feature-level analysis"):
    feature_results = ghost_result.get("feature_results", {})

    if not feature_results:
        st.info("No Ghost feature results are available.")
    else:
        for feature_name, result in feature_results.items():
            observed = result.get("observed", 0.0)
            expected = result.get("expected", 0.0)
            deviation = result.get("deviation", 0.0)
            consistency = result.get("consistency", 0.0)

            st.markdown(
                f"**{FEATURE_LABELS.get(feature_name, feature_name)}**"
            )

            g1, g2, g3, g4 = st.columns(4)

            with g1:
                st.caption("Observed")
                st.write(format_feature_value(feature_name, observed))

            with g2:
                st.caption("Expected")
                st.write(format_feature_value(feature_name, expected))

            with g3:
                st.caption("Normalized deviation")
                st.write(f"{deviation:.2f}")

            with g4:
                st.caption("Consistency")
                st.write(f"{consistency * 100:.1f}%")

            st.divider()


# ---------------------------------------------------------------------
# Before vs After experiment
# ---------------------------------------------------------------------

st.markdown(
    '<div class="section-title">CONTROLLED BEFORE vs AFTER EXPERIMENT</div>',
    unsafe_allow_html=True,
)

st.caption(
    "Synthetic multi-sample evaluation already run against the prototype. "
    "This compares baseline-only scoring with baseline + Ghost + fusion."
)

e1, e2, e3 = st.columns(3)

with e1:
    st.metric(
        "Baseline separation",
        "0.6109",
    )

with e2:
    st.metric(
        "Baseline + Ghost separation",
        "0.6388",
        delta="+0.0279",
    )

with e3:
    st.metric(
        "Relative separation change",
        "+4.6%",
    )

st.info(
    "Interpretation: on the controlled synthetic sample set, the fused "
    "pipeline produced greater separation between the normal and "
    "suspicious/attack-like groups. This is a prototype experiment, not "
    "a real-world accuracy measurement."
)


# ---------------------------------------------------------------------
# Architecture explanation
# ---------------------------------------------------------------------

with st.expander("How the detection architecture works"):
    a1, a2, a3, a4 = st.columns(4)

    with a1:
        st.markdown("**1. Behavioral Features**")
        st.caption(
            "Represents traffic as measurable behavior such as packet rate, "
            "byte rate, SYN ratio, destination diversity and concentration."
        )

    with a2:
        st.markdown("**2. Baseline Detector**")
        st.caption(
            "Measures how far the observed behavior moves from the expected "
            "normal-traffic profile."
        )

    with a3:
        st.markdown("**3. Ghost Response**")
        st.caption(
            "Measures whether the observed interaction remains consistent "
            "with the expected behavioral response."
        )

    with a4:
        st.markdown("**4. Score Fusion**")
        st.caption(
            "Combines the baseline anomaly and Ghost counterfactual "
            "deviation into one explainable threat score."
        )


# ---------------------------------------------------------------------
# Technical details
# ---------------------------------------------------------------------

with st.expander("Technical detection details"):
    st.write(
        {
            "Scenario": scenario_name,
            "Final threat score": final_score,
            "Baseline anomaly": baseline_score,
            "Ghost deviation": ghost_deviation,
            "Ghost consistency": ghost_consistency,
            "Baseline confidence": baseline_confidence,
            "Baseline weight": fusion_result.get("baseline_weight"),
            "Ghost weight": fusion_result.get("ghost_weight"),
            "Classification": fusion_result.get("classification"),
            "Severity": fusion_result.get("severity"),
        }
    )


# ---------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------

st.markdown("---")

st.markdown(
    """
    <div style="text-align:center;color:#6f7a89;font-size:0.75rem;">
        SIH 2026 • Behavioral Threat Monitor • Controlled synthetic prototype
    </div>
    """,
    unsafe_allow_html=True,
)
