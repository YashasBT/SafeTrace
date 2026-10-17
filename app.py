import os, json
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from safetrace.sanitizer import sanitize
from safetrace.pseudonymizer import Pseudonymizer
from safetrace.canary import generate_canaries, evaluate_canaries
from safetrace.benchmark import run_benchmark
from safetrace.ml_detector import detect_candidates, model_status

ROOT=Path(__file__).resolve().parent
st.set_page_config(page_title="SafeTrace Ultra",page_icon="◈",layout="wide",initial_sidebar_state="expanded")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root{--bg:#070a11;--panel:#101725;--line:rgba(148,163,184,.16);--mint:#5eead4;--blue:#60a5fa;--muted:#93a4bc}
html,body,[class*="css"]{font-family:Manrope,sans-serif}
.stApp{background:radial-gradient(ellipse at 82% 0%,rgba(37,99,235,.17),transparent 35%),radial-gradient(ellipse at 6% 20%,rgba(20,184,166,.08),transparent 26%),var(--bg)}
.block-container{max-width:1600px;padding-top:1.2rem}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#101624,#090d15);border-right:1px solid var(--line)}
[data-testid="stMetric"]{background:linear-gradient(135deg,#141e2f,#0c121d);border:1px solid var(--line);border-radius:16px;padding:16px}
[data-testid="stMetricValue"]{font-weight:800}
div[data-testid="stButton"] button,div[data-testid="stDownloadButton"] button{border-radius:11px;min-height:2.6rem;font-weight:750;border:1px solid rgba(94,234,212,.28)}
div[data-testid="stButton"] button[kind="primary"]{background:linear-gradient(100deg,#2dd4bf,#60a5fa);border:0;color:#07111c}
div[data-testid="stTextArea"] textarea,div[data-testid="stTextInput"] input{background:#0a111c;border:1px solid #2a3850;border-radius:11px;font-family:'DM Mono',monospace}
[data-testid="stVerticalBlockBorderWrapper"]{background:linear-gradient(135deg,rgba(16,23,37,.92),rgba(10,15,25,.92));border-color:var(--line)!important;border-radius:17px}
h1,h2,h3{letter-spacing:-.04em}.eyebrow{text-transform:uppercase;letter-spacing:.17em;color:var(--mint);font-size:.72rem;font-weight:800}
.hero{padding:34px;border:1px solid rgba(94,234,212,.22);border-radius:24px;background:linear-gradient(115deg,rgba(20,184,166,.13),rgba(59,130,246,.1) 55%,rgba(167,139,250,.1))}
.hero h1{font-size:clamp(2.5rem,4.5vw,4.1rem);line-height:1.02;margin:.55rem 0}.hero p{max-width:830px;color:#b6c6da;font-size:1.05rem}
.pill{display:inline-block;border:1px solid rgba(94,234,212,.25);background:rgba(20,184,166,.08);color:#8df4e4;padding:5px 10px;border-radius:999px;font-size:.7rem;font-weight:800;margin:5px 6px 0 0}
footer{visibility:hidden}
</style>
""",unsafe_allow_html=True)
if "pseudonymizer" not in st.session_state: st.session_state.pseudonymizer=Pseudonymizer()
for k,v in {"raw_log":"","sanitized":"","scan_history":[]}.items():
    if k not in st.session_state: st.session_state[k]=v
NAV={"Command Center":"◈","Sanitize & Inspect":"⛨","ML Intelligence":"✳","Privacy Lab":"◎","Utility Benchmark":"⌁","Trust Center":"ⓘ"}
with st.sidebar:
    st.markdown("<div style='padding:10px 6px 22px;display:flex;gap:11px;align-items:center'><div style='width:46px;height:46px;border-radius:15px;background:linear-gradient(135deg,#2dd4bf,#3b82f6);display:grid;place-items:center;color:#07111c;font-size:24px;font-weight:900'>◈</div><div><div style='font-size:1.25rem;font-weight:850'>SafeTrace <span style=\"color:#5eead4\">Ultra</span></div><div style='font-size:.68rem;letter-spacing:.12em;color:#8b9bb2'>PRIVACY INTELLIGENCE</div></div></div>",unsafe_allow_html=True)
    page=st.radio("NAVIGATION",list(NAV),format_func=lambda x:f"{NAV[x]}   {x}")
    st.markdown("---")
    st.markdown("<div style='padding:12px;border:1px solid rgba(94,234,212,.2);border-radius:13px;background:rgba(20,184,166,.06);color:#5eead4;font-weight:800'>● HYBRID DETECTION<br><span style='font-size:.75rem;color:#9aaac0;font-weight:500'>Patterns + entropy + ML triage</span></div>",unsafe_allow_html=True)
    st.caption("BUILD 2.0 · LOCAL-FIRST")
status=model_status()
def header(k,t,s): st.markdown(f"<div class='eyebrow'>{k}</div><h1 style='margin:.35rem 0 .3rem'>{t}</h1><p style='color:#9aaac0'>{s}</p>",unsafe_allow_html=True)
def figstyle(fig,h=330):
    fig.update_layout(height=h,paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font=dict(family="Manrope",color="#cbd7e8"),margin=dict(l=10,r=10,t=25,b=10),xaxis=dict(gridcolor="rgba(148,163,184,.1)"),yaxis=dict(gridcolor="rgba(148,163,184,.1)"))
    return fig
if page=="Command Center":
    st.markdown("<div class='hero'><div class='eyebrow'>PRIVACY ENGINEERING · INTELLIGENT LOG DEFENSE</div><h1>Keep the signal.<br><span style='color:#5eead4'>Contain the secret.</span></h1><p>SafeTrace Ultra combines deterministic detection, entropy analysis, contextual machine learning, stable pseudonymization, and measurable privacy experiments.</p><span class='pill'>LOCAL-FIRST</span><span class='pill'>HYBRID DETECTION</span><span class='pill'>ML-ASSISTED</span><span class='pill'>PRIVACY × UTILITY</span></div>",unsafe_allow_html=True)
    st.write("");a,b,c,d=st.columns(4);a.metric("Detection stack","Hybrid ML");b.metric("Model","TF-IDF + Logistic Regression" if status["available"] else "Fallback");c.metric("Sanitization runs",len(st.session_state.scan_history));d.metric("AI diagnosis","Removed")
    left,right=st.columns([1.1,.9],gap="large")
    with left:
        with st.container(border=True):
            st.subheader("01 / Sanitize & inspect");st.write("Import logs, preserve debugging structure, review replacements, and export sanitized output.")
            st.markdown("- Stable pseudonyms\n- Local processing\n- Scan telemetry")
        with st.container(border=True):
            st.subheader("02 / ML Intelligence");st.write("Inspect suspicious spans, confidence ranking, entropy signals, and explainable detection reasons.")
    with right:
        with st.container(border=True):
            st.subheader("Detection pipeline")
            for n,label in [("01","Candidate extraction"),("02","Context + entropy features"),("03","ML confidence ranking"),("04","Human review + sanitization")]:
                st.markdown(f"**{n}**　{label}")
        st.warning("Prototype model trained on a small synthetic dataset. Scores are not calibrated probabilities or security guarantees.")
elif page=="Sanitize & Inspect":
    header("WORKSPACE / 01","Sanitize & Inspect","Local-first log protection with side-by-side review and export.")
    demo='ERROR: AuthenticationError: invalid credential for alice@example.com\nAuthorization: Bearer demo_secret_token_12345\npassword=example_not_a_real_password_987\nFile "/home/alice/project/api.py", line 42, in authenticate\nHTTP 401: request failed'
    x,y,z=st.columns([1,1,2])
    with x:
        if st.button("✦ Load synthetic demo",use_container_width=True): st.session_state.raw_log=demo
    with y:
        if st.button("↺ Clear workspace",use_container_width=True): st.session_state.raw_log="";st.session_state.sanitized="";st.rerun()
    with z:
        uploaded=st.file_uploader("Import .txt / .log",type=["txt","log"],label_visibility="collapsed")
        if uploaded: st.session_state.raw_log=uploaded.getvalue().decode("utf-8",errors="replace")
    a,b=st.columns(2,gap="large")
    with a:
        st.subheader("INPUT STREAM");raw=st.text_area("Raw log",key="raw_log",height=330,label_visibility="collapsed",placeholder="Paste stack trace or application log…",max_chars=200000);st.caption(f"{len(raw):,} characters")
    with b:
        st.subheader("SANITIZED OUTPUT")
        if st.session_state.sanitized: st.code(st.session_state.sanitized,language="text");st.download_button("↓ Export sanitized log",st.session_state.sanitized,file_name="sanitized.log",mime="text/plain",use_container_width=True)
        else: st.info("Sanitized output will appear here after a scan.")
    st.warning("Use synthetic data in demos. Always inspect the output; unknown secrets may be missed.")
    if st.button("⛨ Sanitize locally",type="primary",use_container_width=True):
        try:
            r=sanitize(raw,st.session_state.pseudonymizer,int(os.getenv("SAFETRACE_MAX_INPUT_CHARS","200000")))
            st.session_state.sanitized=r.sanitized_text;st.session_state.last_counts=r.categories;st.session_state.last_replacements=r.replacements
            st.session_state.scan_history.append({"Time":pd.Timestamp.now().strftime("%H:%M:%S"),"Characters":len(raw),"Replacements":r.replacements})
            st.session_state.ml_scan=[{"Candidate":c.value,"Confidence":round(c.confidence*100,1),"Reasons":", ".join(c.reasons)} for c in detect_candidates(raw)]
            st.rerun()
        except Exception as e: st.error(str(e))
    if "last_replacements" in st.session_state:
        a,b,c=st.columns(3);a.metric("Replacements",st.session_state.last_replacements);b.metric("Input size",f"{len(raw):,} chars");c.metric("Categories",len(st.session_state.get("last_counts",{})))
        if st.session_state.last_counts: st.dataframe(pd.DataFrame([{"Category":k.replace("_"," ").title(),"Matches":v} for k,v in st.session_state.last_counts.items()]),hide_index=True,use_container_width=True)
        if st.session_state.get("ml_scan"): st.caption("ML candidate triage is advisory; inspect the ML Intelligence workspace.")
elif page=="ML Intelligence":
    header("MODEL WORKBENCH / 02","ML Intelligence","Explainable candidate triage using character n-grams, field context, and entropy signals.")
    a,b,c=st.columns(3);a.metric("Model status","Available" if status["available"] else "Fallback");b.metric("Classifier","Logistic Regression" if status["available"] else "Heuristic");c.metric("Features","Character n-grams")
    st.info(status["note"])
    st.markdown("**Pipeline**\n1. Extract suspicious candidate spans.\n2. Examine nearby context and entropy.\n3. Rank candidates with a TF-IDF character n-gram classifier.\n4. Review the reasons; the ML layer does not automatically rewrite sanitized output.")
    sample=st.session_state.raw_log or 'ERROR: login failed for alice@example.com\nAuthorization: Bearer demo_secret_token_12345\npassword=demo_password_123456789\nHTTP 401: unauthorized\nrequest_id=abc-123'
    with st.container(border=True):
        text=st.text_area("Text to inspect",value=sample,height=230,key="ml_text");threshold=st.slider("Minimum confidence",0.50,0.99,0.62,0.01)
        if st.button("✳ Analyze candidate spans",type="primary",use_container_width=True):
            cs=detect_candidates(text,threshold);st.session_state.ml_results=[{"Candidate":x.value,"Confidence (%)":round(x.confidence*100,1),"Reasons":", ".join(x.reasons),"Start":x.start,"End":x.end} for x in cs]
        if "ml_results" in st.session_state:
            if st.session_state.ml_results:
                frame=pd.DataFrame(st.session_state.ml_results);st.dataframe(frame,hide_index=True,use_container_width=True)
                st.plotly_chart(figstyle(px.bar(frame,x="Candidate",y="Confidence (%)",range_y=[0,100],color="Confidence (%)",hover_data=["Reasons"]),350),use_container_width=True)
                st.download_button("↓ Export candidate report",frame.to_csv(index=False),file_name="ml_candidate_report.csv",mime="text/csv")
            else: st.success("No candidates exceeded the threshold. This does not prove the text is safe.")
    with st.expander("Model limitations"):
        st.markdown("- Small synthetic training set; not production-trained.\n- Confidence scores are not calibrated.\n- May miss unseen or obfuscated secrets.\n- ML output is advisory and not a security certification.")
elif page=="Privacy Lab":
    header("EVALUATION / 03","Canary Privacy Lab","Measure exact full-value survival for synthetic canaries.")
    st.info("This narrow experiment is not a complete privacy assessment.")
    n=st.slider("Synthetic canary count",1,30,10)
    if st.button("▶ Run privacy experiment",type="primary",use_container_width=True):
        cs=generate_canaries(n);raw="\n".join("debug_token="+x["value"] for x in cs);st.session_state.privacy_report=evaluate_canaries(cs,raw)
    if "privacy_report" in st.session_state:
        r=st.session_state.privacy_report;a,b,c,d=st.columns(4);a.metric("Privacy score",f"{r.privacy_score:.1f}%");b.metric("Leak rate",f"{r.leak_rate:.1f}%");c.metric("Detected",f"{r.detected}/{r.total}");d.metric("Leaked",r.leaked)
        f=go.Figure(go.Pie(labels=["Detected / removed","Leaked"],values=[r.detected,r.leaked],hole=.72,textinfo="label+percent"));f.update_layout(showlegend=False,annotations=[dict(text=f"{r.privacy_score:.0f}%",x=.5,y=.5,showarrow=False,font_size=24)]);st.plotly_chart(figstyle(f,300),use_container_width=True)
elif page=="Utility Benchmark":
    header("EVALUATION / 04","Utility Observatory","Compare retained diagnostic signal across the included baselines.")
    st.warning("Small synthetic dataset; score is reference-term overlap, not human-verified diagnosis accuracy.")
    if st.button("▶ Run benchmark",type="primary",use_container_width=True):
        try: st.session_state.benchmark=run_benchmark(str(ROOT/"data"/"benchmark_cases.json"))
        except Exception as e: st.error(str(e))
    if "benchmark" in st.session_state:
        rep=st.session_state.benchmark;methods=rep["methods"];df=pd.DataFrame([{"Method":n,"Diagnostic utility (%)":v["diagnosis_accuracy"],"Privacy score":v["privacy_score"]} for n,v in methods.items()])
        a,b,c=st.columns(3);a.metric("Cases",rep["sample_size"]);b.metric("Methods",len(methods));c.metric("SafeTrace utility proxy",f"{methods.get('SafeTrace',{}).get('diagnosis_accuracy',0):.2f}%")
        st.dataframe(df,hide_index=True,use_container_width=True);st.plotly_chart(figstyle(px.bar(df,x="Method",y="Diagnostic utility (%)",color="Method",range_y=[0,105],text_auto=".1f"),350),use_container_width=True)
        st.download_button("↓ Export benchmark JSON",json.dumps(rep,indent=2),file_name="benchmark_report.json",mime="application/json")
elif page=="Trust Center":
    header("TRUST CENTER / 05","Methodology & Limitations","Keep claims traceable, bounded, and reproducible.")
    for title,path in [("Evaluation methodology",ROOT/"docs"/"evaluation_methodology.md"),("Known limitations",ROOT/"docs"/"limitations.md"),("Dataset provenance",ROOT/"data"/"DATASET_SOURCES.md"),("ML detector",ROOT/"docs"/"ml_detector.md")]:
        with st.expander(title,expanded=title=="Known limitations"):
            try: st.markdown(path.read_text(encoding="utf-8"))
            except Exception: st.caption(f"Documentation not found: {path.name}")
    st.warning("A successful scan is not a security certification. Review sanitized output manually.")
