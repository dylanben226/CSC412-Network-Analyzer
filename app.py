import threading
import webbrowser
import random
from datetime import datetime

import dash
from dash import dcc, html, Input, Output, State, callback_context, no_update
import plotly.graph_objects as go

try:
    from analyzer import get_protocol_data as _get_protocol_data
    def get_protocol_data():
        d = _get_protocol_data()
        for p in ["TCP", "UDP", "ICMP"]:
            if p not in d or len(d[p]) != 3:
                raise ValueError("bad structure")
        return d, True
except Exception:
    def get_protocol_data():
        return {"TCP": [78.0, 8.0, 12.0], "UDP": [12.0, 9.0, 76.0], "ICMP": [10.0, 83.0, 12.0]}, False

SCENARIOS = ["Browsing", "Ping Flood", "Idle / DNS"]
PROTOCOLS = ["TCP", "UDP", "ICMP"]
SPIKE_SEQ = [4, 7, 5, 11, 38, 62, 80, 79, 81, 72, 61, 44, 28, 14, 4]

BOOT_STEPS = [
    "initializing scapy engine...",
    "mounting pcap filesystem...",
    "loading http.cap · icmp.pcap · dns.cap",
    "parsing packet layers...",
    "computing protocol distribution...",
    "calibrating spike detector (threshold 70%)...",
    "building visualization pipeline...",
    "system ready.",
]

FEED_MSGS = [
    "Watcher online — baseline established",
    "DNS resolver responding normally",
    "Analyzer heartbeat — parser stable",
    "Threat engine idle — no flood detected",
    "TCP lane healthy — browsing profile normal",
    "Telemetry live — dashboard synced",
    "All charts refreshed successfully",
    "ICMP monitor standing by",
]

C = {
    "bg":     "#050d1a",
    "panel":  "#091527",
    "card":   "#0d1c30",
    "border": "#162840",
    "b2":     "#1e3a56",
    "txt":    "#e8f4ff",
    "muted":  "#4a7a9b",
    "dim":    "#1e3040",
    "tcp":    "#22d3ee",
    "udp":    "#4ade80",
    "icmp":   "#f43f5e",
    "warn":   "#fb923c",
    "ok":     "#4ade80",
    "accent": "#818cf8",
    "purple": "#a78bfa",
    "yellow": "#facc15",
}

BOOT_IMAGE_URL = "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=640&q=80&fit=crop"

def safe_load():
    try:
        return get_protocol_data()
    except Exception:
        return {"TCP": [78.0, 8.0, 12.0], "UDP": [12.0, 9.0, 76.0], "ICMP": [10.0, 83.0, 12.0]}, False

def dominant(data):
    avgs = {p: sum(v) / len(v) for p, v in data.items()}
    dom  = max(avgs, key=avgs.get)
    idx  = data[dom].index(max(data[dom]))
    return dom, SCENARIOS[idx]

def filter_data(data, scenario):
    if scenario == "All":
        return data, SCENARIOS
    idx = {"Browsing": 0, "Ping Flood": 1, "Idle / DNS": 2}[scenario]
    return {p: [data[p][idx]] for p in PROTOCOLS}, [scenario]

def total_pkts(data):
    return int(sum(sum(v) for v in data.values()) // 3)

BASE = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(5,13,26,0.6)",
    font=dict(family="'IBM Plex Mono', 'Courier New', monospace", color=C["txt"], size=10),
    margin=dict(l=42, r=14, t=38, b=28),
    transition=dict(duration=320),
    hoverlabel=dict(bgcolor=C["panel"], font_size=11, font_family="IBM Plex Mono"),
)

def build_bar(data, pf, sf, ct):
    fd, labels = filter_data(data, sf)
    protos = PROTOCOLS if pf == "All" else [pf]
    colors = {"TCP": C["tcp"], "UDP": C["udp"], "ICMP": C["icmp"]}
    fig = go.Figure()
    if ct == "Radar":
        for p in protos:
            vals = fd[p]; theta = labels
            if len(labels) == 1: vals, theta = vals * 3, ["A", "B", "C"]
            fig.add_trace(go.Scatterpolar(r=vals+[vals[0]], theta=theta+[theta[0]], fill="toself", name=p, line=dict(color=colors[p], width=2), opacity=0.82))
        fig.update_layout(polar=dict(bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(range=[0,100], gridcolor=C["b2"], tickfont=dict(size=8), color=C["muted"]),
            angularaxis=dict(gridcolor=C["b2"], color=C["muted"])))
    else:
        for p in protos:
            yvals = [max(v, 0) for v in fd[p]]
            fig.add_trace(go.Bar(x=labels, y=yvals, name=p,
                marker=dict(color=colors[p], opacity=0.88, line=dict(width=0)),
                text=[f"<b>{v:.0f}%</b>" for v in yvals], textposition="outside",
                textfont=dict(size=10, color=colors[p]),
                hovertemplate=f"<b>%{{x}}</b><br>{p}: %{{y:.1f}}%<extra></extra>"))
        fig.update_layout(barmode="stack" if ct == "Stacked" else "group",
            xaxis=dict(gridcolor=C["b2"], tickfont=dict(size=9, color=C["muted"]), zeroline=False, showline=False),
            yaxis=dict(gridcolor=C["b2"], tickfont=dict(size=9, color=C["muted"]), range=[0,120], zeroline=False, title=""))
    fig.update_layout(**BASE, legend=dict(orientation="h", y=1.12, x=0, font=dict(size=9, color=C["muted"]), bgcolor="rgba(0,0,0,0)"), height=230, title=dict(text="", x=0))
    return fig

def build_donut(data, sf):
    fd, _ = filter_data(data, sf)
    totals = {p: max(sum(fd[p]), 0.01) for p in PROTOCOLS}
    fig = go.Figure(go.Pie(labels=list(totals.keys()), values=list(totals.values()), hole=0.68, pull=[0.04,0.04,0.04],
        marker=dict(colors=[C["tcp"],C["udp"],C["icmp"]], line=dict(color=C["bg"], width=3)),
        textinfo="label+percent", textfont=dict(size=10, color=C["txt"]), insidetextorientation="radial", sort=False))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="'IBM Plex Mono', monospace", color=C["txt"]),
        showlegend=False, height=200, margin=dict(l=10,r=10,t=30,b=10), transition=dict(duration=300))
    return fig

def build_timeline(pts):
    fig = go.Figure()
    fig.add_hrect(y0=70, y1=100, fillcolor="rgba(244,63,94,0.07)", line_width=0)
    if not pts:
        fig.add_annotation(text="[ run stress test to see spike data ]", x=0.5, y=0.5, xref="paper", yref="paper",
            showarrow=False, font=dict(size=11, color=C["dim"], family="IBM Plex Mono"))
    else:
        fig.add_trace(go.Scatter(x=list(range(1,len(pts)+1)), y=pts, mode="lines",
            line=dict(color=C["icmp"], width=2.5, shape="spline"), fill="tozeroy",
            fillcolor="rgba(244,63,94,0.10)", hovertemplate="step %{x} — ICMP %{y}%<extra></extra>", showlegend=False))
        mc = [C["icmp"] if v>=70 else C["yellow"] if v>=40 else C["ok"] for v in pts]
        fig.add_trace(go.Scatter(x=list(range(1,len(pts)+1)), y=pts, mode="markers",
            marker=dict(size=7, color=mc, line=dict(color=C["bg"], width=1.5)), hoverinfo="skip", showlegend=False))
    fig.add_hline(y=70, line_dash="dot", line_color=C["icmp"], line_width=1.2,
        annotation_text="⚠ 70% alert threshold", annotation_font=dict(size=9, color=C["icmp"]), annotation_position="top left")
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(5,13,26,0.6)",
        font=dict(family="'IBM Plex Mono', monospace", color=C["txt"], size=10),
        height=185, margin=dict(l=42,r=14,t=20,b=28), transition=dict(duration=280),
        xaxis=dict(gridcolor=C["b2"], tickfont=dict(size=9, color=C["muted"]), zeroline=False, title=""),
        yaxis=dict(gridcolor=C["b2"], tickfont=dict(size=9, color=C["muted"]), range=[0,105], zeroline=False, title=""))
    return fig

def mcard(val_id, sub_id, label, icon, color):
    return html.Div([
        html.Div(style={"height": "3px", "background": color}),
        html.Div([
            html.Div([html.Span(label.upper(), className="mlabel"), html.Span(icon, className="micon")], className="mrow"),
            html.Div("—", id=val_id, className="mval", style={"color": color}),
            html.Div("—", id=sub_id, className="msub"),
        ], className="mbody"),
    ], className="mcard")

def panel(children, title=""):
    inner = ([html.Div(title, className="ptitle")] if title else []) + (children if isinstance(children, list) else [children])
    return html.Div(inner, className="panel")

app = dash.Dash(__name__)
app.title = "Network Traffic Analyzer"
init_data, init_live = safe_load()

app.layout = html.Div([
    dcc.Store(id="data-store",   data=init_data),
    dcc.Store(id="live-store",   data=init_live),
    dcc.Store(id="tl-store",     data=[]),
    dcc.Store(id="spike-store",  data={"on": False, "i": 0}),
    dcc.Store(id="reload-store", data={"on": False, "p": 0}),
    dcc.Store(id="boot-store",   data={"on": True, "i": 0, "lines": []}),
    dcc.Store(id="ts-store",     data=datetime.now().strftime("%H:%M:%S")),
    dcc.Store(id="feed-store",   data=0),

    dcc.Interval(id="spike-int",  interval=430,  disabled=True),
    dcc.Interval(id="reload-int", interval=75,   disabled=True),
    dcc.Interval(id="boot-int",   interval=360,  disabled=False),
    dcc.Interval(id="clock-int",  interval=1000, disabled=False),
    dcc.Interval(id="pulse-int",  interval=3000, disabled=False),
    dcc.Interval(id="feed-int",   interval=2200, disabled=False),

    # ── BOOT SCREEN ──────────────────────────────────────────────────────────
    html.Div([
        html.Canvas(id="boot-canvas", className="boot-canvas"),
        html.Div([

            # LEFT
            html.Div([
                html.Div([
                    html.Div(className="boot-badge-dot"),
                    html.Span("SYSTEM BOOT", className="boot-badge-txt"),
                ], className="boot-badge"),
                html.Pre(
                    "  ███╗   ██╗████████╗ █████╗ \n"
                    "  ████╗  ██║╚══██╔══╝██╔══██╗\n"
                    "  ██╔██╗ ██║   ██║   ███████║\n"
                    "  ██║╚██╗██║   ██║   ██╔══██║\n"
                    "  ██║ ╚████║   ██║   ██║  ██║\n"
                    "  ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝",
                    className="ascii"
                ),
                html.Div("Network Traffic Analyzer", className="boot-title"),
                html.Div("CSC412 · Team J & D Unlimited", className="boot-sub"),
                html.Div(className="boot-divider"),
                html.Div(id="boot-lines", className="boot-lines"),
                html.Div([
                    html.Div([
                        html.Span("Loading modules", className="prog-key"),
                        html.Span(id="boot-pct", children="0%", className="prog-pct"),
                    ], className="prog-header"),
                    html.Div([
                        html.Div(id="boot-bar", className="boot-bar-fill"),
                        html.Div(className="boot-shimmer"),
                    ], className="boot-bar-wrap"),
                    html.Div(id="boot-stage", className="boot-stage"),
                ], className="boot-progress"),
                html.Div([
                    html.Span("Python 3.x", className="boot-tag hi"),
                    html.Span("Scapy",      className="boot-tag hi"),
                    html.Span("TCP",         className="boot-tag"),
                    html.Span("UDP",         className="boot-tag"),
                    html.Span("ICMP",        className="boot-tag"),
                    html.Span("Plotly Dash", className="boot-tag"),
                ], className="boot-tags"),
            ], className="boot-left"),

            # RIGHT: image + canvas + counters
            html.Div([
                html.Div([
                    html.Div([
                        html.Div(className="viz-live-dot"),
                        html.Span("Live Network Map", className="viz-panel-title"),
                    ], className="viz-panel-header"),
                    html.Div([
                        html.Img(src=BOOT_IMAGE_URL, className="net-img", alt="Network infrastructure"),
                        html.Div(className="net-img-overlay"),
                        html.Canvas(id="net-canvas", className="net-canvas"),
                    ], className="net-img-wrap"),
                    html.Div([
                        html.Div([html.Div("0", id="cnt-tcp",  className="cnt-val", style={"color": C["tcp"]}),  html.Div("TCP pkts",  className="cnt-lbl")], className="cnt-card"),
                        html.Div([html.Div("0", id="cnt-udp",  className="cnt-val", style={"color": C["udp"]}),  html.Div("UDP pkts",  className="cnt-lbl")], className="cnt-card"),
                        html.Div([html.Div("0", id="cnt-icmp", className="cnt-val", style={"color": C["icmp"]}), html.Div("ICMP pkts", className="cnt-lbl")], className="cnt-card"),
                    ], className="cnt-row"),
                ], className="viz-panel"),
            ], className="boot-right"),

        ], className="boot-inner"),
    ], id="boot-screen", className="boot-screen"),

    # ── DASHBOARD ─────────────────────────────────────────────────────────────
    html.Div([
        html.Div([
            html.Div([html.Span("◈ ", className="brand-glyph"), html.Span("Network Traffic Analyzer", className="brand-title"), html.Span(" / CSC412", className="brand-slash")], className="brand"),
            html.Div([html.Div(id="status-pill", children="● LIVE", className="pill pill-live pulse-soft"), html.Div(id="ts-display", children="00:00:00", className="ts-disp")], className="topright"),
        ], className="topbar"),

        html.Div([
            mcard("m-pkts",   "m-pkts-sub",  "Packets",  "📦", C["tcp"]),
            mcard("m-dom",    "m-dom-sub",   "Dominant", "📊", C["udp"]),
            mcard("m-threat", "m-thr-sub",   "Threat",   "🚨", C["icmp"]),
            mcard("m-status", "m-stat-sub",  "Status",   "⚡", C["accent"]),
        ], className="mcards"),

        html.Div([
            html.Div([
                panel([
                    html.Div("Protocol", className="flabel"),
                    dcc.Dropdown(id="proto-dd", options=[{"label":"All","value":"All"}]+[{"label":p,"value":p} for p in PROTOCOLS], value="All", clearable=False, className="dd"),
                    html.Div(className="gap6"),
                    html.Div("Scenario", className="flabel"),
                    dcc.Dropdown(id="scen-dd", options=[{"label":"All Scenarios","value":"All"}]+[{"label":s,"value":s} for s in SCENARIOS], value="All", clearable=False, className="dd"),
                    html.Div(className="gap6"),
                    html.Div("Chart Type", className="flabel"),
                    dcc.Dropdown(id="chart-dd", options=[{"label":"Bar","value":"Bar"},{"label":"Stacked Bar","value":"Stacked"},{"label":"Radar","value":"Radar"}], value="Bar", clearable=False, className="dd"),
                ], "Filters"),
                html.Div(className="gap8"),
                panel([
                    html.Button([html.Span(id="scan-icon", children="⟳"), html.Span(id="scan-label", children=" Scan Network")], id="reload-btn", n_clicks=0, className="btn btn-scan"),
                    html.Div([html.Div(id="scan-fill", className="scan-fill")], className="scan-track"),
                    html.Div(id="scan-text", children="idle", className="scan-text"),
                    html.Div(className="gap8"),
                    html.Button("⚡  Simulate Stress Test", id="spike-btn", n_clicks=0, className="btn btn-spike"),
                    html.Div(className="gap5"),
                    html.Button("↺  Reset", id="reset-btn", n_clicks=0, className="btn btn-reset"),
                    html.Div(id="sim-status", className="sim-status"),
                    html.Div(id="last-ts",    className="last-ts"),
                ], "Actions"),
                html.Div(className="gap8"),
                panel([html.Div(id="alert-box", className="alert-box")], "Alert"),
            ], className="lcol"),

            html.Div([
                panel([dcc.Graph(id="main-chart", config={"displayModeBar": False}, style={"height": "230px"})], "Traffic Overview"),
                html.Div(className="gap8"),
                panel([dcc.Graph(id="tl-chart",   config={"displayModeBar": False}, style={"height": "185px"})], "Threat Timeline — ICMP Spike"),
            ], className="ccol"),

            html.Div([
                panel([dcc.Graph(id="donut-chart", config={"displayModeBar": False}, style={"height": "200px"})], "Composition"),
                html.Div(className="gap8"),
                panel([html.Div(id="feed-area", className="feed-area"), html.Div(className="gap6"), html.Ul(id="insights", className="insights-list")], "Live Feed"),
            ], className="rcol"),
        ], className="content"),

        html.Div([html.Span("Team J & D Unlimited", style={"color": C["muted"]}), html.Span(" · CSC412 · Python · Scapy · Plotly Dash", style={"color": C["dim"]})], className="footer"),
    ], id="dashboard", style={"display": "none"}),

], className="shell")


# ── Callbacks ─────────────────────────────────────────────────────────────────

@app.callback(
    Output("boot-lines",  "children"),
    Output("boot-bar",    "style"),
    Output("boot-pct",    "children"),
    Output("boot-stage",  "children"),
    Output("boot-store",  "data"),
    Output("boot-screen", "style"),
    Output("dashboard",   "style"),
    Output("boot-int",    "disabled"),
    Input("boot-int",     "n_intervals"),
    State("boot-store",   "data"),
)
def advance_boot(_, store):
    i = store["i"]; lines = store["lines"]; total = len(BOOT_STEPS)
    if i < total:
        lines = lines + [BOOT_STEPS[i]]
        pct = int((i + 1) / total * 100)
        els = [html.Div([
            html.Span("▸ " if j == len(lines)-1 else "✓ ", style={"color": C["accent"] if j == len(lines)-1 else C["ok"], "marginRight": "6px"}),
            html.Span(ln, style={"color": C["txt"] if j == len(lines)-1 else C["muted"]}),
        ], className="boot-line") for j, ln in enumerate(lines)]
        return els, {"width": f"{pct}%"}, f"{pct}%", BOOT_STEPS[i] + "...", \
               {"on": True, "i": i+1, "lines": lines}, {"display": "flex"}, {"display": "none"}, False
    else:
        return no_update, no_update, "100%", "all systems nominal — launching dashboard", \
               {"on": False, "i": i, "lines": lines}, {"display": "none"}, {"display": "block"}, True

@app.callback(Output("ts-display", "children"), Input("clock-int", "n_intervals"))
def clock(_): return datetime.now().strftime("%H:%M:%S")

@app.callback(Output("reload-store","data"), Output("reload-int","disabled"), Input("reload-btn","n_clicks"), prevent_initial_call=True)
def start_scan(_): return {"on": True, "p": 0}, False

@app.callback(
    Output("reload-store","data",allow_duplicate=True), Output("reload-int","disabled",allow_duplicate=True),
    Output("data-store","data",allow_duplicate=True), Output("live-store","data",allow_duplicate=True), Output("ts-store","data",allow_duplicate=True),
    Input("reload-int","n_intervals"), State("reload-store","data"), prevent_initial_call=True,
)
def advance_reload(_, rs):
    if not rs["on"]: return rs, True, no_update, no_update, no_update
    p = rs["p"]; step = 5 if p < 60 else 3 if p < 85 else 1; p += step
    if p < 100: return {"on": True, "p": p}, False, no_update, no_update, no_update
    d, live = safe_load()
    return {"on": False, "p": 100}, True, d, live, datetime.now().strftime("%H:%M:%S")

@app.callback(Output("scan-fill","style"), Output("scan-text","children"), Output("scan-icon","children"), Output("scan-label","children"), Output("reload-btn","disabled"), Input("reload-store","data"))
def scan_ui(rs):
    p = rs["p"]; phases = ["mounting pcap..","reading packets..","computing stats..","building charts..","finalizing.."]
    if rs["on"]: return {"width":f"{p}%"}, phases[min(int(p/22),4)], "◌", " Scanning...", True
    elif p >= 100: return {"width":"100%"}, "scan complete ✓", "⟳", " Scan Network", False
    return {"width":"0%"}, "idle", "⟳", " Scan Network", False

@app.callback(Output("spike-store","data"), Output("tl-store","data"), Output("spike-int","disabled"), Input("spike-btn","n_clicks"), Input("reset-btn","n_clicks"), prevent_initial_call=True)
def handle_spike(sim, rst):
    t = callback_context.triggered[0]["prop_id"].split(".")[0]
    if t == "spike-btn": return {"on":True,"i":0}, [], False
    return {"on":False,"i":0}, [], True

@app.callback(Output("spike-store","data",allow_duplicate=True), Output("tl-store","data",allow_duplicate=True), Output("spike-int","disabled",allow_duplicate=True), Input("spike-int","n_intervals"), State("spike-store","data"), State("tl-store","data"), prevent_initial_call=True)
def advance_spike(_, ss, tl):
    if not ss["on"]: return ss, tl, True
    i = ss["i"]
    if i >= len(SPIKE_SEQ): return {"on":False,"i":0}, tl, True
    return {"on":True,"i":i+1}, tl+[SPIKE_SEQ[i]], False

@app.callback(Output("main-chart","figure"), Output("donut-chart","figure"), Output("insights","children"), Input("data-store","data"), Input("proto-dd","value"), Input("scen-dd","value"), Input("chart-dd","value"))
def update_charts(data, pf, sf, ct):
    cols = {"TCP":C["tcp"],"UDP":C["udp"],"ICMP":C["icmp"]}
    ins = [html.Li([html.Span(f"{s}:  ",style={"color":C["muted"],"fontSize":"9px"}),
        html.Span(f"{max({p:data[p][i] for p in PROTOCOLS},key=lambda p:data[p][i])} {max(data[p][i] for p in PROTOCOLS):.0f}%",
            style={"color":cols[max({p:data[p][i] for p in PROTOCOLS},key=lambda p:data[p][i])],"fontWeight":"700","fontSize":"10px"})],
        style={"marginBottom":"5px"}) for i,s in enumerate(SCENARIOS)]
    return build_bar(data,pf,sf,ct), build_donut(data,sf), ins

@app.callback(Output("tl-chart","figure"), Input("tl-store","data"))
def update_tl(tl): return build_timeline(tl)

@app.callback(
    Output("m-pkts","children"), Output("m-pkts-sub","children"), Output("m-dom","children"), Output("m-dom-sub","children"),
    Output("m-threat","children"), Output("m-thr-sub","children"), Output("m-status","children"), Output("m-stat-sub","children"),
    Output("status-pill","children"), Output("status-pill","className"), Output("alert-box","children"), Output("sim-status","children"), Output("last-ts","children"),
    Input("data-store","data"), Input("tl-store","data"), Input("ts-store","data"), Input("live-store","data"),
)
def update_metrics(data, tl, ts, live):
    total = total_pkts(data); dom, dom_s = dominant(data); peak = max(tl) if tl else 0
    if peak >= 70:
        pill,pcls = "⚠ ALERT","pill pill-alert pulse"
        alert = html.Div([html.Div("ICMP spike detected",className="a-danger"),html.Div("ICMP > 70% — possible ping flood",className="a-sub")])
        thr_s,sim_s = "above threshold","threat pattern observed"
    elif tl:
        pill,pcls = "◎ WATCH","pill pill-watch pulse-soft"
        alert = html.Div([html.Div("Simulation running",className="a-warn"),html.Div("traffic below threshold",className="a-sub")])
        thr_s,sim_s = "monitoring","simulation in progress..."
    else:
        pill,pcls = "● LIVE","pill pill-live pulse-soft"
        alert = html.Div([html.Div("No anomalies detected",className="a-ok"),html.Div("System monitoring normal traffic",className="a-sub")])
        thr_s,sim_s = "all clear","ready for stress test"
    stat = "ONLINE" if live else "DEMO MODE"; src = "live PCAP data" if live else "demo data"
    return (f"{total:,}","from 3 PCAP files",dom,dom_s,f"{peak}%",thr_s,stat,src,pill,pcls,alert,sim_s,f"last scan: {ts}")

@app.callback(Output("m-pkts","children",allow_duplicate=True), Input("pulse-int","n_intervals"), State("data-store","data"), State("reload-store","data"), prevent_initial_call=True)
def jitter(_, data, rs):
    if rs["on"]: return no_update
    return f"{total_pkts(data)+random.randint(-4,4):,}"

@app.callback(Output("feed-store","data"), Input("feed-int","n_intervals"), State("feed-store","data"))
def rot_feed(_, idx): return (idx+1) % len(FEED_MSGS)

@app.callback(Output("feed-area","children"), Input("feed-store","data"))
def update_feed(idx):
    return [html.Div([html.Span("●",className="feed-dot"),html.Span(FEED_MSGS[(idx-i)%len(FEED_MSGS)],className="feed-text")],className="feed-item") for i in range(4)]

def open_browser():
    webbrowser.open_new("http://127.0.0.1:8050/")

if __name__ == "__main__":
    threading.Timer(1.2, open_browser).start()
    app.run(debug=False, use_reloader=False)