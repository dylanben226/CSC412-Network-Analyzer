import threading
import webbrowser
from datetime import datetime
import random

import dash
from dash import dcc, html, Input, Output, State, callback_context, no_update
import plotly.graph_objects as go

from analyzer import get_protocol_data

# ── Constants ──────────────────────────────────────────────────────────────────
SCENARIOS     = ["Browsing", "Ping Flood", "Idle / DNS"]
PROTOCOLS     = ["TCP", "UDP", "ICMP"]
SPIKE_SEQ     = [4, 7, 5, 11, 38, 62, 80, 79, 81, 72, 61, 44, 28, 14, 4]
BOOT_MESSAGES = [
    "initializing scapy engine...",
    "mounting pcap file system...",
    "loading http.cap · icmp.pcap · dns.cap",
    "parsing packet layers...",
    "computing protocol distribution...",
    "calibrating spike detector (threshold 70%)...",
    "building visualization pipeline...",
    "system ready.",
]

C = {
    "bg":      "#060B14",
    "panel":   "#0A1120",
    "card":    "#0D1829",
    "border":  "#16253D",
    "border2": "#1E3352",
    "text":    "#E8F4FF",
    "muted":   "#5B7BA8",
    "dim":     "#2A3F5F",
    "tcp":     "#00D4FF",
    "udp":     "#00FF9F",
    "icmp":    "#FF4D7D",
    "warn":    "#FFB020",
    "ok":      "#00E5A0",
    "accent":  "#4A9EFF",
    "purple":  "#8B5CF6",
}

# ── Data helpers ───────────────────────────────────────────────────────────────
def safe_load():
    try:
        d = get_protocol_data()
        for p in PROTOCOLS:
            if p not in d or len(d[p]) != 3:
                raise ValueError
        return d, True
    except Exception:
        return {"TCP": [80.0, 10.0, 10.0], "UDP": [10.0, 10.0, 80.0], "ICMP": [10.0, 80.0, 10.0]}, False

def dominant(data):
    avgs = {p: sum(v)/len(v) for p, v in data.items()}
    dom  = max(avgs, key=avgs.get)
    idx  = data[dom].index(max(data[dom]))
    return dom, SCENARIOS[idx]

def filter_data(data, scenario):
    if scenario == "All":
        return data, SCENARIOS
    idx = {"Browsing": 0, "Ping Flood": 1, "Idle / DNS": 2}[scenario]
    return {p: [data[p][idx]] for p in PROTOCOLS}, [scenario]

# ── Chart builders ─────────────────────────────────────────────────────────────
CHART_BASE = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="'JetBrains Mono', 'Fira Code', monospace", color=C["text"], size=10),
    margin=dict(l=38, r=12, t=36, b=28),
    transition=dict(duration=320),
)

def build_bar(data, proto_f, scen_f, chart_t):
    fd, labels = filter_data(data, scen_f)
    protos = PROTOCOLS if proto_f == "All" else [proto_f]
    fig = go.Figure()

    if chart_t == "Radar":
        for p in protos:
            vals = fd[p]
            theta = labels
            if len(labels) == 1:
                vals, theta = vals * 3, ["A", "B", "C"]
            vc, tc = vals + [vals[0]], theta + [theta[0]]
            fig.add_trace(go.Scatterpolar(
                r=vc, theta=tc, fill="toself", name=p,
                line=dict(color=C[p.lower()], width=2),
                fillcolor=C[p.lower()].replace(")", ",0.08)").replace("rgb", "rgba") if "rgb" in C[p.lower()] else C[p.lower()] + "14",
                opacity=0.9,
            ))
        fig.update_layout(polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(range=[0,100], gridcolor=C["border2"], tickfont=dict(size=9), color=C["muted"]),
            angularaxis=dict(gridcolor=C["border2"], color=C["muted"]),
        ))
    else:
        for p in protos:
            fig.add_trace(go.Bar(
                x=labels, y=fd[p], name=p,
                marker=dict(
                    color=C[p.lower()],
                    opacity=0.88,
                    line=dict(color=C[p.lower()], width=0),
                ),
                text=[f"{v}%" for v in fd[p]],
                textposition="outside",
                textfont=dict(size=9, color=C[p.lower()]),
                hovertemplate=f"<b>%{{x}}</b><br>{p}: %{{y:.1f}}%<extra></extra>",
            ))
        fig.update_layout(
            barmode="stack" if chart_t == "Stacked" else "group",
            xaxis=dict(gridcolor=C["border"], tickfont=dict(size=9), color=C["muted"], zeroline=False),
            yaxis=dict(gridcolor=C["border"], tickfont=dict(size=9), color=C["muted"], range=[0,110], zeroline=False, title=""),
        )

    fig.update_layout(
        **CHART_BASE,
        legend=dict(orientation="h", y=1.08, x=0, font=dict(size=9), bgcolor="rgba(0,0,0,0)"),
        height=240,
        title=dict(text="Protocol Distribution", font=dict(size=11, color=C["muted"]), x=0),
    )
    return fig

def build_donut(data, scen_f):
    fd, _ = filter_data(data, scen_f)
    totals = {p: sum(fd[p]) for p in PROTOCOLS}
    fig = go.Figure(go.Pie(
        labels=list(totals.keys()),
        values=list(totals.values()),
        hole=0.72,
        marker=dict(colors=[C["tcp"], C["udp"], C["icmp"]], line=dict(color=C["bg"], width=2)),
        textinfo="label+percent",
        textfont=dict(size=9),
        sort=False,
    ))
    fig.update_layout(
        **CHART_BASE,
        showlegend=False,
        height=210,
        title=dict(text="Traffic Share", font=dict(size=11, color=C["muted"]), x=0),
        margin=dict(l=8, r=8, t=32, b=8),
    )
    return fig

def build_timeline(pts):
    fig = go.Figure()
    if not pts:
        fig.add_annotation(
            text="[ awaiting stress test ]",
            x=0.5, y=0.5, xref="paper", yref="paper",
            showarrow=False,
            font=dict(size=11, color=C["dim"], family="'JetBrains Mono', monospace"),
        )
    else:
        colors = [C["icmp"] if v >= 70 else C["ok"] for v in pts]
        fig.add_trace(go.Scatter(
            x=list(range(1, len(pts)+1)), y=pts,
            mode="lines+markers",
            line=dict(color=C["icmp"], width=2, shape="spline"),
            marker=dict(size=6, color=colors, line=dict(color=C["bg"], width=1)),
            fill="tozeroy",
            fillcolor="rgba(255,77,125,0.07)",
            hovertemplate="t=%{x}<br>ICMP %{y}%<extra></extra>",
        ))
    fig.add_hline(y=70, line_dash="dot", line_color=C["warn"], line_width=1,
                  annotation_text="⚠ threshold", annotation_font=dict(size=9, color=C["warn"]))
    fig.update_layout(
        **CHART_BASE,
        height=195,
        title=dict(text="ICMP Spike Timeline", font=dict(size=11, color=C["muted"]), x=0),
        xaxis=dict(gridcolor=C["border"], tickfont=dict(size=9), color=C["muted"], zeroline=False, title=""),
        yaxis=dict(gridcolor=C["border"], tickfont=dict(size=9), color=C["muted"], range=[0,100], zeroline=False, title=""),
    )
    return fig

# ── Layout helpers ─────────────────────────────────────────────────────────────
def metric_card(cid_val, cid_sub, label, icon, color):
    return html.Div([
        html.Div(style={"height":"2px","background":color,"borderRadius":"2px 2px 0 0"}),
        html.Div([
            html.Div([
                html.Span(label.upper(), className="clabel"),
                html.Span(icon, className="cicon"),
            ], className="crow"),
            html.Div("—", id=cid_val, className="cval", style={"color":color}),
            html.Div("loading...", id=cid_sub, className="csub"),
        ], className="cinner"),
    ], className="mcard")

def panel(children, title=""):
    return html.Div([
        html.Div(title, className="ptitle") if title else None,
        *children,
    ], className="panel")

# ── App setup ──────────────────────────────────────────────────────────────────
app = dash.Dash(__name__, suppress_callback_exceptions=True)
app.title = "NTA · CSC412"

init_data, init_live = safe_load()

# ── Layout ─────────────────────────────────────────────────────────────────────
app.layout = html.Div([
    # ── Stores & intervals
    dcc.Store(id="data-store",    data=init_data),
    dcc.Store(id="live-store",    data=init_live),
    dcc.Store(id="tl-store",      data=[]),
    dcc.Store(id="spike-store",   data={"on":False,"i":0}),
    dcc.Store(id="reload-store",  data={"on":False,"p":0}),
    dcc.Store(id="boot-store",    data={"on":True,"i":0,"lines":[]}),
    dcc.Store(id="scan-store",    data={"on":False,"p":0}),
    dcc.Store(id="ts-store",      data=datetime.now().strftime("%H:%M:%S")),
    dcc.Store(id="packet-store",  data={"count":0,"target":0}),

    dcc.Interval(id="spike-int",   interval=420,  disabled=True),
    dcc.Interval(id="reload-int",  interval=80,   disabled=True),
    dcc.Interval(id="boot-int",    interval=340,  disabled=False),
    dcc.Interval(id="scan-int",    interval=60,   disabled=True),
    dcc.Interval(id="pkt-int",     interval=40,   disabled=True),
    dcc.Interval(id="pulse-int",   interval=3000, disabled=False),

    # ════════════════════════════════════════════
    # BOOT SCREEN  (shown until boot completes)
    # ════════════════════════════════════════════
    html.Div([
        html.Div([
            # ASCII-style logo
            html.Pre("""
  ███╗   ██╗████████╗ █████╗ 
  ████╗  ██║╚══██╔══╝██╔══██╗
  ██╔██╗ ██║   ██║   ███████║
  ██║╚██╗██║   ██║   ██╔══██║
  ██║ ╚████║   ██║   ██║  ██║
  ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝""", className="ascii-logo"),
            html.Div("Network Traffic Analyzer", className="boot-title"),
            html.Div("CSC412 · Team J & D Unlimited", className="boot-sub"),
            html.Div(className="boot-div"),
            html.Div(id="boot-lines", className="boot-lines"),
            html.Div([
                html.Div(id="boot-bar-fill", className="boot-bar-fill"),
            ], className="boot-bar"),
            html.Div(id="boot-pct", className="boot-pct"),
        ], className="boot-inner"),
    ], id="boot-screen", className="boot-screen"),

    # ════════════════════════════════════════════
    # MAIN DASHBOARD  (hidden until boot done)
    # ════════════════════════════════════════════
    html.Div([

        # ── Top bar
        html.Div([
            html.Div([
                html.Span("◈ ", style={"color":C["accent"],"fontSize":"18px"}),
                html.Span("Network Traffic Analyzer", className="htitle"),
                html.Span(" / CSC412", className="hslash"),
            ], className="hbrand"),
            html.Div([
                html.Div(id="live-pill", children="● LIVE", className="pill-live"),
                html.Div(id="ts-display", className="ts-display"),
            ], className="hright"),
        ], className="topbar"),

        # ── Metric cards
        html.Div([
            metric_card("m-total",   "m-total-sub",   "Packets",   "📦", C["tcp"]),
            metric_card("m-dom",     "m-dom-sub",     "Dominant",  "📊", C["udp"]),
            metric_card("m-threat",  "m-threat-sub",  "Threat",    "🚨", C["icmp"]),
            metric_card("m-status",  "m-status-sub",  "Status",    "⚡", C["accent"]),
        ], className="metrics-row"),

        # ── Main content
        html.Div([

            # LEFT column — controls
            html.Div([
                panel([
                    html.Div("Protocol", className="flabel"),
                    dcc.Dropdown(id="proto-dd",
                        options=[{"label":"All","value":"All"}]+[{"label":p,"value":p} for p in PROTOCOLS],
                        value="All", clearable=False, className="dd"),
                    html.Div(className="gap6"),
                    html.Div("Scenario", className="flabel"),
                    dcc.Dropdown(id="scen-dd",
                        options=[{"label":"All Scenarios","value":"All"}]+[{"label":s,"value":s} for s in SCENARIOS],
                        value="All", clearable=False, className="dd"),
                    html.Div(className="gap6"),
                    html.Div("Chart Type", className="flabel"),
                    dcc.Dropdown(id="chart-dd",
                        options=[{"label":"Bar","value":"Bar"},{"label":"Stacked Bar","value":"Stacked"},{"label":"Radar","value":"Radar"}],
                        value="Bar", clearable=False, className="dd"),
                ], "Filters"),

                html.Div(className="gap8"),

                panel([
                    # Scan / Reload button with animated states
                    html.Button([
                        html.Span(id="scan-icon", children="⟳"),
                        html.Span(id="scan-label", children=" Scan Network"),
                    ], id="reload-btn", n_clicks=0, className="btn-scan"),

                    html.Div(className="gap6"),
                    html.Div([
                        html.Div(id="scan-bar-fill", className="scan-fill"),
                    ], className="scan-track"),
                    html.Div(id="scan-text", children="idle", className="scan-text"),

                    html.Div(className="gap10"),

                    html.Button([
                        html.Span("⚡ "),
                        html.Span("Simulate Stress Test"),
                    ], id="spike-btn", n_clicks=0, className="btn-spike"),

                    html.Div(className="gap6"),

                    html.Button("↺  Reset", id="reset-btn", n_clicks=0, className="btn-reset"),

                    html.Div(id="sim-status", className="sim-status"),
                    html.Div(id="last-ts",    className="last-ts"),
                ], "Actions"),

                html.Div(className="gap8"),

                panel([
                    html.Div(id="alert-box", className="alert-box"),
                ], "Alert"),

            ], className="lcol"),

            # CENTER column — main chart + timeline
            html.Div([
                panel([
                    dcc.Graph(id="main-chart", config={"displayModeBar":False}),
                ], "Traffic Overview"),
                html.Div(className="gap8"),
                panel([
                    dcc.Graph(id="tl-chart", config={"displayModeBar":False}),
                ], "Threat Timeline"),
            ], className="ccol"),

            # RIGHT column — donut + insights
            html.Div([
                panel([
                    dcc.Graph(id="donut-chart", config={"displayModeBar":False}),
                ], "Composition"),
                html.Div(className="gap8"),
                panel([
                    html.Div(id="packet-ticker", className="pkt-ticker"),
                    html.Div(className="gap8"),
                    html.Ul(id="insights", className="insights"),
                ], "Live Feed"),
            ], className="rcol"),

        ], className="content"),

        # footer
        html.Div([
            html.Span("Team J & D Unlimited", style={"color":C["muted"]}),
            html.Span(" · CSC412 · Weeks 1–6 complete", style={"color":C["dim"]}),
            html.Span(" · Python · Scapy · Dash", style={"color":C["dim"]}),
        ], className="footer"),

    ], id="dashboard", style={"display":"none"}),

], className="shell")


# ══════════════════════════════════════════════════════════════════════════════
# CALLBACKS
# ══════════════════════════════════════════════════════════════════════════════

# ── Boot sequence ──────────────────────────────────────────────────────────────
@app.callback(
    Output("boot-lines",    "children"),
    Output("boot-bar-fill", "style"),
    Output("boot-pct",      "children"),
    Output("boot-store",    "data"),
    Output("boot-screen",   "style"),
    Output("dashboard",     "style"),
    Output("boot-int",      "disabled"),
    Input("boot-int",       "n_intervals"),
    State("boot-store",     "data"),
)
def advance_boot(_, store):
    i     = store["i"]
    lines = store["lines"]
    total = len(BOOT_MESSAGES)

    if i < total:
        lines = lines + [BOOT_MESSAGES[i]]
        pct   = int((i + 1) / total * 100)
        new_store = {"on": True, "i": i + 1, "lines": lines}

        line_els = []
        for j, ln in enumerate(lines):
            is_last = j == len(lines) - 1
            line_els.append(
                html.Div([
                    html.Span("▸ " if is_last else "✓ ",
                              style={"color": C["accent"] if is_last else C["ok"], "marginRight":"6px"}),
                    html.Span(ln, style={"color": C["text"] if is_last else C["muted"]}),
                ], className="boot-line")
            )

        bar_style = {"width": f"{pct}%"}
        return line_els, bar_style, f"{pct}%", new_store, {"display":"flex"}, {"display":"none"}, False

    else:
        # Boot complete — show dashboard
        return no_update, no_update, "100%", {"on":False,"i":i,"lines":lines}, \
               {"display":"none"}, {"display":"block"}, True


# ── Scan / Reload ──────────────────────────────────────────────────────────────
@app.callback(
    Output("reload-store",  "data"),
    Output("reload-int",    "disabled"),
    Output("scan-int",      "disabled"),
    Input("reload-btn",     "n_clicks"),
    prevent_initial_call=True,
)
def start_scan(_):
    return {"on": True, "p": 0}, False, False


@app.callback(
    Output("reload-store",  "data",   allow_duplicate=True),
    Output("reload-int",    "disabled", allow_duplicate=True),
    Output("data-store",    "data",   allow_duplicate=True),
    Output("live-store",    "data",   allow_duplicate=True),
    Output("ts-store",      "data",   allow_duplicate=True),
    Output("scan-int",      "disabled", allow_duplicate=True),
    Output("packet-store",  "data",   allow_duplicate=True),
    Input("reload-int",     "n_intervals"),
    State("reload-store",   "data"),
    prevent_initial_call=True,
)
def advance_reload(_, rs):
    if not rs["on"]:
        return rs, True, no_update, no_update, no_update, True, no_update
    p    = rs["p"]
    step = 5 if p < 60 else 3 if p < 85 else 1
    p   += step
    if p < 100:
        return {"on":True,"p":p}, False, no_update, no_update, no_update, False, no_update
    d, live = safe_load()
    total   = sum(sum(v) for v in d.values()) // 3
    return {"on":False,"p":100}, True, d, live, datetime.now().strftime("%H:%M:%S"), True, \
           {"count":0,"target":total}


@app.callback(
    Output("scan-bar-fill", "style"),
    Output("scan-text",     "children"),
    Output("scan-icon",     "children"),
    Output("scan-label",    "children"),
    Output("reload-btn",    "disabled"),
    Input("reload-store",   "data"),
)
def update_scan_ui(rs):
    p = rs["p"]
    if rs["on"]:
        phases = ["mounting pcap..","reading packets..","computing stats..","building charts..","finalizing.."]
        phase  = phases[min(int(p / 22), len(phases)-1)]
        return ({"width":f"{p}%"}, phase, "◌", " Scanning...", True)
    elif p >= 100:
        return ({"width":"100%"}, "scan complete ✓", "⟳", " Scan Network", False)
    return ({"width":"0%"}, "idle", "⟳", " Scan Network", False)


# ── Packet count ticker ────────────────────────────────────────────────────────
@app.callback(
    Output("packet-store",  "data",   allow_duplicate=True),
    Output("pkt-int",       "disabled", allow_duplicate=True),
    Input("packet-store",   "data"),
    prevent_initial_call=True,
)
def start_pkt_ticker(ps):
    if ps["target"] > 0 and ps["count"] == 0:
        return ps, False
    return no_update, no_update


@app.callback(
    Output("packet-store",  "data",   allow_duplicate=True),
    Output("pkt-int",       "disabled", allow_duplicate=True),
    Output("packet-ticker", "children"),
    Input("pkt-int",        "n_intervals"),
    State("packet-store",   "data"),
    prevent_initial_call=True,
)
def tick_packets(_, ps):
    if ps["target"] == 0:
        return ps, True, no_update
    step  = max(1, ps["target"] // 30)
    count = min(ps["count"] + step, ps["target"])
    done  = count >= ps["target"]
    el    = html.Div([
        html.Span(f"{count:,}", style={"color":C["tcp"],"fontSize":"22px","fontWeight":"700"}),
        html.Span(" packets analyzed", style={"color":C["muted"],"fontSize":"10px","marginLeft":"6px"}),
        html.Div([
            html.Div("TCP",  style={"color":C["tcp"],"fontSize":"9px"}),
            html.Div("UDP",  style={"color":C["udp"],"fontSize":"9px"}),
            html.Div("ICMP", style={"color":C["icmp"],"fontSize":"9px"}),
        ], style={"display":"flex","gap":"10px","marginTop":"4px"}),
    ])
    return {"count":count,"target":ps["target"]}, done, el


# ── Spike simulation ───────────────────────────────────────────────────────────
@app.callback(
    Output("spike-store",   "data"),
    Output("tl-store",      "data"),
    Output("spike-int",     "disabled"),
    Input("spike-btn",      "n_clicks"),
    Input("reset-btn",      "n_clicks"),
    prevent_initial_call=True,
)
def handle_spike_btns(sim, rst):
    ctx = callback_context
    if not ctx.triggered:
        return no_update, no_update, True
    t = ctx.triggered[0]["prop_id"].split(".")[0]
    if t == "spike-btn":
        return {"on":True,"i":0}, [], False
    return {"on":False,"i":0}, [], True


@app.callback(
    Output("spike-store",   "data",   allow_duplicate=True),
    Output("tl-store",      "data",   allow_duplicate=True),
    Output("spike-int",     "disabled", allow_duplicate=True),
    Input("spike-int",      "n_intervals"),
    State("spike-store",    "data"),
    State("tl-store",       "data"),
    prevent_initial_call=True,
)
def advance_spike(_, ss, tl):
    if not ss["on"]:
        return ss, tl, True
    i = ss["i"]
    if i >= len(SPIKE_SEQ):
        return {"on":False,"i":0}, tl, True
    return {"on":True,"i":i+1}, tl+[SPIKE_SEQ[i]], False


# ── Charts ─────────────────────────────────────────────────────────────────────
@app.callback(
    Output("main-chart",  "figure"),
    Output("donut-chart", "figure"),
    Output("insights",    "children"),
    Input("data-store",   "data"),
    Input("proto-dd",     "value"),
    Input("scen-dd",      "value"),
    Input("chart-dd",     "value"),
)
def update_charts(data, pf, sf, ct):
    ins = []
    for i, s in enumerate(SCENARIOS):
        vals = {p: data[p][i] for p in PROTOCOLS}
        dom  = max(vals, key=vals.get)
        col  = C[dom.lower()]
        ins.append(html.Li([
            html.Span(f"{s}:", style={"color":C["muted"],"fontSize":"9px"}),
            html.Span(f" {dom} {vals[dom]}%", style={"color":col,"fontWeight":"700","fontSize":"10px"}),
        ], style={"marginBottom":"4px"}))
    return build_bar(data, pf, sf, ct), build_donut(data, sf), ins


@app.callback(
    Output("tl-chart", "figure"),
    Input("tl-store",  "data"),
)
def update_tl(tl):
    return build_timeline(tl)


# ── Metrics + alerts ───────────────────────────────────────────────────────────
@app.callback(
    Output("m-total",     "children"),
    Output("m-total-sub", "children"),
    Output("m-dom",       "children"),
    Output("m-dom-sub",   "children"),
    Output("m-threat",    "children"),
    Output("m-threat-sub","children"),
    Output("m-status",    "children"),
    Output("m-status-sub","children"),
    Output("live-pill",   "children"),
    Output("live-pill",   "className"),
    Output("alert-box",   "children"),
    Output("sim-status",  "children"),
    Output("last-ts",     "children"),
    Output("ts-display",  "children"),
    Input("data-store",   "data"),
    Input("tl-store",     "data"),
    Input("ts-store",     "data"),
    Input("live-store",   "data"),
)
def update_metrics(data, tl, ts, live):
    total = sum(sum(v) for v in data.values()) // 3
    dom, dom_s = dominant(data)
    peak  = max(tl) if tl else 0

    if peak >= 70:
        pill, pcls = "⚠ ALERT", "pill-alert pulse"
        alert = html.Div([
            html.Div("ICMP spike detected", style={"color":C["icmp"],"fontWeight":"700","fontSize":"11px"}),
            html.Div("ICMP > 70% — possible ping flood attack", style={"color":C["muted"],"fontSize":"10px","marginTop":"3px"}),
        ])
        threat, threat_s = f"{peak}%", "⚠ above threshold"
        sim_s = "threat pattern observed"
    elif tl:
        pill, pcls = "◎ WATCH", "pill-watch pulse-soft"
        alert = html.Div([
            html.Div("Simulation running", style={"color":C["warn"],"fontWeight":"700","fontSize":"11px"}),
            html.Div("traffic below threshold", style={"color":C["muted"],"fontSize":"10px","marginTop":"3px"}),
        ])
        threat, threat_s = f"{peak}%", "monitoring"
        sim_s = "simulation in progress..."
    else:
        pill, pcls = "● LIVE", "pill-live pulse-soft"
        alert = html.Div([
            html.Div("No anomalies detected", style={"color":C["ok"],"fontWeight":"700","fontSize":"11px"}),
            html.Div("system monitoring normal traffic", style={"color":C["muted"],"fontSize":"10px","marginTop":"3px"}),
        ])
        threat, threat_s = "0%", "all clear"
        sim_s = "ready"

    src  = "live PCAP data" if live else "demo data"
    stat = "ONLINE" if live else "DEMO MODE"

    return (
        f"{total:,}", f"from 3 PCAP files",
        dom, dom_s,
        threat, threat_s,
        stat, src,
        pill, pcls,
        alert, sim_s, f"last scan: {ts}",
        f"◷ {ts}",
    )


# ── Pulse — random packet count flicker ───────────────────────────────────────
@app.callback(
    Output("m-total", "children", allow_duplicate=True),
    Input("pulse-int", "n_intervals"),
    State("data-store", "data"),
    State("reload-store", "data"),
    prevent_initial_call=True,
)
def pulse_total(_, data, rs):
    if rs["on"]:
        return no_update
    base  = sum(sum(v) for v in data.values()) // 3
    jitter = random.randint(-3, 3)
    return f"{(base + jitter):,}"


def open_browser():
    webbrowser.open_new("http://127.0.0.1:8050/")


if __name__ == "__main__":
    threading.Timer(1.2, open_browser).start()
    app.run(debug=False, use_reloader=False)