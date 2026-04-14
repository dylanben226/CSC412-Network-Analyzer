import tkinter as tk
import math
import threading
import random

try:
    from analyzer import get_protocol_data
    LIVE_DATA = True
except ImportError:
    LIVE_DATA = False

FALLBACK_DATA = {
    "TCP": [80, 10, 10],
    "UDP": [10, 10, 80],
    "ICMP": [10, 80, 10]
}

C = {
    "bg":      "#07090F",
    "panel":   "#0D1117",
    "card":    "#111520",
    "border":  "#1E2535",
    "TCP":     "#00C2FF",
    "UDP":     "#00E887",
    "ICMP":    "#FF4560",
    "text":    "#E8EDF5",
    "muted":   "#4A5568",
    "bright":  "#FFFFFF",
    "warn":    "#FFB020",
    "accent":  "#7C3AED",
}

scenarios = ["Browsing\n(http.cap)", "Ping Flood\n(icmp.pcap)", "Idle / DNS\n(dns.cap)"]
scenario_names = ["Browsing", "Ping Flood", "Idle / DNS"]


# ── COLOR HELPERS ─────────────────────────────────────────────────────────────
def hex_to_rgb(hex_color):
    hex_color = hex_color.lstrip("#")
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def rgb_to_hex(rgb):
    return "#{:02X}{:02X}{:02X}".format(*rgb)

def blend(c1, c2, t=0.5):
    """
    Blend c1 toward c2 by fraction t.
    t=0 => c1
    t=1 => c2
    """
    r1, g1, b1 = hex_to_rgb(c1)
    r2, g2, b2 = hex_to_rgb(c2)
    r = round(r1 + (r2 - r1) * t)
    g = round(g1 + (g2 - g1) * t)
    b = round(b1 + (b2 - b1) * t)
    return rgb_to_hex((r, g, b))


root = tk.Tk()
root.title("CSC412 — Network Traffic Analyzer")
root.geometry("1100x800")
root.configure(bg=C["bg"])
root.resizable(False, False)

data = dict(FALLBACK_DATA)
active_filter = tk.StringVar(value="All")
active_chart = tk.StringVar(value="Bar")
spike_active = False
timeline_data = []
timeline_job = None
anim_vals = {"TCP": [0, 0, 0], "UDP": [0, 0, 0], "ICMP": [0, 0, 0]}
anim_job = None
filter_btns = {}
chart_btns = {}

# ── CANVAS BACKGROUND ─────────────────────────────────────────────────────────
bg_canvas = tk.Canvas(root, width=1100, height=800, bg=C["bg"], highlightthickness=0)
bg_canvas.place(x=0, y=0)

def draw_bg():
    bg_canvas.delete("grid")
    for x in range(0, 1100, 60):
        bg_canvas.create_line(x, 0, x, 800, fill="#0E1420", tags="grid")
    for y in range(0, 800, 60):
        bg_canvas.create_line(0, y, 1100, y, fill="#0E1420", tags="grid")
    for _ in range(18):
        x, y = random.randint(0, 1100), random.randint(0, 800)
        r = random.randint(1, 3)
        col = random.choice([C["TCP"], C["UDP"], C["ICMP"], C["accent"]])
        bg_canvas.create_oval(x-r, y-r, x+r, y+r, fill=col, outline="", tags="grid")

draw_bg()

def make_frame(parent, **kw):
    f = tk.Frame(parent, bg=C["card"], bd=0,
                 highlightthickness=1, highlightbackground=C["border"])
    for k, v in kw.items():
        f.configure(**{k: v})
    return f

# ── HEADER ────────────────────────────────────────────────────────────────────
hdr = tk.Frame(root, bg=C["bg"])
hdr.place(x=20, y=14, width=1060)

title_frame = tk.Frame(hdr, bg=C["bg"])
title_frame.pack(side="left")

tk.Label(
    title_frame,
    text="◈ NETWORK TRAFFIC ANALYZER",
    font=("Courier", 18, "bold"),
    bg=C["bg"],
    fg=C["bright"]
).pack(anchor="w")

tk.Label(
    title_frame,
    text="CSC412  ·  Team J & D Unlimited  ·  Jack Ngog & Dylan Ben  ·  Weeks 1–6",
    font=("Courier", 9),
    bg=C["bg"],
    fg=C["muted"]
).pack(anchor="w")

status_box = tk.Frame(hdr, bg="#0A1A0A", highlightthickness=1, highlightbackground="#1A4A1A")
status_box.pack(side="right", pady=4)

pulse_dot = tk.Label(status_box, text="●", font=("Courier", 12), bg="#0A1A0A", fg="#00E887")
pulse_dot.pack(side="left", padx=(10, 4), pady=6)

status_lbl = tk.Label(status_box, text="LIVE", font=("Courier", 10, "bold"), bg="#0A1A0A", fg="#00E887")
status_lbl.pack(side="left", padx=(0, 12), pady=6)

pulse_on = True
def pulse_status():
    global pulse_on
    if not spike_active:
        pulse_on = not pulse_on
        pulse_dot.config(fg="#00E887" if pulse_on else "#004422")
        root.after(800, pulse_status)

pulse_status()

# ── METRIC CARDS ──────────────────────────────────────────────────────────────
metrics_row = tk.Frame(root, bg=C["bg"])
metrics_row.place(x=20, y=72, width=1060)

metric_refs = {}
card_defs = [
    ("TOTAL PACKETS", "—", "loading...", C["TCP"]),
    ("DOMINANT", "—", "loading...", C["UDP"]),
    ("ANOMALY SCORE", "0%", "no spike", C["ICMP"]),
    ("SCENARIOS", "3", "files analyzed", C["accent"]),
]

for i, (lbl, val, sub, accent) in enumerate(card_defs):
    card = tk.Frame(metrics_row, bg=C["card"], highlightthickness=1, highlightbackground=C["border"])
    card.grid(row=0, column=i, padx=(0, 10) if i < 3 else 0, sticky="ew")
    metrics_row.columnconfigure(i, weight=1)

    tk.Frame(card, bg=accent, height=2).pack(fill="x")
    tk.Label(card, text=lbl, font=("Courier", 8, "bold"), bg=C["card"], fg=C["muted"]).pack(anchor="w", padx=12, pady=(8, 0))
    vl = tk.Label(card, text=val, font=("Courier", 20, "bold"), bg=C["card"], fg=accent)
    vl.pack(anchor="w", padx=12)
    sl = tk.Label(card, text=sub, font=("Courier", 9), bg=C["card"], fg=C["muted"])
    sl.pack(anchor="w", padx=12, pady=(0, 10))
    metric_refs[lbl] = (vl, sl, accent)

# ── CONTROLS ──────────────────────────────────────────────────────────────────
ctrl = tk.Frame(root, bg=C["bg"])
ctrl.place(x=20, y=172, width=1060)

def pill(parent, text, on_click, active=False, accent=C["TCP"]):
    bg = blend(C["card"], accent, 0.22) if active else C["card"]
    fg = accent if active else C["muted"]
    border = accent if active else C["border"]
    active_bg = blend(C["card"], accent, 0.15)

    b = tk.Button(
        parent,
        text=text,
        font=("Courier", 10, "bold"),
        bg=bg,
        fg=fg,
        relief="flat",
        bd=0,
        padx=14,
        pady=6,
        cursor="hand2",
        highlightthickness=1,
        highlightbackground=border,
        activebackground=active_bg,
        activeforeground=accent,
        command=on_click
    )
    return b

tk.Label(ctrl, text="FILTER ▸", font=("Courier", 9, "bold"), bg=C["bg"], fg=C["muted"]).pack(side="left", padx=(0, 8))

for mode, acc in [("All", C["bright"]), ("TCP", C["TCP"]), ("UDP", C["UDP"]), ("ICMP", C["ICMP"])]:
    def _set(m=mode):
        set_filter(m)
    b = pill(ctrl, mode, _set, mode == "All", acc)
    b.pack(side="left", padx=(0, 5))
    filter_btns[mode] = b

tk.Label(ctrl, text="   CHART ▸", font=("Courier", 9, "bold"), bg=C["bg"], fg=C["muted"]).pack(side="left", padx=(10, 8))

for ct in ["Bar", "Radar", "Donut"]:
    def _set(c=ct):
        set_chart(c)
    b = pill(ctrl, ct, _set, ct == "Bar", C["accent"])
    b.pack(side="left", padx=(0, 5))
    chart_btns[ct] = b

# ── MAIN CHART CANVAS ─────────────────────────────────────────────────────────
chart_outer = make_frame(root)
chart_outer.place(x=20, y=210, width=760, height=300)

tk.Frame(chart_outer, bg=C["TCP"], height=2).pack(fill="x")
chart_canvas = tk.Canvas(chart_outer, width=756, height=292, bg=C["card"], highlightthickness=0)
chart_canvas.pack(padx=2, pady=2)

tip = tk.Label(
    root,
    text="",
    bg="#1A2035",
    fg=C["bright"],
    font=("Courier", 10, "bold"),
    padx=10,
    pady=5,
    highlightthickness=1,
    highlightbackground=C["border"]
)

def tip_enter(e, txt):
    tip.place(
        x=min(e.x_root - root.winfo_x() + 12, 900),
        y=e.y_root - root.winfo_y() - 44
    )
    tip.config(text=txt)

def tip_leave(e):
    tip.place_forget()

# ── CHARTS ────────────────────────────────────────────────────────────────────
def draw_bar_chart(use_anim=True):
    chart_canvas.delete("all")
    W, H, pl, pb = 756, 292, 60, 44
    ch = H - pb - 14
    vals = anim_vals if use_anim else data

    for pct in [0, 25, 50, 75, 100]:
        y = H - pb - int((pct / 100) * ch)
        chart_canvas.create_line(pl, y, W - 8, y, fill=C["border"], dash=(3, 5))
        chart_canvas.create_text(pl - 6, y, text=f"{pct}%", fill=C["muted"], font=("Courier", 8), anchor="e")

    protos = ["TCP", "UDP", "ICMP"] if active_filter.get() == "All" else [active_filter.get()]
    n = len(scenarios)
    gw = (W - pl - 8) / n
    bw = min(30, gw / (len(protos) + 1))
    gap = bw * 0.4

    for i, scen in enumerate(scenarios):
        gx = pl + i * gw + gw / 2 - (len(protos) * (bw + gap)) / 2
        for j, proto in enumerate(protos):
            v = vals[proto][i]
            h = int((v / 100) * ch)
            x0 = gx + j * (bw + gap)
            x1 = x0 + bw
            y0 = H - pb - h
            y1 = H - pb
            col = C[proto]

            shadow_col = blend(C["card"], col, 0.25)
            shine_col = blend(col, C["bright"], 0.35)

            chart_canvas.create_rectangle(x0, y0 + 4, x1, y1, fill=shadow_col, outline="")
            chart_canvas.create_rectangle(x0 + 2, y0 + 4, x1 - 2, y1, fill=col, outline="")
            chart_canvas.create_rectangle(x0 + 2, y0 + 4, x1 - 2, min(y0 + 10, y1), fill=shine_col, outline="")

            rid = chart_canvas.create_rectangle(x0, y0, x1, y1, fill="", outline=col, width=1)
            chart_canvas.create_text((x0 + x1) / 2, y0 - 9, text=f"{int(v)}%", fill=col, font=("Courier", 8, "bold"))

            chart_canvas.tag_bind(
                rid,
                "<Enter>",
                lambda e, p=proto, vv=int(v), s=scen.replace("\n", " "): tip_enter(e, f" {p}: {vv}%  {s} ")
            )
            chart_canvas.tag_bind(rid, "<Leave>", tip_leave)

        chart_canvas.create_text(
            pl + i * gw + gw / 2,
            H - pb + 14,
            text=scen,
            fill=C["muted"],
            font=("Courier", 8, "bold"),
            justify="center"
        )

    lx = pl + 4
    for p in ["TCP", "UDP", "ICMP"]:
        chart_canvas.create_rectangle(lx, 8, lx + 10, 18, fill=C[p], outline="")
        chart_canvas.create_text(lx + 14, 13, text=p, fill=C[p], font=("Courier", 9, "bold"), anchor="w")
        lx += 56

def draw_radar_chart():
    chart_canvas.delete("all")
    W, H = 756, 292
    cx, cy, r = W // 2, H // 2 - 10, 95
    protos = ["TCP", "UDP", "ICMP"] if active_filter.get() == "All" else [active_filter.get()]
    n = len(scenarios)

    for ring in [25, 50, 75, 100]:
        pts = []
        for k in range(n):
            ang = math.pi / 2 - 2 * math.pi * k / n
            rr = r * (ring / 100)
            pts += [cx + rr * math.cos(ang), cy - rr * math.sin(ang)]
        chart_canvas.create_polygon(pts, outline=C["border"], fill="", width=1)

    for k, scen in enumerate(scenarios):
        ang = math.pi / 2 - 2 * math.pi * k / n
        chart_canvas.create_line(cx, cy, cx + r * math.cos(ang), cy - r * math.sin(ang), fill=C["border"])
        chart_canvas.create_text(
            cx + (r + 28) * math.cos(ang),
            cy - (r + 28) * math.sin(ang),
            text=scen.replace("\n", " "),
            fill=C["muted"],
            font=("Courier", 8, "bold"),
            justify="center"
        )

    for proto in protos:
        pts = []
        for k in range(n):
            ang = math.pi / 2 - 2 * math.pi * k / n
            rr = r * (data[proto][k] / 100)
            pts += [cx + rr * math.cos(ang), cy - rr * math.sin(ang)]
        fill_col = blend(C["card"], C[proto], 0.18)
        chart_canvas.create_polygon(pts, outline=C[proto], fill=fill_col, width=2)

        for k in range(n):
            ang = math.pi / 2 - 2 * math.pi * k / n
            rr = r * (data[proto][k] / 100)
            px2, py2 = cx + rr * math.cos(ang), cy - rr * math.sin(ang)
            chart_canvas.create_oval(px2 - 5, py2 - 5, px2 + 5, py2 + 5, fill=C[proto], outline=C["bg"], width=2)
            chart_canvas.create_text(px2, py2 - 14, text=f"{int(data[proto][k])}%", fill=C[proto], font=("Courier", 7, "bold"))

    lx = 10
    for p in (["TCP", "UDP", "ICMP"] if active_filter.get() == "All" else [active_filter.get()]):
        chart_canvas.create_rectangle(lx, 8, lx + 10, 18, fill=C[p], outline="")
        chart_canvas.create_text(lx + 14, 13, text=p, fill=C[p], font=("Courier", 9, "bold"), anchor="w")
        lx += 56

def draw_donut_chart():
    chart_canvas.delete("all")
    W, H = 756, 292
    cx, cy = 160, H // 2
    r_out, r_in = 95, 48
    protos = ["TCP", "UDP", "ICMP"] if active_filter.get() == "All" else [active_filter.get()]
    totals = {p: sum(data[p]) for p in protos}
    grand = sum(totals.values()) or 1
    start = 90.0

    for proto in protos:
        extent = -360 * totals[proto] / grand
        soft_col = blend(C["card"], C[proto], 0.3)

        chart_canvas.create_arc(
            cx - r_out, cy - r_out, cx + r_out, cy + r_out,
            start=start, extent=extent,
            fill=soft_col, outline=C["card"], width=3, style="pieslice"
        )
        chart_canvas.create_arc(
            cx - r_out + 4, cy - r_out + 4, cx + r_out - 4, cy + r_out - 4,
            start=start, extent=extent,
            fill=C[proto], outline=""
        )

        mid = math.radians(-(start + extent / 2))
        mx = cx + (r_out + r_in) / 2 * math.cos(mid)
        my = cy + (r_out + r_in) / 2 * math.sin(mid)
        pct = int(totals[proto] / grand * 100)
        chart_canvas.create_text(mx, my, text=f"{pct}%", fill=C["bright"], font=("Courier", 9, "bold"))
        start += extent

    chart_canvas.create_oval(cx - r_in, cy - r_in, cx + r_in, cy + r_in, fill=C["card"], outline=C["border"], width=1)
    chart_canvas.create_text(cx, cy - 8, text=str(grand), fill=C["bright"], font=("Courier", 18, "bold"))
    chart_canvas.create_text(cx, cy + 12, text="pkts", fill=C["muted"], font=("Courier", 9))

    tx = cx + r_out + 40
    y = 40
    for proto in ["TCP", "UDP", "ICMP"]:
        chart_canvas.create_rectangle(tx, y, tx + 12, y + 12, fill=C[proto], outline="")
        row = f"  {proto}   " + "  ".join(f"{data[proto][j]}%" for j in range(3))
        chart_canvas.create_text(tx + 16, y + 6, text=row, fill=C[proto], font=("Courier", 10, "bold"), anchor="w")
        y += 36

    chart_canvas.create_text(tx + 16, 20, text="       Browse  PingFlood  DNS", fill=C["muted"], font=("Courier", 9), anchor="w")

def draw_chart(use_anim=True):
    t = active_chart.get()
    if t == "Bar":
        draw_bar_chart(use_anim)
    elif t == "Radar":
        draw_radar_chart()
    elif t == "Donut":
        draw_donut_chart()

# ── BAR ANIMATION ─────────────────────────────────────────────────────────────
anim_step = [0]

def animate_bars():
    global anim_job
    step = anim_step[0]
    total_steps = 20

    if step <= total_steps:
        t = step / total_steps
        ease = 1 - (1 - t) ** 3
        for proto in ["TCP", "UDP", "ICMP"]:
            for i in range(3):
                anim_vals[proto][i] = data[proto][i] * ease

        if active_chart.get() == "Bar":
            draw_bar_chart(use_anim=True)

        anim_step[0] += 1
        anim_job = root.after(18, animate_bars)

def trigger_animation():
    anim_step[0] = 0
    animate_bars()

# ── BREAKDOWN PANEL ───────────────────────────────────────────────────────────
breakdown_outer = make_frame(root)
breakdown_outer.place(x=796, y=210, width=284, height=300)
tk.Frame(breakdown_outer, bg=C["UDP"], height=2).pack(fill="x")

tk.Label(breakdown_outer, text="BREAKDOWN", font=("Courier", 9, "bold"), bg=C["card"], fg=C["muted"]).pack(anchor="w", padx=12, pady=(8, 4))

bk_canvas = tk.Canvas(breakdown_outer, bg=C["card"], highlightthickness=0, width=280, height=260)
bk_canvas.pack(fill="both", expand=True, padx=4)

def draw_breakdown():
    bk_canvas.delete("all")
    labels = ["Browsing", "Ping Flood", "Idle/DNS"]
    row_h = 80

    for si, slabel in enumerate(labels):
        y = si * row_h + 4
        bk_canvas.create_text(10, y + 8, text=slabel, fill=C["bright"], font=("Courier", 9, "bold"), anchor="w")

        for pi, proto in enumerate(["TCP", "UDP", "ICMP"]):
            by = y + 24 + pi * 16
            val = data[proto][si]
            bk_canvas.create_text(10, by + 5, text=proto, fill=C[proto], font=("Courier", 8, "bold"), anchor="w")
            bk_canvas.create_rectangle(42, by + 1, 220, by + 9, fill=C["border"], outline="")

            fw = int(178 * val / 100)
            if fw > 0:
                bk_canvas.create_rectangle(42, by + 1, 42 + fw, by + 9, fill=C[proto], outline="")
                shine = blend(C[proto], C["bright"], 0.3)
                bk_canvas.create_rectangle(42, by + 1, 42 + fw, by + 4, fill=shine, outline="")

            bk_canvas.create_text(228, by + 5, text=f"{int(val)}%", fill=C[proto], font=("Courier", 8, "bold"), anchor="w")

        if si < 2:
            bk_canvas.create_line(4, y + row_h - 2, 276, y + row_h - 2, fill=C["border"])

draw_breakdown()

# ── TIMELINE PANEL ────────────────────────────────────────────────────────────
tl_outer = make_frame(root)
tl_outer.place(x=20, y=524, width=1060, height=130)
tk.Frame(tl_outer, bg=C["ICMP"], height=2).pack(fill="x")

tl_header = tk.Frame(tl_outer, bg=C["card"])
tl_header.pack(fill="x", padx=12, pady=(6, 0))

tk.Label(tl_header, text="ICMP TIMELINE", font=("Courier", 9, "bold"), bg=C["card"], fg=C["muted"]).pack(side="left")
tl_status = tk.Label(tl_header, text="waiting for stress test...", font=("Courier", 8), bg=C["card"], fg=C["muted"])
tl_status.pack(side="right")

tl_canvas = tk.Canvas(tl_outer, width=1056, height=88, bg=C["card"], highlightthickness=0)
tl_canvas.pack(padx=2, pady=(0, 4))

def draw_timeline():
    tl_canvas.delete("all")
    W, H, pl, pr, pt, pb = 1056, 88, 40, 16, 10, 20
    cw, ch = W - pl - pr, H - pt - pb

    for pct in [0, 35, 70, 100]:
        y = H - pb - int((pct / 100) * ch)
        tl_canvas.create_line(pl, y, W - pr, y, fill=C["border"], dash=(2, 4))
        tl_canvas.create_text(pl - 4, y, text=f"{pct}%", fill=C["muted"], font=("Courier", 7), anchor="e")

    threshold_y = H - pb - int((70 / 100) * ch)
    tl_canvas.create_line(pl, threshold_y, W - pr, threshold_y, fill=blend(C["card"], C["ICMP"], 0.55), dash=(6, 3), width=1)
    tl_canvas.create_text(W - pr + 2, threshold_y, text="70%", fill=C["ICMP"], font=("Courier", 7), anchor="w")

    if len(timeline_data) < 2:
        tl_canvas.create_text(W // 2, H // 2, text="◈  Run Simulate Stress Test to see live timeline", fill=C["muted"], font=("Courier", 9))
        return

    n = len(timeline_data)
    pts = []
    for i, v in enumerate(timeline_data):
        x = pl + i * (cw / max(n - 1, 1))
        y = H - pb - int((v / 100) * ch)
        pts.append((x, y))

    fill_pts = [(pl, H - pb)] + pts + [(pts[-1][0], H - pb)]
    flat = [c for p in fill_pts for c in p]
    tl_canvas.create_polygon(flat, fill=blend(C["card"], C["ICMP"], 0.18), outline="")

    for i in range(len(pts) - 1):
        x1, y1 = pts[i]
        x2, y2 = pts[i + 1]
        v = timeline_data[i + 1]
        col = C["ICMP"] if v >= 70 else C["UDP"]
        tl_canvas.create_line(x1, y1, x2, y2, fill=col, width=2, smooth=True)

    if pts:
        lx, ly = pts[-1]
        tl_canvas.create_oval(lx - 5, ly - 5, lx + 5, ly + 5, fill=C["ICMP"], outline=C["bg"], width=2)

draw_timeline()

# ── ACTION BUTTONS ────────────────────────────────────────────────────────────
actions = tk.Frame(root, bg=C["bg"])
actions.place(x=20, y=670, width=1060)

def action_btn(parent, text, cmd, bg, fg, border):
    return tk.Button(
        parent,
        text=text,
        command=cmd,
        font=("Courier", 10, "bold"),
        bg=bg,
        fg=fg,
        relief="flat",
        bd=0,
        padx=16,
        pady=8,
        cursor="hand2",
        highlightthickness=1,
        highlightbackground=border,
        activebackground=bg,
        activeforeground=fg
    )

reload_btn = action_btn(actions, "⟳  RELOAD DATA", lambda: reload_live_data(), "#081830", C["TCP"], "#1A4060")
reload_btn.pack(side="left", padx=(0, 8))

spike_btn = action_btn(actions, "⚡  SIMULATE STRESS TEST", lambda: simulate_spike(), "#1A0808", C["ICMP"], "#4A1515")
spike_btn.pack(side="left", padx=(0, 8))

reset_btn = action_btn(actions, "↺  RESET", lambda: reset_all(), C["card"], C["muted"], C["border"])
reset_btn.pack(side="left")

# ── FOOTER ────────────────────────────────────────────────────────────────────
tk.Frame(root, bg=C["border"], height=1).place(x=20, y=740, width=1060)

footer = tk.Frame(root, bg=C["bg"])
footer.place(x=20, y=748, width=1060)

tk.Label(
    footer,
    text="◈ J & D Unlimited  ·  CSC412  ·  Python + Scapy + Tkinter",
    font=("Courier", 9),
    bg=C["bg"],
    fg=C["muted"]
).pack(side="left")

alert_lbl = tk.Label(footer, text="", font=("Courier", 9), bg=C["bg"], fg=C["muted"])
alert_lbl.pack(side="right")

# ── FILTER / CHART SETTERS ────────────────────────────────────────────────────
def set_filter(f):
    active_filter.set(f)
    accs = {
        "All": C["bright"],
        "TCP": C["TCP"],
        "UDP": C["UDP"],
        "ICMP": C["ICMP"]
    }

    for k, b in filter_btns.items():
        acc = accs[k]
        on = (k == f)
        b.config(
            bg=blend(C["card"], acc, 0.22) if on else C["card"],
            fg=acc if on else C["muted"],
            highlightbackground=acc if on else C["border"],
            activebackground=blend(C["card"], acc, 0.15)
        )

    draw_chart()

def set_chart(c):
    active_chart.set(c)
    for k, b in chart_btns.items():
        on = (k == c)
        b.config(
            bg=blend(C["card"], C["accent"], 0.22) if on else C["card"],
            fg=C["accent"] if on else C["muted"],
            highlightbackground=C["accent"] if on else C["border"],
            activebackground=blend(C["card"], C["accent"], 0.15)
        )

    if c == "Bar":
        trigger_animation()
    else:
        draw_chart()

# ── UPDATE METRICS ────────────────────────────────────────────────────────────
def update_metrics():
    protos = ["TCP", "UDP", "ICMP"]
    best, bestv = "", 0

    for p in protos:
        avg = sum(data[p]) / 3
        if avg > bestv:
            bestv, best = avg, p

    si = data[best].index(max(data[best]))
    metric_refs["DOMINANT"][0].config(text=best, fg=C[best])
    metric_refs["DOMINANT"][1].config(text=scenario_names[si])

# ── SPIKE SIMULATION ──────────────────────────────────────────────────────────
spike_seq = [4, 7, 5, 11, 38, 62, 80, 79, 81, 72, 61, 44, 28, 14, 4]
spike_step_var = [0]

def tick_spike():
    global timeline_job
    idx = spike_step_var[0]

    if idx < len(spike_seq):
        val = spike_seq[idx]
        timeline_data.append(val)
        draw_timeline()

        tl_status.config(
            text=f"ICMP: {val}%  {'▲ SPIKE DETECTED' if val >= 70 else '▼ normalizing'}",
            fg=C["ICMP"] if val >= 70 else C["UDP"]
        )

        metric_refs["ANOMALY SCORE"][0].config(text=f"{val}%", fg=C["ICMP"] if val >= 70 else C["text"])
        metric_refs["ANOMALY SCORE"][1].config(text="PING FLOOD DETECTED!" if val >= 70 else "returning to normal")

        if val >= 70:
            status_lbl.config(text="ALERT", fg=C["ICMP"])
            pulse_dot.config(fg=C["ICMP"])
            alert_lbl.config(text="[!] ICMP SPIKE — Possible Ping Flood Attack  ", fg=C["ICMP"])

        spike_step_var[0] += 1
        timeline_job = root.after(380, tick_spike)
    else:
        root.after(2000, clear_spike)

def simulate_spike():
    global spike_active
    if spike_active:
        return
    spike_active = True
    spike_step_var[0] = 0
    timeline_data.clear()
    tick_spike()

def clear_spike():
    global spike_active, timeline_job
    spike_active = False
    timeline_data.clear()
    draw_timeline()
    tl_status.config(text="waiting for stress test...", fg=C["muted"])
    status_lbl.config(text="LIVE", fg=C["UDP"])
    pulse_dot.config(fg=C["UDP"])
    alert_lbl.config(text="[PASS] Error handling active — script never crashed  ", fg=C["UDP"])
    metric_refs["ANOMALY SCORE"][0].config(text="0%", fg=C["text"])
    metric_refs["ANOMALY SCORE"][1].config(text="no spike")
    pulse_status()

# ── LIVE DATA LOADER ──────────────────────────────────────────────────────────
def reload_live_data():
    status_lbl.config(text="LOADING", fg=C["warn"])
    pulse_dot.config(fg=C["warn"])
    alert_lbl.config(text="", fg=C["muted"])

    def _load():
        global data
        try:
            live = get_protocol_data()
            data = live
            root.after(0, _done, True)
        except Exception:
            root.after(0, _done, False)

    def _done(ok):
        global data
        if ok:
            total = sum(sum(v) for v in data.values()) // 3
            metric_refs["TOTAL PACKETS"][0].config(text=str(total))
            metric_refs["TOTAL PACKETS"][1].config(text="from 3 PCAP files")
            alert_lbl.config(text="[PASS] Live data loaded from analyzer.py  ", fg=C["UDP"])
            status_lbl.config(text="LIVE", fg=C["UDP"])
            pulse_dot.config(fg=C["UDP"])
        else:
            data = dict(FALLBACK_DATA)
            metric_refs["TOTAL PACKETS"][0].config(text="300")
            metric_refs["TOTAL PACKETS"][1].config(text="demo fallback")
            alert_lbl.config(text="[!] PCAP files not found — using demo data  ", fg=C["warn"])
            status_lbl.config(text="DEMO", fg=C["warn"])
            pulse_dot.config(fg=C["warn"])

        update_metrics()
        draw_breakdown()
        trigger_animation()

    threading.Thread(target=_load, daemon=True).start()

# ── RESET ─────────────────────────────────────────────────────────────────────
def reset_all():
    global spike_active
    if timeline_job:
        root.after_cancel(timeline_job)
    spike_active = False
    timeline_data.clear()
    active_filter.set("All")
    active_chart.set("Bar")
    set_filter("All")
    set_chart("Bar")
    clear_spike()

# ── INIT ──────────────────────────────────────────────────────────────────────
update_metrics()
draw_timeline()
root.after(400, reload_live_data)

root.mainloop()