import tkinter as tk
from tkinter import ttk
import math

# ── DATA ──────────────────────────────────────────────────────────────────────
scenarios = ["Browsing\n(http.cap)", "Ping Flood\n(icmp.pcap)", "Idle/DNS\n(dns.cap)"]
data = {
    "TCP":  [80, 10, 10],
    "UDP":  [10, 10, 80],
    "ICMP": [10, 80, 10],
}
COLORS = {
    "TCP":  "#378ADD",
    "UDP":  "#639922",
    "ICMP": "#E24B4A",
    "bg":   "#0F1117",
    "card": "#1A1D27",
    "grid": "#23263A",
    "text": "#E8EAF0",
    "muted":"#6B7280",
}

# ── ROOT ──────────────────────────────────────────────────────────────────────
root = tk.Tk()
root.title("CSC412 — Network Traffic Analyzer")
root.geometry("1000x720")
root.configure(bg=COLORS["bg"])
root.resizable(False, False)

# ── STATE ─────────────────────────────────────────────────────────────────────
active_filter   = tk.StringVar(value="All")
active_chart    = tk.StringVar(value="Bar")
scenario_idx    = tk.IntVar(value=-1)
spike_active    = False
timeline_data   = []
timeline_job    = None
filter_buttons  = {}
chart_buttons   = {}

# ── HELPERS ───────────────────────────────────────────────────────────────────
def hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

def blend(hex1, hex2, t):
    r1,g1,b1 = hex_to_rgb(hex1)
    r2,g2,b2 = hex_to_rgb(hex2)
    r = int(r1 + (r2-r1)*t)
    g = int(g1 + (g2-g1)*t)
    b = int(b1 + (b2-b1)*t)
    return f"#{r:02x}{g:02x}{b:02x}"

def dim(color): return blend(color, COLORS["bg"], 0.60)

# ── LAYOUT ────────────────────────────────────────────────────────────────────
# Header
hdr = tk.Frame(root, bg=COLORS["bg"])
hdr.pack(fill="x", padx=20, pady=(16, 0))

tk.Label(hdr, text="Network Traffic Analyzer",
         font=("Courier", 20, "bold"), bg=COLORS["bg"], fg=COLORS["text"]).pack(side="left")

status_frame = tk.Frame(hdr, bg="#1E2535", bd=0, highlightthickness=1,
                        highlightbackground="#2A3050")
status_frame.pack(side="right", pady=4)
status_dot = tk.Label(status_frame, text="●", font=("Arial", 10),
                      bg="#1E2535", fg="#22C55E")
status_dot.pack(side="left", padx=(8,2), pady=4)
status_label = tk.Label(status_frame, text="Monitoring",
                        font=("Courier", 10), bg="#1E2535", fg="#22C55E")
status_label.pack(side="left", padx=(0,10), pady=4)

tk.Label(root, text="CSC412 · Week 4 & 5 packet capture analysis",
         font=("Courier", 10), bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w", padx=20)

# ── METRIC CARDS ──────────────────────────────────────────────────────────────
metrics_frame = tk.Frame(root, bg=COLORS["bg"])
metrics_frame.pack(fill="x", padx=20, pady=(14,0))

metric_vals = {}
for i, (lbl, val, sub) in enumerate([
    ("Total Packets", "900", "across 3 captures"),
    ("Dominant Protocol", "TCP", "Browsing scenario"),
    ("Anomaly Score", "0%", "No spike detected"),
]):
    card = tk.Frame(metrics_frame, bg=COLORS["card"], bd=0,
                    highlightthickness=1, highlightbackground=COLORS["grid"])
    card.grid(row=0, column=i, padx=(0,10) if i<2 else 0, sticky="ew")
    metrics_frame.columnconfigure(i, weight=1)
    tk.Label(card, text=lbl, font=("Courier", 9), bg=COLORS["card"],
             fg=COLORS["muted"]).pack(anchor="w", padx=12, pady=(10,0))
    vl = tk.Label(card, text=val, font=("Courier", 18, "bold"),
                  bg=COLORS["card"], fg=COLORS["text"])
    vl.pack(anchor="w", padx=12)
    sl = tk.Label(card, text=sub, font=("Courier", 9),
                  bg=COLORS["card"], fg=COLORS["muted"])
    sl.pack(anchor="w", padx=12, pady=(0,10))
    metric_vals[lbl] = (vl, sl)

# ── CONTROLS ROW ──────────────────────────────────────────────────────────────
ctrl = tk.Frame(root, bg=COLORS["bg"])
ctrl.pack(fill="x", padx=20, pady=(14,0))

tk.Label(ctrl, text="FILTER", font=("Courier", 9, "bold"),
         bg=COLORS["bg"], fg=COLORS["muted"]).pack(side="left", padx=(0,8))

def set_filter(f):
    active_filter.set(f)
    for k,b in filter_buttons.items():
        if k == f:
            b.config(bg=COLORS.get(k, "#2A3050"), fg=COLORS["text"],
                     highlightbackground=COLORS.get(k, "#4A5070"))
        else:
            b.config(bg=COLORS["card"], fg=COLORS["muted"],
                     highlightbackground=COLORS["grid"])
    draw_chart()
    update_metrics()

for mode in ["All", "TCP", "UDP", "ICMP"]:
    col = COLORS.get(mode, "#2A3050")
    b = tk.Button(ctrl, text=mode, font=("Courier", 10, "bold"),
                  bg=COLORS["card"] if mode != "All" else "#2A3050",
                  fg=COLORS["text"] if mode == "All" else COLORS["muted"],
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
                  highlightthickness=1,
                  highlightbackground=COLORS["grid"] if mode != "All" else "#4A5070",
                  command=lambda m=mode: set_filter(m))
    b.pack(side="left", padx=(0,6))
    filter_buttons[mode] = b

tk.Label(ctrl, text="  CHART", font=("Courier", 9, "bold"),
         bg=COLORS["bg"], fg=COLORS["muted"]).pack(side="left", padx=(12,8))

def set_chart(c):
    active_chart.set(c)
    for k,b in chart_buttons.items():
        b.config(bg="#2A3050" if k==c else COLORS["card"],
                 fg=COLORS["text"] if k==c else COLORS["muted"],
                 highlightbackground="#4A5070" if k==c else COLORS["grid"])
    draw_chart()

for ct in ["Bar", "Radar", "Donut"]:
    b = tk.Button(ctrl, text=ct, font=("Courier", 10),
                  bg=COLORS["card"], fg=COLORS["muted"],
                  relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
                  highlightthickness=1, highlightbackground=COLORS["grid"],
                  command=lambda c=ct: set_chart(c))
    b.pack(side="left", padx=(0,6))
    chart_buttons[ct] = b

# Mark defaults active
filter_buttons["All"].config(bg="#2A3050", fg=COLORS["text"], highlightbackground="#4A5070")
chart_buttons["Bar"].config(bg="#2A3050", fg=COLORS["text"], highlightbackground="#4A5070")

# ── MAIN CHART CANVAS ─────────────────────────────────────────────────────────
chart_frame = tk.Frame(root, bg=COLORS["card"], bd=0,
                       highlightthickness=1, highlightbackground=COLORS["grid"])
chart_frame.pack(fill="x", padx=20, pady=(12,0))

canvas = tk.Canvas(chart_frame, width=960, height=260,
                   bg=COLORS["card"], highlightthickness=0)
canvas.pack(padx=12, pady=12)

tooltip = tk.Label(root, text="", bg="#2A3050", fg=COLORS["text"],
                   font=("Courier", 10, "bold"), padx=8, pady=4,
                   relief="flat", bd=0, highlightthickness=1,
                   highlightbackground="#4A5070")

def on_enter(e, proto, val, scenario):
    tooltip.place(x=e.x_root - root.winfo_x() + 10,
                  y=e.y_root - root.winfo_y() - 40)
    tooltip.config(text=f"  {proto}: {val}%  |  {scenario}  ")

def on_leave(e):
    tooltip.place_forget()

def draw_bar_chart():
    canvas.delete("all")
    W, H, pad_l, pad_b = 960, 260, 55, 40
    chart_h = H - pad_b - 10

    # Grid lines
    for pct in [0, 25, 50, 75, 100]:
        y = H - pad_b - int((pct/100)*chart_h)
        canvas.create_line(pad_l, y, W-10, y, fill=COLORS["grid"], dash=(4,4))
        canvas.create_text(pad_l-8, y, text=f"{pct}%",
                           fill=COLORS["muted"], font=("Courier", 8), anchor="e")

    protos = ["TCP","UDP","ICMP"] if active_filter.get()=="All" else [active_filter.get()]
    n_scen = len(scenarios)
    group_w = (W - pad_l - 10) / n_scen
    bar_w = min(28, group_w / (len(protos)+1))
    gap   = bar_w * 0.35

    for i, scen in enumerate(scenarios):
        gx = pad_l + i * group_w + group_w/2 - (len(protos)*(bar_w+gap))/2
        for j, proto in enumerate(protos):
            val = data[proto][i]
            h   = int((val/100)*chart_h)
            x0  = gx + j*(bar_w+gap)
            x1  = x0 + bar_w
            y0  = H - pad_b - h
            y1  = H - pad_b
            # Rounded top
            rid = canvas.create_rectangle(x0, y0+6, x1, y1, fill=COLORS[proto], outline="")
            canvas.create_arc(x0, y0, x1, y0+12, start=0, extent=180,
                              fill=COLORS[proto], outline="")
            # Value label
            canvas.create_text((x0+x1)/2, y0-8, text=f"{val}%",
                                fill=COLORS[proto], font=("Courier", 8, "bold"))
            for item in [rid]:
                canvas.tag_bind(item, "<Enter>",
                                lambda e, p=proto, v=val, s=scen.replace("\n"," "): on_enter(e,p,v,s))
                canvas.tag_bind(item, "<Leave>", on_leave)

        label = scen.replace("\n", "\n")
        canvas.create_text(pad_l + i*group_w + group_w/2, H - pad_b + 14,
                           text=scen, fill=COLORS["muted"],
                           font=("Courier", 9, "bold"), justify="center")

    # Legend
    lx = pad_l
    protos_all = ["TCP","UDP","ICMP"]
    for p in protos_all:
        canvas.create_rectangle(lx, 8, lx+10, 18, fill=COLORS[p], outline="")
        canvas.create_text(lx+14, 13, text=p, fill=COLORS["muted"],
                           font=("Courier", 9), anchor="w")
        lx += 60

def draw_radar_chart():
    canvas.delete("all")
    W, H = 960, 260
    cx, cy, r = W//2, H//2, 90
    protos = ["TCP","UDP","ICMP"] if active_filter.get()=="All" else [active_filter.get()]
    n = len(scenarios)

    # Rings
    for pct in [25,50,75,100]:
        pts = []
        for k in range(n):
            ang = math.pi/2 - 2*math.pi*k/n
            rr = r*(pct/100)
            pts += [cx + rr*math.cos(ang), cy - rr*math.sin(ang)]
        canvas.create_polygon(pts, outline=COLORS["grid"], fill="", width=1)
        canvas.create_text(cx + r*(pct/100)*math.cos(math.pi/2),
                           cy - r*(pct/100)*math.sin(math.pi/2) - 6,
                           text=f"{pct}%", fill=COLORS["muted"], font=("Courier", 7))

    # Axes & labels
    for k, scen in enumerate(scenarios):
        ang = math.pi/2 - 2*math.pi*k/n
        canvas.create_line(cx, cy, cx+r*math.cos(ang), cy-r*math.sin(ang),
                           fill=COLORS["grid"])
        canvas.create_text(cx+(r+24)*math.cos(ang), cy-(r+24)*math.sin(ang),
                           text=scen.replace("\n"," "), fill=COLORS["muted"],
                           font=("Courier", 8), justify="center")

    for proto in protos:
        pts = []
        for k in range(n):
            ang = math.pi/2 - 2*math.pi*k/n
            rr = r*(data[proto][k]/100)
            pts += [cx+rr*math.cos(ang), cy-rr*math.sin(ang)]
        canvas.create_polygon(pts, outline=COLORS[proto], fill=dim(COLORS[proto]), width=2)
        for k in range(n):
            ang = math.pi/2 - 2*math.pi*k/n
            rr = r*(data[proto][k]/100)
            px, py = cx+rr*math.cos(ang), cy-rr*math.sin(ang)
            canvas.create_oval(px-4,py-4,px+4,py+4, fill=COLORS[proto], outline="")

    # Legend
    lx = 20
    for p in (["TCP","UDP","ICMP"] if active_filter.get()=="All" else [active_filter.get()]):
        canvas.create_rectangle(lx,8,lx+10,18,fill=COLORS[p],outline="")
        canvas.create_text(lx+14,13,text=p,fill=COLORS["muted"],
                           font=("Courier",9),anchor="w")
        lx += 60

def draw_donut_chart():
    canvas.delete("all")
    W, H = 960, 260
    cx, cy, r_out, r_in = 200, H//2, 90, 45
    protos = ["TCP","UDP","ICMP"] if active_filter.get()=="All" else [active_filter.get()]
    totals = {p: sum(data[p]) for p in protos}
    grand  = sum(totals.values())

    start = 0.0
    for proto in protos:
        extent = 360 * totals[proto] / grand
        canvas.create_arc(cx-r_out, cy-r_out, cx+r_out, cy+r_out,
                          start=start, extent=extent,
                          fill=COLORS[proto], outline=COLORS["card"], width=2)
        canvas.create_oval(cx-r_in, cy-r_in, cx+r_in, cy+r_in,
                           fill=COLORS["card"], outline="")
        mid = math.radians(start + extent/2)
        mx  = cx + (r_out+r_in)/2 * math.cos(mid)
        my  = cy - (r_out+r_in)/2 * math.sin(mid)
        pct = int(totals[proto]/grand*100)
        canvas.create_text(mx, my, text=f"{pct}%", fill=COLORS["text"],
                           font=("Courier", 9, "bold"))
        start += extent

    canvas.create_text(cx, cy, text=f"{grand}", fill=COLORS["text"],
                       font=("Courier", 16, "bold"))
    canvas.create_text(cx, cy+16, text="pkts", fill=COLORS["muted"],
                       font=("Courier", 9))

    # Table on right
    tx = cx + r_out + 60
    canvas.create_text(tx, 30, text="Protocol  Browse  PingFlood  DNS",
                       fill=COLORS["muted"], font=("Courier", 9), anchor="w")
    for i, (scen_label, col) in enumerate(zip(
            ["Browse","PingFlood","DNS"], ["TCP","UDP","ICMP"])):
        pass
    for i, proto in enumerate(["TCP","UDP","ICMP"]):
        y = 55 + i*36
        canvas.create_rectangle(tx, y+2, tx+10, y+12,
                                 fill=COLORS[proto], outline="")
        row = f"  {proto:<6}" + "".join(f"   {data[proto][j]:>3}%" for j in range(3))
        canvas.create_text(tx+14, y+7, text=row,
                           fill=COLORS[proto], font=("Courier", 10, "bold"), anchor="w")

def draw_chart():
    t = active_chart.get()
    if   t == "Bar":   draw_bar_chart()
    elif t == "Radar": draw_radar_chart()
    elif t == "Donut": draw_donut_chart()

# ── BREAKDOWN MINI-BARS ───────────────────────────────────────────────────────
breakdown_frame = tk.Frame(root, bg=COLORS["bg"])
breakdown_frame.pack(fill="x", padx=20, pady=(12,0))

scenario_labels = ["Browsing (http.cap)", "Ping Flood (icmp.pcap)", "Idle/DNS (dns.cap)"]
breakdown_bars  = {}   # (scenario_idx, proto) -> canvas item

for si, slabel in enumerate(scenario_labels):
    card = tk.Frame(breakdown_frame, bg=COLORS["card"], bd=0,
                    highlightthickness=1, highlightbackground=COLORS["grid"])
    card.grid(row=0, column=si, padx=(0,10) if si<2 else 0, sticky="ew")
    breakdown_frame.columnconfigure(si, weight=1)
    tk.Label(card, text=slabel, font=("Courier", 9, "bold"),
             bg=COLORS["card"], fg=COLORS["text"]).pack(anchor="w", padx=10, pady=(8,4))
    for proto in ["TCP","UDP","ICMP"]:
        row = tk.Frame(card, bg=COLORS["card"])
        row.pack(fill="x", padx=10, pady=2)
        tk.Label(row, text=proto, width=5, font=("Courier", 8),
                 bg=COLORS["card"], fg=COLORS[proto], anchor="w").pack(side="left")
        track = tk.Frame(row, bg=COLORS["grid"], height=5)
        track.pack(side="left", fill="x", expand=True, padx=(0,6))
        track.pack_propagate(False)
        fill_bar = tk.Frame(track, bg=COLORS[proto], height=5)
        fill_bar.place(relwidth=data[proto][si]/100, relheight=1)
        val_lbl = tk.Label(row, text=f"{data[proto][si]}%",
                           font=("Courier", 8, "bold"),
                           bg=COLORS["card"], fg=COLORS[proto])
        val_lbl.pack(side="right")
    tk.Frame(card, bg=COLORS["card"], height=6).pack()

# ── ALERT / TIMELINE ──────────────────────────────────────────────────────────
alert_frame = tk.Frame(root, bg=COLORS["bg"])
alert_frame.pack(fill="x", padx=20, pady=(10,0))

alert_label = tk.Label(alert_frame, text="",
                        font=("Courier", 10), bg=COLORS["bg"], fg=COLORS["muted"])
alert_label.pack(side="left")

timeline_frame = tk.Frame(root, bg=COLORS["card"], bd=0,
                          highlightthickness=1, highlightbackground=COLORS["grid"])
tl_canvas = tk.Canvas(timeline_frame, width=960, height=80,
                      bg=COLORS["card"], highlightthickness=0)
tl_canvas.pack(padx=8, pady=8)

# ── ACTION BUTTONS ────────────────────────────────────────────────────────────
action_frame = tk.Frame(root, bg=COLORS["bg"])
action_frame.pack(fill="x", padx=20, pady=(10,0))

def update_metrics():
    protos = ["TCP","UDP","ICMP"] if active_filter.get()=="All" else [active_filter.get()]
    best, bestv = "", 0
    for p in protos:
        avg = sum(data[p])/3
        if avg > bestv:
            bestv, best = avg, p
    si = data[best].index(max(data[best]))
    names = ["Browsing","Ping Flood","Idle/DNS"]
    metric_vals["Dominant Protocol"][0].config(text=best)
    metric_vals["Dominant Protocol"][1].config(text=f"{names[si]} scenario")

def clear_spike():
    global spike_active, timeline_job
    spike_active = False
    timeline_data.clear()
    tl_canvas.delete("all")
    timeline_frame.pack_forget()
    alert_label.config(text="", fg=COLORS["muted"])
    status_label.config(text="Monitoring", fg="#22C55E")
    status_dot.config(fg="#22C55E")
    metric_vals["Anomaly Score"][0].config(text="0%", fg=COLORS["text"])
    metric_vals["Anomaly Score"][1].config(text="No spike detected")

def draw_timeline():
    tl_canvas.delete("all")
    W, H = 960, 80
    pad = 30
    if len(timeline_data) < 2:
        return
    mx = max(timeline_data)
    pts = []
    for i, v in enumerate(timeline_data):
        x = pad + i * (W - 2*pad) / max(len(timeline_data)-1, 1)
        y = H - pad - int((v/100)*(H-2*pad))
        pts += [x, y]
    if len(pts) >= 4:
        tl_canvas.create_line(*pts, fill=COLORS["ICMP"], width=2, smooth=True)
    # threshold
    ty = H - pad - int((70/100)*(H-2*pad))
    tl_canvas.create_line(pad, ty, W-pad, ty,
                          fill="#E24B4A", dash=(6,4), width=1)
    tl_canvas.create_text(W-pad+2, ty, text="70%",
                           fill="#E24B4A", font=("Courier",7), anchor="w")
    tl_canvas.create_text(pad, 8, text="ICMP live timeline",
                           fill=COLORS["muted"], font=("Courier",8), anchor="w")

spike_sequence = [5,8,6,12,40,65,80,78,80,70,60,45,30,15,5]
spike_step     = tk.IntVar(value=0)

def tick_spike():
    global timeline_job
    idx = spike_step.get()
    if idx < len(spike_sequence):
        val = spike_sequence[idx]
        timeline_data.append(val)
        draw_timeline()
        pct = val
        metric_vals["Anomaly Score"][0].config(
            text=f"{pct}%",
            fg="#E24B4A" if pct>=70 else COLORS["text"])
        metric_vals["Anomaly Score"][1].config(
            text="CRITICAL — ping flood!" if pct>=70 else "Returning to normal")
        spike_step.set(idx+1)
        timeline_job = root.after(400, tick_spike)
    else:
        root.after(2000, clear_spike)

def simulate_spike():
    global spike_active
    if spike_active:
        return
    spike_active = True
    spike_step.set(0)
    timeline_data.clear()
    timeline_frame.pack(fill="x", padx=20, pady=(8,0))
    status_label.config(text="ICMP SPIKE DETECTED", fg="#EF4444")
    status_dot.config(fg="#EF4444")
    alert_label.config(
        text="  ⚠  CRITICAL: ICMP Spike 80% — Potential Ping Flood Attack",
        fg="#E24B4A")
    tick_spike()

def cycle_scenario():
    idx = (scenario_idx.get() + 1) % 3
    scenario_idx.set(idx)
    names = ["Browsing","Ping Flood","Idle/DNS"]
    metric_vals["Dominant Protocol"][0].config(text=names[idx])
    metric_vals["Dominant Protocol"][1].config(text=scenario_labels[idx])
    if active_chart.get() == "Bar":
        draw_bar_highlight(idx)

def draw_bar_highlight(hi):
    draw_bar_chart()
    # Slight re-tint not needed — already bright colors per bar

def reset_all():
    global spike_active
    if timeline_job:
        root.after_cancel(timeline_job)
    spike_active = False
    scenario_idx.set(-1)
    timeline_data.clear()
    active_filter.set("All")
    active_chart.set("Bar")
    for k,b in filter_buttons.items():
        is_all = k=="All"
        b.config(bg="#2A3050" if is_all else COLORS["card"],
                 fg=COLORS["text"] if is_all else COLORS["muted"],
                 highlightbackground="#4A5070" if is_all else COLORS["grid"])
    for k,b in chart_buttons.items():
        is_bar = k=="Bar"
        b.config(bg="#2A3050" if is_bar else COLORS["card"],
                 fg=COLORS["text"] if is_bar else COLORS["muted"],
                 highlightbackground="#4A5070" if is_bar else COLORS["grid"])
    clear_spike()
    draw_chart()
    update_metrics()

btn_style = dict(font=("Courier",10,"bold"), relief="flat", bd=0,
                 padx=14, pady=7, cursor="hand2", highlightthickness=1)

tk.Button(action_frame, text="⚡  Simulate Week 5 Stress Test",
          command=simulate_spike,
          bg="#3D1515", fg="#E24B4A",
          highlightbackground="#6B2222",
          **btn_style).pack(side="left", padx=(0,8))

tk.Button(action_frame, text="↻  Cycle Scenario",
          command=cycle_scenario,
          bg="#1A2535", fg="#378ADD",
          highlightbackground="#2A4060",
          **btn_style).pack(side="left", padx=(0,8))

tk.Button(action_frame, text="Reset",
          command=reset_all,
          bg=COLORS["card"], fg=COLORS["muted"],
          highlightbackground=COLORS["grid"],
          **btn_style).pack(side="left")

# ── INIT ──────────────────────────────────────────────────────────────────────
draw_chart()
update_metrics()
root.mainloop()