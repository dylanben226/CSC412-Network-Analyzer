import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont

# ── DATA FROM YOUR WEEK 4 RESULTS ──────────────────────────
scenarios = ["Browsing\n(http.cap)", "Ping Flood\n(icmp.pcap)", "Idle/DNS\n(dns.cap)"]
tcp_data  = [80, 10, 10]
udp_data  = [10, 10, 80]
icmp_data = [10, 80, 10]

COLORS = {"TCP": "#2E75B6", "UDP": "#70AD47", "ICMP": "#FF6B6B", "bg": "#1E1E2E", "card": "#2A2A3E"}

# ── MAIN WINDOW ─────────────────────────────────────────────
root = tk.Tk()
root.title("CSC412 - Network Traffic Analyzer")
root.geometry("900x620")
root.configure(bg=COLORS["bg"])
root.resizable(False, False)

# ── TITLE ───────────────────────────────────────────────────
tk.Label(root, text="Network Traffic Analyzer",
         font=("Arial", 22, "bold"), bg=COLORS["bg"], fg="white").pack(pady=(20, 2))
tk.Label(root, text="J & D Unlimited  |  Jack Ngog & Dylan Ben  |  CSC412",
         font=("Arial", 11), bg=COLORS["bg"], fg="#888888").pack(pady=(0, 20))

# ── CANVAS FOR BAR CHART ────────────────────────────────────
canvas = tk.Canvas(root, width=860, height=340, bg=COLORS["card"],
                   highlightthickness=0, bd=0)
canvas.pack(padx=20)

BAR_W = 40
GROUP_GAP = 100
START_X = 80
BASE_Y = 300
MAX_H = 240

def draw_bar(x, value, color, label):
    height = int((value / 100) * MAX_H)
    y0 = BASE_Y - height
    canvas.create_rectangle(x, y0, x + BAR_W, BASE_Y, fill=color, outline="")
    canvas.create_text(x + BAR_W // 2, y0 - 10,
                       text=f"{value}%", fill="white", font=("Arial", 9, "bold"))

# Draw gridlines
for pct in [25, 50, 75, 100]:
    y = BASE_Y - int((pct / 100) * MAX_H)
    canvas.create_line(50, y, 840, y, fill="#3A3A5A", dash=(4, 4))
    canvas.create_text(44, y, text=f"{pct}%", fill="#666688", font=("Arial", 8), anchor="e")

# Draw bars for each scenario
for i, scenario in enumerate(scenarios):
    gx = START_X + i * (3 * BAR_W + GROUP_GAP)
    draw_bar(gx,            tcp_data[i],  COLORS["TCP"],  "TCP")
    draw_bar(gx + BAR_W,    udp_data[i],  COLORS["UDP"],  "UDP")
    draw_bar(gx + BAR_W*2,  icmp_data[i], COLORS["ICMP"], "ICMP")
    canvas.create_line(50, BASE_Y, 840, BASE_Y, fill="#444466")
    canvas.create_text(gx + BAR_W, BASE_Y + 20,
                       text=scenario, fill="white", font=("Arial", 9, "bold"), anchor="n")

# ── LEGEND ──────────────────────────────────────────────────
legend_frame = tk.Frame(root, bg=COLORS["bg"])
legend_frame.pack(pady=12)
for label, color in [("TCP", COLORS["TCP"]), ("UDP", COLORS["UDP"]), ("ICMP", COLORS["ICMP"])]:
    tk.Label(legend_frame, text="  ", bg=color, width=2).pack(side="left", padx=(10, 4))
    tk.Label(legend_frame, text=label, bg=COLORS["bg"],
             fg="white", font=("Arial", 11, "bold")).pack(side="left", padx=(0, 16))

# ── STATS CARDS ─────────────────────────────────────────────
cards_frame = tk.Frame(root, bg=COLORS["bg"])
cards_frame.pack(pady=8, padx=20, fill="x")

cards = [
    ("Browsing Traffic", "80% TCP", "Websites use TCP\nfor reliable delivery", COLORS["TCP"]),
    ("Ping Flood",       "80% ICMP", "Ping uses ICMP\nSpike detected!", COLORS["ICMP"]),
    ("Idle / DNS",       "80% UDP", "DNS uses UDP\nfor fast lookups", COLORS["UDP"]),
]

for title, stat, desc, color in cards:
    card = tk.Frame(cards_frame, bg=COLORS["card"], padx=14, pady=10)
    card.pack(side="left", expand=True, fill="both", padx=6)
    tk.Label(card, text=title, bg=COLORS["card"], fg="#AAAACC",
             font=("Arial", 9)).pack(anchor="w")
    tk.Label(card, text=stat, bg=COLORS["card"], fg=color,
             font=("Arial", 16, "bold")).pack(anchor="w")
    tk.Label(card, text=desc, bg=COLORS["card"], fg="#888888",
             font=("Arial", 8)).pack(anchor="w")

# ── FOOTER ──────────────────────────────────────────────────
tk.Label(root, text="Packets analyzed across 3 scenarios  •  Weeks 4 & 5 Complete  •  Error handling & spike detection active",
         font=("Arial", 8), bg=COLORS["bg"], fg="#555577").pack(pady=(8, 0))

root.mainloop()