/* boot.js — auto-loaded by Dash from assets/ folder */
(function () {
  const TCP = "#22d3ee", UDP = "#4ade80", ICMP = "#f43f5e", ACC = "#818cf8", OK = "#4ade80";
  const DIM = "#1e3040", BG = "#050d1a";

  /* ── Wait for DOM ── */
  function init() {
    startParticleBg();
    startNetCanvas();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* ══════════════════════════════════════════
     1. PARTICLE BACKGROUND (full boot screen)
  ══════════════════════════════════════════ */
  function startParticleBg() {
    const canvas = document.getElementById("boot-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let W, H, pts = [];

    function resize() {
      W = canvas.offsetWidth;
      H = canvas.offsetHeight;
      canvas.width = W;
      canvas.height = H;
      pts = Array.from({ length: 60 }, () => ({
        x: Math.random() * W,
        y: Math.random() * H,
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
        r: Math.random() * 1.4 + 0.4,
        c: [TCP, UDP, ICMP, ACC][Math.floor(Math.random() * 4)],
        a: Math.random() * 0.35 + 0.08,
      }));
    }

    resize();
    window.addEventListener("resize", resize);

    function draw() {
      ctx.clearRect(0, 0, W, H);
      for (let i = 0; i < pts.length; i++) {
        const a = pts[i];
        a.x += a.vx; a.y += a.vy;
        if (a.x < 0 || a.x > W) a.vx *= -1;
        if (a.y < 0 || a.y > H) a.vy *= -1;
        for (let j = i + 1; j < pts.length; j++) {
          const b = pts[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 100) {
            ctx.beginPath();
            ctx.strokeStyle = a.c;
            ctx.globalAlpha = (1 - d / 100) * 0.07;
            ctx.lineWidth = 0.5;
            ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
        ctx.globalAlpha = a.a;
        ctx.beginPath();
        ctx.fillStyle = a.c;
        ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
      requestAnimationFrame(draw);
    }
    draw();
  }

  /* ══════════════════════════════════════════
     2. NETWORK MAP CANVAS (overlaid on image)
  ══════════════════════════════════════════ */
  function startNetCanvas() {
    const canvas = document.getElementById("net-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    const nodes = [
      { x: 0.50, y: 0.42, r: 0.06, c: ACC,   lbl: "Router",  type: "hub" },
      { x: 0.18, y: 0.18, r: 0.04, c: TCP,   lbl: "HTTP",    type: "tcp" },
      { x: 0.82, y: 0.18, r: 0.04, c: TCP,   lbl: "HTTPS",   type: "tcp" },
      { x: 0.10, y: 0.65, r: 0.04, c: UDP,   lbl: "DNS",     type: "udp" },
      { x: 0.90, y: 0.65, r: 0.04, c: UDP,   lbl: "DHCP",    type: "udp" },
      { x: 0.34, y: 0.80, r: 0.04, c: ICMP,  lbl: "Ping",    type: "icmp"},
      { x: 0.66, y: 0.80, r: 0.04, c: ICMP,  lbl: "Trace",   type: "icmp"},
      { x: 0.30, y: 0.08, r: 0.03, c: TCP,   lbl: "",        type: "tcp" },
      { x: 0.70, y: 0.08, r: 0.03, c: TCP,   lbl: "",        type: "tcp" },
    ];
    const edges = [[0,1],[0,2],[0,3],[0,4],[0,5],[0,6],[1,7],[2,8]];
    let pulses = [], animT = 0;
    let counts = { tcp: 0, udp: 0, icmp: 0 };

    function addPulse() {
      const e = edges[Math.floor(Math.random() * edges.length)];
      const from = nodes[e[0]], to = nodes[e[1]];
      pulses.push({ fx: from.x, fy: from.y, tx: to.x, ty: to.y, t: 0, c: to.c, type: to.type });
    }

    function draw() {
      const W = canvas.offsetWidth, H = canvas.offsetHeight;
      canvas.width = W; canvas.height = H;
      ctx.clearRect(0, 0, W, H);
      animT++;

      /* Edges */
      edges.forEach(([a, b]) => {
        const na = nodes[a], nb = nodes[b];
        ctx.beginPath();
        ctx.strokeStyle = DIM;
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.7;
        ctx.moveTo(na.x * W, na.y * H);
        ctx.lineTo(nb.x * W, nb.y * H);
        ctx.stroke();
      });

      /* Pulses */
      pulses = pulses.filter(p => {
        p.t += 0.03;
        if (p.t > 1) {
          if (p.type !== "hub") {
            counts[p.type] = (counts[p.type] || 0) + 1;
            const el = document.getElementById("cnt-" + p.type);
            if (el) el.textContent = counts[p.type];
          }
          return false;
        }
        const x = (p.fx + (p.tx - p.fx) * p.t) * W;
        const y = (p.fy + (p.ty - p.fy) * p.t) * H;
        ctx.globalAlpha = 0.9 * (1 - Math.abs(p.t - 0.5) * 1.6);
        ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fillStyle = p.c; ctx.fill();
        return true;
      });

      /* Nodes */
      nodes.forEach(n => {
        const nx = n.x * W, ny = n.y * H, nr = n.r * Math.min(W, H);
        ctx.globalAlpha = 1;

        if (n.type === "hub") {
          const pulse = (Math.sin(animT * 0.04) + 1) / 2;
          ctx.beginPath(); ctx.arc(nx, ny, nr + 3 + pulse * 3, 0, Math.PI * 2);
          ctx.strokeStyle = n.c; ctx.lineWidth = 1.2; ctx.globalAlpha = 0.22 + pulse * 0.12; ctx.stroke();
        }

        ctx.globalAlpha = 0.9;
        ctx.beginPath(); ctx.arc(nx, ny, nr, 0, Math.PI * 2);
        ctx.fillStyle = n.c + "1a"; ctx.fill();
        ctx.strokeStyle = n.c; ctx.lineWidth = 1.5; ctx.stroke();

        ctx.beginPath(); ctx.arc(nx, ny, nr * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = n.c; ctx.globalAlpha = 0.85; ctx.fill();

        if (n.lbl) {
          ctx.globalAlpha = 0.75;
          ctx.fillStyle = "#e8f4ff";
          ctx.font = `${Math.round(nr * 0.75)}px IBM Plex Mono, monospace`;
          ctx.textAlign = "center";
          ctx.fillText(n.lbl, nx, ny + nr + nr * 0.9);
        }
      });

      ctx.globalAlpha = 1;
      requestAnimationFrame(draw);
    }

    draw();
    setInterval(addPulse, 200);
  }
})();