/* =====================================================================
   SECTION 1: WebGL SHADER SYSTEM
   ===================================================================== */

const canvas = document.getElementById("glCanvas");

// Always use WebGL1 — simpler, works identically on all browsers including Chromium/ANGLE
const gl =
  canvas.getContext("webgl", { antialias: false, alpha: false }) ||
  canvas.getContext("experimental-webgl", { antialias: false, alpha: false });

// ── Vertex shader ────────────────────────────────────────────────────────────
const VERT = `
  attribute vec2 a_pos;
  void main() { gl_Position = vec4(a_pos, 0.0, 1.0); }
`;

// ── Fragment shader ──────────────────────────────────────────────────────────
// Written for maximum cross-browser / ANGLE compatibility:
//   • highp precision (supported everywhere on desktop)
//   • mod(p, 289.0) keeps hash inputs bounded → no mediump overflow artifacts
//   • vortex uses a rotation matrix instead of atan() → no ANGLE precision blowup
//   • time is mod-bounded → stays precise after long sessions
//   • loop unrolled → avoids ANGLE loop-with-accumulator miscompile
const FRAG = `
  #ifdef GL_FRAGMENT_PRECISION_HIGH
    precision highp float;
  #else
    precision mediump float;
  #endif

  uniform float u_time;
  uniform vec2  u_res;
  uniform vec3  u_colorA;
  uniform vec3  u_colorB;

  vec2 hash2(vec2 p) {
    p = mod(p, 289.0);
    p = vec2(dot(p, vec2(127.1, 311.7)), dot(p, vec2(269.5, 183.3)));
    p = mod(p, 289.0);
    return -1.0 + 2.0 * fract(sin(p) * 43758.5453);
  }

  float noise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    vec2 u = f * f * (3.0 - 2.0 * f);
    return mix(
      mix(dot(hash2(i + vec2(0.0, 0.0)), f - vec2(0.0, 0.0)),
          dot(hash2(i + vec2(1.0, 0.0)), f - vec2(1.0, 0.0)), u.x),
      mix(dot(hash2(i + vec2(0.0, 1.0)), f - vec2(0.0, 1.0)),
          dot(hash2(i + vec2(1.0, 1.0)), f - vec2(1.0, 1.0)), u.x),
      u.y);
  }

  float fbm(vec2 p) {
    float v = 0.0;
    v += 0.5000 * noise(p); p = p * 2.1 + vec2(1.7, 9.2);
    v += 0.2500 * noise(p); p = p * 2.1 + vec2(1.7, 9.2);
    v += 0.1250 * noise(p); p = p * 2.1 + vec2(1.7, 9.2);
    v += 0.0625 * noise(p); p = p * 2.1 + vec2(1.7, 9.2);
    v += 0.03125 * noise(p);
    return v;
  }

  vec2 curl(vec2 p, float t) {
    float eps = 0.01;
    float n1 = fbm(p + vec2(0.0,  eps) + vec2(t * 0.12, t * 0.12));
    float n2 = fbm(p + vec2(0.0, -eps) + vec2(t * 0.12, t * 0.12));
    float n3 = fbm(p + vec2( eps, 0.0) + vec2(t * 0.12, t * 0.12));
    float n4 = fbm(p + vec2(-eps, 0.0) + vec2(t * 0.12, t * 0.12));
    return vec2((n1 - n2) / (2.0 * eps), -(n3 - n4) / (2.0 * eps));
  }

  // Rotation-matrix vortex — no atan(), no precision blowup on ANGLE
  vec2 vortex(vec2 p, vec2 center, float strength, float t) {
    vec2 d = p - center;
    float r2 = dot(d, d) + 0.04;
    float spin = strength / r2 * sin(t);
    float cs = cos(spin);
    float sn = sin(spin);
    return center + vec2(cs * d.x - sn * d.y, sn * d.x + cs * d.y);
  }

  void main() {
    vec2 uv = (gl_FragCoord.xy - 0.5 * u_res) / min(u_res.x, u_res.y);

    // Bound time to avoid float precision loss over long sessions
    float T = mod(u_time, 628.318);
    float t = T * 0.18;

    vec2 v1 = vec2(sin(t * 0.7) * 0.6, cos(t * 0.5) * 0.4);
    vec2 v2 = vec2(cos(t * 0.4) * 0.5, sin(t * 0.8) * 0.5);

    vec2 wp = uv;
    wp = mix(wp, vortex(wp, v1, 0.4, t), 0.3);
    wp = mix(wp, vortex(wp, v2, 0.3, t), 0.25);

    vec2 flow = curl(wp * 1.2, t);
    wp += flow * 0.18;

    float layer1 = fbm(wp * 1.8 + t * vec2(0.30,  0.20));
    float layer2 = fbm(wp * 3.2 - t * vec2(0.15,  0.35) + vec2(4.5, 2.1));
    float layer3 = fbm(wp * 6.0 + t * vec2(0.25,  0.10) + vec2(9.3, 6.7));

    float depth = (layer1 * 0.5 + layer2 * 0.35 + layer3 * 0.15) * 0.5 + 0.5;

    float wave = sin(length(uv) * 8.0 - T * 1.5) * 0.5 + 0.5;
    wave = pow(wave, 6.0) * 0.12;

    vec3 col = mix(u_colorA, u_colorB, smoothstep(0.2, 0.8, depth));
    col = mix(col, u_colorB * 1.4, wave);
    col *= sin(T * 0.7) * 0.05 + 1.0;

    float lum = dot(col, vec3(0.299, 0.587, 0.114));
    col += col * smoothstep(0.6, 1.0, lum) * 0.4;

    float scan = sin(gl_FragCoord.y * 3.14159 * 2.0) * 0.5 + 0.5;
    col *= 0.93 + 0.07 * scan;

    float vig = 1.0 - smoothstep(0.55, 1.3, length(uv * vec2(0.85, 1.1)));
    col *= vig;

    vec2 ab = uv * 0.004;
    float rS = fbm((wp + ab) * 1.8 + t * vec2(0.3, 0.2)) * 0.5 + 0.5;
    float bS = fbm((wp - ab) * 1.8 + t * vec2(0.3, 0.2)) * 0.5 + 0.5;
    col.r = mix(col.r, mix(u_colorA.r, u_colorB.r, smoothstep(0.2, 0.8, rS)), 0.08);
    col.b = mix(col.b, mix(u_colorA.b, u_colorB.b, smoothstep(0.2, 0.8, bS)), 0.08);

    gl_FragColor = vec4(clamp(col, 0.0, 1.0), 1.0);
  }
`;

// ── Boot WebGL ───────────────────────────────────────────────────────────────
function compileShader(type, src) {
  const s = gl.createShader(type);
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS))
    console.error("Shader compile error:", gl.getShaderInfoLog(s));
  return s;
}

let uTime, uRes, uColorA, uColorB;
let currentColorA = [0.12, 0.02, 0.28];
let currentColorB = [0.65, 0.08, 0.85];
let targetColorA = [0.12, 0.02, 0.28];
let targetColorB = [0.65, 0.08, 0.85];
let colorT = 1.0;
const COLOR_SPEED = 0.007;

if (gl) {
  const prog = gl.createProgram();
  gl.attachShader(prog, compileShader(gl.VERTEX_SHADER, VERT));
  gl.attachShader(prog, compileShader(gl.FRAGMENT_SHADER, FRAG));
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS))
    console.error("Shader link error:", gl.getProgramInfoLog(prog));
  gl.useProgram(prog);

  const vb = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, vb);
  gl.bufferData(
    gl.ARRAY_BUFFER,
    new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]),
    gl.STATIC_DRAW
  );
  const aPos = gl.getAttribLocation(prog, "a_pos");
  gl.enableVertexAttribArray(aPos);
  gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

  uTime = gl.getUniformLocation(prog, "u_time");
  uRes = gl.getUniformLocation(prog, "u_res");
  uColorA = gl.getUniformLocation(prog, "u_colorA");
  uColorB = gl.getUniformLocation(prog, "u_colorB");
}

// ── Color themes ─────────────────────────────────────────────────────────────
const colorThemes = {
  "win-vitals": { a: [0.15, 0.02, 0.32], b: [0.72, 0.12, 0.95] },
  "win-net": { a: [0.02, 0.1, 0.3], b: [0.12, 0.55, 0.98] },
  "win-scope": { a: [0.28, 0.02, 0.12], b: [0.95, 0.18, 0.55] },
  "win-term": { a: [0.02, 0.18, 0.05], b: [0.1, 0.9, 0.25] },
  "win-feed": { a: [0.28, 0.1, 0.02], b: [0.98, 0.52, 0.12] },
  "win-metrics": { a: [0.2, 0.22, 0.02], b: [0.82, 0.95, 0.15] },
  "win-linechart": { a: [0.02, 0.18, 0.25], b: [0.05, 0.85, 0.98] }
};

function setColorTarget(winId) {
  const theme = colorThemes[winId];
  if (!theme) return;
  targetColorA = [...theme.a];
  targetColorB = [...theme.b];
  colorT = 0.0;
}

function lerpArr(a, b, t) {
  const ease = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
  return a.map((v, i) => v + (b[i] - v) * ease);
}

// ── Resize ────────────────────────────────────────────────────────────────────
function resize() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  if (gl) gl.viewport(0, 0, canvas.width, canvas.height);
}
resize();
window.addEventListener("resize", resize);

// ── Render loop ───────────────────────────────────────────────────────────────
const startTime = performance.now();
function render() {
  const t = (performance.now() - startTime) / 1000;

  if (colorT < 1.0) {
    colorT = Math.min(1.0, colorT + COLOR_SPEED);
    currentColorA = lerpArr(currentColorA, targetColorA, colorT);
    currentColorB = lerpArr(currentColorB, targetColorB, colorT);
  }

  if (gl) {
    gl.uniform1f(uTime, t);
    gl.uniform2f(uRes, canvas.width, canvas.height);
    gl.uniform3f(uColorA, ...currentColorA);
    gl.uniform3f(uColorB, ...currentColorB);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  }

  requestAnimationFrame(render);
}
render();

/* =====================================================================
   SECTION 2: DRAGGABLE WINDOW SYSTEM + RANDOM PLACEMENT
   ===================================================================== */

let topZ = 10;
const windows = document.querySelectorAll(".win");

// ── Zone-based placement with jitter ─────────────────────────────────────────
// Divides the screen into a 3-column × 3-row grid of zones.
// Each window gets a unique zone, then is nudged by a small random offset
// within the zone's safe area. Guarantees no overlap at any screen size.
function scatterWindows() {
  const PAD = 28; // screen edge padding
  const GAP = 18; // gap between zone cells
  const COLS = 3,
    ROWS = 3;
  const W = window.innerWidth,
    H = window.innerHeight;
  const cellW = (W - PAD * 2 - GAP * (COLS - 1)) / COLS;
  const cellH = (H - PAD * 2 - GAP * (ROWS - 1)) / ROWS;

  // Build zone list in reading order, shuffle it so windows get different
  // zones each reload without ever doubling up
  const zones = [];
  for (let r = 0; r < ROWS; r++)
    for (let c = 0; c < COLS; c++) zones.push({ c, r });

  // Fisher-Yates shuffle
  for (let i = zones.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [zones[i], zones[j]] = [zones[j], zones[i]];
  }

  windows.forEach((win, idx) => {
    const ww = win.offsetWidth || 260;
    const wh = win.offsetHeight || 200;
    const zone = zones[idx % zones.length];

    // Top-left corner of this zone
    const zoneX = PAD + zone.c * (cellW + GAP);
    const zoneY = PAD + zone.r * (cellH + GAP);

    // Safe jitter range: keep window fully inside the zone
    const jitterX = Math.max(0, cellW - ww);
    const jitterY = Math.max(0, cellH - wh);

    // Bias jitter toward center of zone for a more natural look
    const rx = (Math.random() * 0.6 + 0.2) * jitterX;
    const ry = (Math.random() * 0.6 + 0.2) * jitterY;

    win.style.left = Math.round(zoneX + rx) + "px";
    win.style.top = Math.round(zoneY + ry) + "px";
  });
}

// Wait one frame so the browser has rendered and offsetWidth/Height are available
requestAnimationFrame(scatterWindows);

// ── Drag behaviour ────────────────────────────────────────────────────────────

windows.forEach((win) => {
  let dragging = false,
    ox = 0,
    oy = 0;
  win.style.zIndex = topZ++;

  const bar = win.querySelector(".titlebar");

  bar.addEventListener("mousedown", (e) => {
    if (e.button !== 0) return;
    dragging = true;
    const r = win.getBoundingClientRect();
    ox = e.clientX - r.left;
    oy = e.clientY - r.top;
    bringToFront(win);
    e.preventDefault();
  });

  win.addEventListener("mousedown", () => bringToFront(win));

  document.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    let nx = e.clientX - ox;
    let ny = e.clientY - oy;
    nx = Math.max(0, Math.min(window.innerWidth - win.offsetWidth, nx));
    ny = Math.max(0, Math.min(window.innerHeight - win.offsetHeight, ny));
    win.style.left = nx + "px";
    win.style.top = ny + "px";
  });

  document.addEventListener("mouseup", () => {
    dragging = false;
  });
});

function bringToFront(win) {
  win.style.zIndex = ++topZ;
  if (win.dataset.color) setColorTarget(win.id);
  // Jiggle
  win.classList.remove("jiggling");
  void win.offsetWidth; // reflow to restart animation
  win.classList.add("jiggling");
  win.addEventListener("animationend", () => win.classList.remove("jiggling"), {
    once: true
  });
  // Active flash
  document
    .querySelectorAll(".win")
    .forEach((w) => w.classList.remove("active"));
  win.classList.add("active");
  setTimeout(() => win.classList.remove("active"), 300);
}

/* =====================================================================
   SECTION 3: DASHBOARD DATA SIMULATION
   ===================================================================== */

// CPU bars
function makeBars(containerId, color, count = 7) {
  const c = document.getElementById(containerId);
  for (let i = 0; i < count; i++) {
    const b = document.createElement("div");
    b.className = "bar";
    b.style.background = color;
    b.style.height = 20 + Math.random() * 80 + "%";
    b.style.animationDelay = i * 0.15 + "s";
    c.appendChild(b);
  }
}
makeBars("cpu-bars", "linear-gradient(to top, #8b2cff, #d08fff)", 7);
makeBars("lat-bars", "linear-gradient(to top, #20aaff, #80e0ff)", 7);

// Update simulated vitals
function rand(min, max) {
  return min + Math.random() * (max - min);
}

setInterval(() => {
  document.getElementById("cpu-val").textContent =
    Math.round(rand(55, 90)) + "%";
  document.getElementById("mem-val").textContent =
    rand(3.5, 6.2).toFixed(1) + "GB";
  document.getElementById("temp-val").textContent =
    Math.round(rand(38, 58)) + "°C";
  document.getElementById("net-up").textContent =
    rand(5, 25).toFixed(1) + " MB/s";
  document.getElementById("net-down").textContent =
    rand(2, 15).toFixed(1) + " MB/s";
  document.getElementById("pkt-val").textContent = Math.round(
    rand(12000, 25000)
  ).toLocaleString();
  document.getElementById("freq-val").textContent =
    Math.round(rand(220, 880)) + " Hz";
  document.getElementById("amp-val").textContent = rand(0.4, 1.0).toFixed(2);

  // Uptime
  const ms = performance.now();
  const s = Math.floor(ms / 1000) % 60;
  const m = Math.floor(ms / 60000) % 60;
  const h = Math.floor(ms / 3600000);
  document.getElementById("uptime").textContent = [h, m, s]
    .map((n) => String(n).padStart(2, "0"))
    .join(":");

  // Radial arc
  const pct = rand(0.3, 0.9);
  const circ = 2 * Math.PI * 42;
  document
    .getElementById("radial-arc")
    .setAttribute("stroke-dashoffset", circ * (1 - pct));
  const t = document.getElementById("radial-arc").previousElementSibling
    ?.nextElementSibling;
  document.querySelector("#win-net .radial text:first-of-type").textContent =
    Math.round(pct * 100) + "%";
}, 1600);

/* =====================================================================
   SECTION 4: OSCILLOSCOPE CANVAS
   ===================================================================== */

const oscCanvas = document.getElementById("osc-canvas");
const ctx2d = oscCanvas.getContext("2d");
let oscPhase = 0;
let oscFreq = 1.8;

function drawOsc() {
  const w = oscCanvas.width,
    h = oscCanvas.height;
  ctx2d.clearRect(0, 0, w, h);
  ctx2d.fillStyle = "rgba(0,0,0,0.3)";
  ctx2d.fillRect(0, 0, w, h);

  // Grid
  ctx2d.strokeStyle = "rgba(255,255,255,0.06)";
  ctx2d.lineWidth = 0.5;
  for (let x = 0; x < w; x += w / 8) {
    ctx2d.beginPath();
    ctx2d.moveTo(x, 0);
    ctx2d.lineTo(x, h);
    ctx2d.stroke();
  }
  for (let y = 0; y < h; y += h / 4) {
    ctx2d.beginPath();
    ctx2d.moveTo(0, y);
    ctx2d.lineTo(w, y);
    ctx2d.stroke();
  }

  // Signal
  const grad = ctx2d.createLinearGradient(0, 0, w, 0);
  grad.addColorStop(0, "#ff2888");
  grad.addColorStop(0.5, "#ff80cc");
  grad.addColorStop(1, "#ff2888");
  ctx2d.strokeStyle = grad;
  ctx2d.lineWidth = 1.8;
  ctx2d.shadowColor = "#ff2888";
  ctx2d.shadowBlur = 8;
  ctx2d.beginPath();
  for (let x = 0; x <= w; x++) {
    const t = x / w;
    const y =
      h / 2 +
      h *
        0.35 *
        (Math.sin(t * Math.PI * 2 * 3 * oscFreq + oscPhase) * 0.5 +
          Math.sin(t * Math.PI * 2 * 7 * oscFreq + oscPhase * 1.3) * 0.25 +
          Math.sin(t * Math.PI * 2 * 13 * oscFreq + oscPhase * 0.7) * 0.1);
    x === 0 ? ctx2d.moveTo(x, y) : ctx2d.lineTo(x, y);
  }
  ctx2d.stroke();
  ctx2d.shadowBlur = 0;

  oscPhase += 0.06;
  oscFreq = 1.5 + Math.sin(performance.now() / 2000) * 0.5;
  requestAnimationFrame(drawOsc);
}
drawOsc();

/* =====================================================================
   SECTION 5: TERMINAL ANIMATION
   ===================================================================== */

const termLines = [
  "> SYSTEM INIT... OK",
  "> LOADING MODULES...",
  "> shader.glsl .......... [COMPILED]",
  "> fluid_sim.wasm ....... [READY]",
  "> net_monitor .......... [ACTIVE]",
  "> ALL SYSTEMS NOMINAL",
  "> MONITORING LIVE..."
];
const termOut = document.getElementById("term-out");
let termIdx = 0,
  termLineIdx = 0;

function termTick() {
  if (termIdx >= termLines.length) {
    // loop with delay
    setTimeout(() => {
      termOut.innerHTML = "";
      termIdx = 0;
      termLineIdx = 0;
      termTick();
    }, 4000);
    return;
  }
  const line = termLines[termIdx];
  if (termLineIdx <= line.length) {
    termOut.innerHTML =
      termLines
        .slice(0, termIdx)
        .map((l) => l + "<br>")
        .join("") +
      line.slice(0, termLineIdx) +
      '<span class="caret"> </span>';
    termLineIdx++;
    setTimeout(termTick, 35 + Math.random() * 40);
  } else {
    termIdx++;
    termLineIdx = 0;
    setTimeout(termTick, 180);
  }
}
termTick();

/* =====================================================================
   SECTION 6: ACTIVITY FEED
   ===================================================================== */

const events = [
  { label: "PACKET BURST DETECTED", color: "#ff4a4a" },
  { label: "MEMORY SPIKE → 89%", color: "#ffaa00" },
  { label: "CONNECTION ESTABLISHED", color: "#40ff88" },
  { label: "SHADER RECOMPILED", color: "#c86fff" },
  { label: "CACHE CLEARED", color: "#40ccff" },
  { label: "WATCHDOG PING OK", color: "#40ff88" },
  { label: "THROTTLE APPLIED", color: "#ffaa00" },
  { label: "NODE SYNC COMPLETE", color: "#40ccff" }
];

const feedBody = document.getElementById("feed-body");
function addFeedItem() {
  const ev = events[Math.floor(Math.random() * events.length)];
  const d = document.createElement("div");
  d.className = "feed-item";
  const now = new Date();
  const ts = [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map((n) => String(n).padStart(2, "0"))
    .join(":");
  d.innerHTML = `<div class="feed-dot" style="background:${ev.color};box-shadow:0 0 6px ${ev.color}"></div>
    <div><div style="color:rgba(255,255,255,0.75);font-size:10px">${ev.label}</div><div style="font-size:9px;margin-top:1px">${ts}</div></div>`;
  feedBody.insertBefore(d, feedBody.firstChild);
  while (feedBody.children.length > 12)
    feedBody.removeChild(feedBody.lastChild);
}
addFeedItem();
setInterval(addFeedItem, 1800 + Math.random() * 1000);
// Vary interval
setInterval(() => setInterval(addFeedItem, 1200 + Math.random() * 2000), 8000);

/* =====================================================================
   SECTION 7: THROUGHPUT LINE CHART
   ===================================================================== */

const lineCanvas = document.getElementById("line-canvas");
const lctx = lineCanvas.getContext("2d");
const LINE_POINTS = 40;

// Two simulated data series: TX and RX
const txData = Array.from(
  { length: LINE_POINTS },
  () => 20 + Math.random() * 60
);
const rxData = Array.from(
  { length: LINE_POINTS },
  () => 10 + Math.random() * 40
);

function pushLineData() {
  txData.push(10 + Math.random() * 80 + Math.sin(performance.now() / 800) * 15);
  rxData.push(5 + Math.random() * 50 + Math.cos(performance.now() / 1200) * 10);
  if (txData.length > LINE_POINTS) {
    txData.shift();
    rxData.shift();
  }

  document.getElementById("tx-val").textContent =
    txData[txData.length - 1].toFixed(1) + " MB/s";
  document.getElementById("rx-val").textContent =
    rxData[rxData.length - 1].toFixed(1) + " MB/s";
}

function drawLineChart() {
  const w = lineCanvas.width,
    h = lineCanvas.height;
  lctx.clearRect(0, 0, w, h);

  // Background
  lctx.fillStyle = "rgba(0,0,0,0.25)";
  lctx.fillRect(0, 0, w, h);

  // Grid lines
  lctx.strokeStyle = "rgba(255,255,255,0.05)";
  lctx.lineWidth = 0.5;
  for (let i = 1; i < 4; i++) {
    const y = (h / 4) * i;
    lctx.beginPath();
    lctx.moveTo(0, y);
    lctx.lineTo(w, y);
    lctx.stroke();
  }
  for (let i = 1; i < 5; i++) {
    const x = (w / 5) * i;
    lctx.beginPath();
    lctx.moveTo(x, 0);
    lctx.lineTo(x, h);
    lctx.stroke();
  }

  const allVals = [...txData, ...rxData];
  const maxVal = Math.max(...allVals, 1);

  function drawSeries(data, colorTop, colorBot, glowColor) {
    const step = w / (LINE_POINTS - 1);

    // Filled area
    const areaGrad = lctx.createLinearGradient(0, 0, 0, h);
    areaGrad.addColorStop(0, colorTop);
    areaGrad.addColorStop(1, colorBot);
    lctx.beginPath();
    data.forEach((v, i) => {
      const x = i * step;
      const y = h - (v / maxVal) * (h * 0.88) - 2;
      i === 0 ? lctx.moveTo(x, y) : lctx.lineTo(x, y);
    });
    lctx.lineTo((LINE_POINTS - 1) * step, h);
    lctx.lineTo(0, h);
    lctx.closePath();
    lctx.fillStyle = areaGrad;
    lctx.fill();

    // Glowing stroke line
    lctx.beginPath();
    data.forEach((v, i) => {
      const x = i * step;
      const y = h - (v / maxVal) * (h * 0.88) - 2;
      i === 0 ? lctx.moveTo(x, y) : lctx.lineTo(x, y);
    });
    lctx.strokeStyle = glowColor;
    lctx.lineWidth = 1.5;
    lctx.shadowColor = glowColor;
    lctx.shadowBlur = 6;
    lctx.stroke();
    lctx.shadowBlur = 0;
  }

  drawSeries(
    rxData,
    "rgba(255,110,199,0.22)",
    "rgba(255,110,199,0.0)",
    "#ff6ec7"
  );

  drawSeries(txData, "rgba(0,229,255,0.28)", "rgba(0,229,255,0.0)", "#00e5ff");
}

setInterval(() => {
  pushLineData();
  drawLineChart();
}, 600);
drawLineChart();