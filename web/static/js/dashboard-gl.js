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
