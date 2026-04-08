(() => {
  // ===== DOM =====
  const canvas = document.getElementById("stream");
  const ctx = canvas.getContext("2d", { alpha: true });

  const btnToggle = document.getElementById("btnToggle");
  const btnToggleLabel = document.getElementById("btnToggleLabel");
  const btnClear = document.getElementById("btnClear");
  const speedRange = document.getElementById("speedRange");
  const speedLabel = document.getElementById("speedLabel");
  const stateChip = document.getElementById("stateChip");

  const feed = document.getElementById("feed");
  const btnCopy = document.getElementById("btnCopy");

  const clock = document.getElementById("clock");
  const asof = document.getElementById("asof");
  const modeText = document.getElementById("modeText");

  const fpsEl = document.getElementById("fps");
  const evCountEl = document.getElementById("evCount");
  const p95El = document.getElementById("p95");
  const foot = document.getElementById("foot");

  // ===== State =====
  const state = {
    running: true,
    speed: 12,          // events/sec
    particles: [],
    events: [],
    totalEvents: 0,
    laneCount: 7,
    tPrev: performance.now(),
    spawnAcc: 0,
    fps: 0,
    fpsAcc: 0,
    fpsFrames: 0
  };

  // Revolut-ish palette accents
  const COLORS = {
    bgA: "rgba(11,16,32,1)",
    bgB: "rgba(7,10,18,1)",
    grid: "rgba(255,255,255,.06)",
    text: "rgba(234,240,255,1)",
    muted: "rgba(169,182,211,1)",
    good: "rgba(30,230,168,1)",
    warn: "rgba(255,176,32,1)",
    bad:  "rgba(255,77,109,1)"
  };

  const merchants = ["REV*COFFEE", "UBR*RIDE", "AMZN*MKT", "AIR*LHR", "FX*DESK", "GROC*UK", "SUB*STREAM"];
  const methods = ["VISA", "MC", "AMEX", "APPLEPAY", "SEPA"];
  const countries = ["GB", "DE", "FR", "ES", "TR", "NL", "IE"];
  const outcomes = ["approved", "review", "blocked"];

  const rand = (a,b) => a + Math.random() * (b-a);
  const pick = (arr) => arr[(Math.random() * arr.length) | 0];
  const clamp = (v,a,b) => Math.max(a, Math.min(b, v));

  // ===== Resize / DPR =====
  function resizeCanvas(){
    const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    const rect = canvas.getBoundingClientRect();
    canvas.width = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  window.addEventListener("resize", resizeCanvas);

  // ===== Lane geometry =====
  function laneY(i){
    const h = canvas.getBoundingClientRect().height;
    const top = 44;
    const bottom = h - 64;
    const span = bottom - top;
    return top + (i / (state.laneCount - 1)) * span;
  }

  // ===== Spawn transaction particle =====
  function spawn(){
    const lane = (Math.random() * state.laneCount) | 0;
    const outcome = weightedOutcome();

    const w = canvas.getBoundingClientRect().width;
    const y = laneY(lane);

    const speedPx = rand(110, 260); // px/sec
    const radius = rand(2.3, 3.6);

    state.particles.push({
      x: -20,
      y,
      vx: speedPx,
      r: radius,
      lane,
      outcome,
      life: 0,
      glow: rand(0.15, 0.35)
    });

    // add to event log (limit 12)
    const ev = mkEvent(outcome);
    state.events.unshift(ev);
    state.events = state.events.slice(0, 12);
    state.totalEvents++;
    evCountEl.textContent = String(state.totalEvents);

    renderFeed();
  }

  function weightedOutcome(){
    const r = Math.random();
    if (r < 0.84) return "approved";
    if (r < 0.95) return "review";
    return "blocked";
  }

  function mkEvent(outcome){
    const amt = outcome === "blocked" ? rand(120, 1600) : rand(5, 980);
    const lat = Math.round(rand(18, 420) + (outcome === "review" ? rand(80, 180) : 0) + (outcome === "blocked" ? rand(120, 240) : 0));
    return {
      id: cryptoSafeId(),
      t: new Date(),
      outcome,
      merchant: pick(merchants),
      method: pick(methods),
      country: pick(countries),
      amount: amt,
      latency: lat
    };
  }

  function cryptoSafeId(){
    // no external libs
    return (Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2)).slice(0, 12);
  }

  // ===== Feed render =====
  function renderFeed(){
    const html = state.events.map(ev => {
      const badgeClass = ev.outcome === "approved" ? "good" : ev.outcome === "review" ? "warn" : "bad";
      const label = ev.outcome.toUpperCase();
      const time = ev.t.toTimeString().slice(0,8);
      const amt = `£${ev.amount.toFixed(2)}`;
      return `
        <div class="rt-item">
          <div class="rt-item-top">
            <div class="rt-item-title">${ev.merchant}</div>
            <span class="rt-badge ${badgeClass}">${label}</span>
          </div>
          <div class="rt-item-bottom">
            <div class="rt-item-meta">${time} • ${ev.method} • ${ev.country} • ${ev.id}</div>
            <div class="rt-amt">${amt}</div>
          </div>
          <div class="rt-item-bottom" style="margin-top:6px;">
            <div>latency</div>
            <div class="rt-item-meta">${ev.latency}ms</div>
          </div>
        </div>
      `;
    }).join("");

    feed.innerHTML = html;

    // footline & p95 estimate from last N latencies
    const lats = state.events.map(e => e.latency).slice(0, 30).sort((a,b)=>a-b);
    const p95 = lats.length ? lats[Math.floor(lats.length * 0.95)] : 0;
    p95El.textContent = p95 ? `${p95}ms` : "—";

    foot.textContent = `events/sec: ${state.speed} • lanes: ${state.laneCount} • particles: ${state.particles.length}`;
  }

  // ===== Copy last 12 =====
  btnCopy.addEventListener("click", async () => {
    const lines = state.events.map(ev => {
      const time = ev.t.toTimeString().slice(0,8);
      return `${time} | ${ev.outcome.toUpperCase()} | ${ev.merchant} | ${ev.method} | ${ev.country} | £${ev.amount.toFixed(2)} | ${ev.latency}ms | ${ev.id}`;
    }).join("\n");

    try{
      await navigator.clipboard.writeText(lines);
      btnCopy.innerHTML = `<i class="fa-solid fa-check"></i>`;
      setTimeout(()=> btnCopy.innerHTML = `<i class="fa-regular fa-copy"></i>`, 900);
    }catch(e){
      alert("Clipboard blocked by browser. Try manual copy from console.");
      console.log(lines);
    }
  });

  // ===== Controls =====
  function setRunning(next){
    state.running = next;
    stateChip.textContent = next ? "LIVE" : "PAUSED";
    stateChip.style.borderColor = next ? "rgba(30,230,168,.28)" : "rgba(255,176,32,.28)";
    stateChip.style.color = next ? "rgba(30,230,168,1)" : "rgba(255,176,32,1)";
    stateChip.style.background = next ? "rgba(30,230,168,.10)" : "rgba(255,176,32,.10)";

    btnToggleLabel.textContent = next ? "Pause" : "Resume";
    btnToggle.querySelector("i").className = next ? "fa-solid fa-pause" : "fa-solid fa-play";
    modeText.textContent = next ? "Rendering" : "Paused";
  }

  function setSpeed(v){
    state.speed = v;
    speedLabel.textContent = `${v}/s`;
    speedRange.value = String(v);
  }

  btnToggle.addEventListener("click", () => setRunning(!state.running));

  btnClear.addEventListener("click", () => {
    state.particles.length = 0;
    state.events.length = 0;
    renderFeed();
  });

  speedRange.addEventListener("input", () => {
    setSpeed(parseInt(speedRange.value, 10));
  });

  // keyboard shortcuts
  window.addEventListener("keydown", (e) => {
    if (e.code === "Space"){
      e.preventDefault();
      setRunning(!state.running);
    }
    if (e.key === "c" || e.key === "C"){
      state.particles.length = 0;
      state.events.length = 0;
      renderFeed();
    }
    if (e.key === "ArrowUp"){
      e.preventDefault();
      setSpeed(clamp(state.speed + 1, 2, 40));
    }
    if (e.key === "ArrowDown"){
      e.preventDefault();
      setSpeed(clamp(state.speed - 1, 2, 40));
    }
  });

  // ===== Drawing =====
  function drawBackground(w, h){
    // subtle lane grid
    ctx.clearRect(0,0,w,h);

    // gradient wash
    const g = ctx.createLinearGradient(0,0,0,h);
    g.addColorStop(0, "rgba(12,20,41,.85)");
    g.addColorStop(1, "rgba(7,10,18,.85)");
    ctx.fillStyle = g;
    ctx.fillRect(0,0,w,h);

    // lanes
    ctx.strokeStyle = COLORS.grid;
    ctx.lineWidth = 1;

    for (let i=0;i<state.laneCount;i++){
      const y = laneY(i);
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // vertical markers
    ctx.strokeStyle = "rgba(255,255,255,.04)";
    for (let x=60; x<w; x+=90){
      ctx.beginPath();
      ctx.moveTo(x, 18);
      ctx.lineTo(x, h-18);
      ctx.stroke();
    }

    // header line
    ctx.strokeStyle = "rgba(255,255,255,.06)";
    ctx.beginPath();
    ctx.moveTo(0, 34);
    ctx.lineTo(w, 34);
    ctx.stroke();
  }

  function colorFor(outcome){
    if (outcome === "approved") return COLORS.good;
    if (outcome === "review") return COLORS.warn;
    return COLORS.bad;
  }

  function drawParticle(p){
    const c = colorFor(p.outcome);

    // glow
    ctx.save();
    ctx.shadowColor = c;
    ctx.shadowBlur = 14;
    ctx.fillStyle = c;
    ctx.globalAlpha = 0.85;

    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
    ctx.fill();

    // tail
    ctx.globalAlpha = 0.22;
    ctx.shadowBlur = 0;
    ctx.fillRect(p.x - 18, p.y - 1, 14, 2);

    ctx.restore();
  }

  function update(dt){
    // spawn logic: speed events/sec
    state.spawnAcc += dt * state.speed;
    const spawnN = Math.floor(state.spawnAcc);
    state.spawnAcc -= spawnN;

    for (let i=0;i<spawnN;i++) spawn();

    // update particles
    const w = canvas.getBoundingClientRect().width;
    for (let i=state.particles.length-1;i>=0;i--){
      const p = state.particles[i];
      p.life += dt;
      p.x += p.vx * dt;

      if (p.x > w + 30){
        state.particles.splice(i,1);
      }
    }
  }

  function rafLoop(tNow){
    const dt = Math.min(0.05, (tNow - state.tPrev) / 1000);
    state.tPrev = tNow;

    // fps calc
    state.fpsAcc += dt;
    state.fpsFrames++;
    if (state.fpsAcc >= 0.5){
      state.fps = Math.round(state.fpsFrames / state.fpsAcc);
      state.fpsAcc = 0;
      state.fpsFrames = 0;
      fpsEl.textContent = String(state.fps);
    }

    const w = canvas.getBoundingClientRect().width;
    const h = canvas.getBoundingClientRect().height;

    drawBackground(w, h);

    if (state.running){
      update(dt);
    }

    // draw particles
    for (const p of state.particles){
      drawParticle(p);
    }

    // as-of
    asof.textContent = `as-of ${new Date().toTimeString().slice(0,8)}`;

    requestAnimationFrame(rafLoop);
  }

  // ===== Clock =====
  function tickClock(){
    const d = new Date();
    clock.textContent = d.toTimeString().slice(0,8);
  }

  // ===== Boot =====
  function boot(){
    resizeCanvas();
    setSpeed(state.speed);
    setRunning(true);
    tickClock();
    setInterval(tickClock, 1000);

    // warm start some events to avoid empty UI
    for (let i=0;i<6;i++) spawn();
    renderFeed();

    requestAnimationFrame((t)=> {
      state.tPrev = t;
      requestAnimationFrame(rafLoop);
    });
  }

  boot();
})();