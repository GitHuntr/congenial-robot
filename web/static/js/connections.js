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

  const asof = document.getElementById("asof");
  const modeText = document.getElementById("modeText");

  const evCountEl = document.getElementById("evCount");
  const p95El = document.getElementById("p95");
  const externalCountEl = document.getElementById("externalCount");
  const foot = document.getElementById("foot");

  // ===== State =====
  const state = {
    running: true,
    speed: 2,          // poll interval in seconds
    particles: [],
    events: [],
    knownIds: new Set(),
    totalEvents: 0,
    laneCount: 7,
    tPrev: performance.now(),
    canvasWidth: 0,
    canvasHeight: 0,
    maxParticles: 120
  };

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

  const rand = (a,b) => a + Math.random() * (b-a);

  function extractIp(endpoint = "") {
    const m = endpoint.match(/\d{1,3}(?:\.\d{1,3}){3}/);
    return m ? m[0] : "";
  }

  function isPrivateIp(ip) {
    if (!ip) return false;
    if (ip.startsWith("10.")) return true;
    if (ip.startsWith("192.168.")) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
    if (ip.startsWith("127.")) return true;
    return false;
  }

  function classifyFlow(conn) {
    if (conn.zone) {
      const z = String(conn.zone).toLowerCase();
      return z === "local-only" ? "internal" : z;
    }

    const srcIp = extractIp(conn.source);
    const dstIp = extractIp(conn.destination);
    const srcInternal = isPrivateIp(srcIp);
    const dstInternal = isPrivateIp(dstIp);

    if (srcInternal && dstInternal) return "internal";
    if (srcInternal && !dstInternal) return "outbound";
    if (!srcInternal && dstInternal) return "inbound";
    return "external";
  }

  // ===== Resize / DPR =====
  function resizeCanvas(){
    const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    const rect = canvas.getBoundingClientRect();
    state.canvasWidth = rect.width;
    state.canvasHeight = rect.height;
    canvas.width = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  window.addEventListener("resize", resizeCanvas);

  // ===== Lane geometry =====
  function laneY(i){
    const h = state.canvasHeight || canvas.getBoundingClientRect().height;
    const top = 44;
    const bottom = h - 64;
    const span = bottom - top;
    return top + (i / (state.laneCount - 1)) * span;
  }

  // ===== Backend Fetching Loop =====
  async function fetchLiveConnections() {
      if(!state.running) {
          setTimeout(fetchLiveConnections, state.speed * 1000);
          return;
      }
      try {
          const res = await fetch('/api/pcap');
          if(res.ok) {
              const connections = await res.json();
              if (connections.length > 0) {
                  // Simulate random ping/latency for aesthetic UI
                  const simPing = Math.round(rand(20, 150));
                  p95El.textContent = `${simPing}ms`;
                  
                  // Process diff to shoot new particles
                  // For a visual makeover, shoot particles for all active if list changed
                  // We'll shoot a random active socket to keep the screen busy!
                  const randConn = connections[Math.floor(Math.random() * connections.length)];
                  if(randConn) {
                      spawnConnection(randConn);
                  }

                  // Update actual feed strictly with backend mapping
                  const sorted = connections.slice().reverse().slice(0, 15);
                  state.events = sorted;
                  state.totalEvents = connections.length;
                  const externalCount = connections.filter(c => classifyFlow(c) !== "internal").length;
                  evCountEl.textContent = String(state.totalEvents);
                  if (externalCountEl) externalCountEl.textContent = String(externalCount);
                  renderFeed();
              } else {
                  state.events = [];
                  state.totalEvents = 0;
                  evCountEl.textContent = "0";
                  if (externalCountEl) externalCountEl.textContent = "0";
                  renderFeed();
              }
          }
      } catch (e) {
          console.log("Failed to fetch sockets from backend");
      }
      
      asof.textContent = `as-of ${new Date().toTimeString().slice(0,8)}`;
      setTimeout(fetchLiveConnections, state.speed * 1000);
  }

  // ===== Spawn transaction particle =====
  function spawnConnection(conn){
    const lane = (Math.random() * state.laneCount) | 0;
    
    let outcome = "bad";
    if (conn.info.includes("ESTABLISHED") || conn.info.includes("LISTEN")) outcome = "approved";
    else if (conn.info.includes("WAIT") || conn.protocol.includes("UDP")) outcome = "review";

    const w = state.canvasWidth || canvas.getBoundingClientRect().width;
    const y = laneY(lane);

    const speedPx = rand(150, 400); // px/sec
    const radius = rand(2.3, 3.8);

    if (state.particles.length >= state.maxParticles) {
      state.particles.shift();
    }

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
  }

  // ===== Feed render =====
  function renderFeed(){
    const html = state.events.map(ev => {
      let badgeClass = "bad";
      let label = String(ev.state || ev.info || "UNKNOWN").replace("State: ", "");
      if (label.includes("ESTABLISHED") || label.includes("LISTEN")) badgeClass = "good";
      else if (label.includes("WAIT") || ev.protocol.includes("UDP")) badgeClass = "warn";
      const flowClass = classifyFlow(ev);
      const flowLabel = flowClass.toUpperCase();
      const flowBadgeClass = flowClass === "internal" ? "good" : flowClass === "outbound" ? "warn" : "bad";

      const time = new Date().toTimeString().slice(0,8);
      return `
        <div class="rt-item">
          <div class="rt-item-top">
            <div class="rt-item-title">${ev.source} <span class="rt-flow-arrow">➔</span> ${ev.destination}</div>
            <span class="rt-badge ${badgeClass}">${label}</span>
          </div>
          <div class="rt-item-bottom">
            <div class="rt-item-meta">${time} • ${ev.protocol} • ID:${ev.id}</div>
            <span class="rt-badge ${flowBadgeClass}">${flowLabel}</span>
          </div>
        </div>
      `;
    }).join("");

    feed.innerHTML = html || '<p class="rt-empty">No live flows in the current polling window.</p>';
    const activeExternal = state.events.filter(c => classifyFlow(c) !== "internal").length;
    foot.textContent = `Polling Rate: ${state.speed}s • Canvas Lanes: ${state.laneCount} • External/Boundary Flows: ${activeExternal}`;
  }

  // ===== Copy =====
  btnCopy.addEventListener("click", async () => {
    const lines = state.events.map(ev => {
      return `${ev.source} -> ${ev.destination} | ${ev.protocol} | ${ev.info}`;
    }).join("\n");

    try{
      await navigator.clipboard.writeText(lines);
      btnCopy.innerHTML = `<i class="fa-solid fa-check"></i>`;
      setTimeout(()=> btnCopy.innerHTML = `<svg class="icon-14" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 01-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 00-3.375-3.375h-1.5a1.125 1.125 0 01-1.125-1.125v-1.5a3.375 3.375 0 00-3.375-3.375H9.75" /></svg>`, 900);
    }catch(e){
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

    btnToggleLabel.textContent = next ? "Pause Stream" : "Resume Stream";
    modeText.textContent = next ? "Scanning..." : "Frozen";
  }

  function setSpeed(v){
    state.speed = v;
    speedLabel.textContent = `${v}s`;
    speedRange.value = String(v);
  }

  btnToggle.addEventListener("click", () => setRunning(!state.running));

  btnClear.addEventListener("click", () => {
    state.particles.length = 0;
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
    }
    if (e.key === "ArrowUp"){
      e.preventDefault();
      setSpeed(Math.min(state.speed + 1, 10));
    }
    if (e.key === "ArrowDown"){
      e.preventDefault();
      setSpeed(Math.max(state.speed - 1, 1));
    }
  });

  // ===== Drawing =====
  function drawBackground(w, h){
    ctx.clearRect(0,0,w,h);
    const g = ctx.createLinearGradient(0,0,0,h);
    g.addColorStop(0, "rgba(12,20,41,.85)");
    g.addColorStop(1, "rgba(7,10,18,.85)");
    ctx.fillStyle = g;
    ctx.fillRect(0,0,w,h);

    ctx.strokeStyle = COLORS.grid;
    ctx.lineWidth = 1;

    for (let i=0;i<state.laneCount;i++){
      const y = laneY(i);
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    ctx.strokeStyle = "rgba(255,255,255,.04)";
    for (let x=60; x<w; x+=90){
      ctx.beginPath();
      ctx.moveTo(x, 18);
      ctx.lineTo(x, h-18);
      ctx.stroke();
    }

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
    ctx.save();
    ctx.shadowColor = c;
    ctx.shadowBlur = 8;
    ctx.fillStyle = c;
    ctx.globalAlpha = 0.85;

    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
    ctx.fill();

    ctx.globalAlpha = 0.22;
    ctx.shadowBlur = 0;
    ctx.fillRect(p.x - 18, p.y - 1, 14, 2);
    ctx.restore();
  }

  function update(dt){
    // In our app, particles are injected when fetchLiveConnections resolves socket hits.
    const w = state.canvasWidth || canvas.getBoundingClientRect().width;
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
    if (document.hidden) {
      requestAnimationFrame(rafLoop);
      return;
    }

    const dt = Math.min(0.05, (tNow - state.tPrev) / 1000);
    state.tPrev = tNow;

    const w = state.canvasWidth || canvas.getBoundingClientRect().width;
    const h = state.canvasHeight || canvas.getBoundingClientRect().height;

    drawBackground(w, h);

    if (state.running){
      update(dt);
    }

    // draw particles
    for (const p of state.particles){
      drawParticle(p);
    }

    requestAnimationFrame(rafLoop);
  }

  // ===== Boot =====
  function boot(){
    resizeCanvas();
    setSpeed(state.speed);
    setRunning(true);
    
    // begin backend polling cycle
    fetchLiveConnections();

    requestAnimationFrame((t)=> {
      state.tPrev = t;
      requestAnimationFrame(rafLoop);
    });
  }

  boot();
})();
