(() => {
  const zoneFilter = document.getElementById("zoneFilter");
  const protocolFilter = document.getElementById("protocolFilter");
  const pollInterval = document.getElementById("pollInterval");
  const pollLabel = document.getElementById("pollLabel");
  const refreshNow = document.getElementById("refreshNow");
  const snapshotTime = document.getElementById("snapshotTime");

  const packetFeed = document.getElementById("packetFeed");

  const zoneInternal = document.getElementById("zoneInternal");
  const zoneOutbound = document.getElementById("zoneOutbound");
  const zoneInbound = document.getElementById("zoneInbound");
  const zoneExternal = document.getElementById("zoneExternal");

  const hId = document.getElementById("hId");
  const hSource = document.getElementById("hSource");
  const hDestination = document.getElementById("hDestination");
  const hFamily = document.getElementById("hFamily");
  const hProtocol = document.getElementById("hProtocol");
  const hState = document.getElementById("hState");
  const hZone = document.getElementById("hZone");
  const hDirection = document.getElementById("hDirection");
  const hLocalPort = document.getElementById("hLocalPort");
  const hRemotePort = document.getElementById("hRemotePort");
  const hPid = document.getElementById("hPid");
  const hProcess = document.getElementById("hProcess");
  const hRisk = document.getElementById("hRisk");
  const hPolicy = document.getElementById("hPolicy");

  const state = {
    allPackets: [],
    filteredPackets: [],
    selectedId: null,
    timer: null,
    intervalSec: 2,
  };

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

  function classifyZone(pkt) {
    if (pkt.zone) return String(pkt.zone).toLowerCase();

    const srcIp = extractIp(pkt.source);
    const dstIp = extractIp(pkt.destination);
    const srcInternal = isPrivateIp(srcIp);
    const dstInternal = isPrivateIp(dstIp);

    if (srcInternal && dstInternal) return "internal";
    if (srcInternal && !dstInternal) return "outbound";
    if (!srcInternal && dstInternal) return "inbound";
    return "external";
  }

  function connectionState(pkt) {
    if (pkt.state) return String(pkt.state).toUpperCase();
    return String(pkt.info || "").replace("State: ", "").toUpperCase() || "UNKNOWN";
  }

  function classifyPolicy(pkt) {
    const s = connectionState(pkt);
    if (s.includes("ESTABLISHED") || s.includes("LISTEN")) return "allow / monitor";
    if (s.includes("WAIT") || String(pkt.protocol).toUpperCase() === "UDP") return "inspect / rate-limit";
    return "review / potential block";
  }

  function directionFor(zone) {
    if (zone === "local-only") return "LOCAL LISTENER";
    if (zone === "outbound") return "LAN -> WAN";
    if (zone === "inbound") return "WAN -> LAN";
    if (zone === "internal") return "LAN -> LAN";
    return "WAN -> WAN";
  }

  function zoneBadgeClass(zone) {
    if (zone === "internal" || zone === "local-only") return "good";
    if (zone === "outbound" || zone === "local-only") return "warn";
    if (zone === "inbound") return "bad";
    return "bad";
  }

  function matchesFilters(pkt) {
    const zone = classifyZone(pkt);
    const normalizedZone = zone === "local-only" ? "internal" : zone;
    const protocol = String(pkt.protocol || "").toUpperCase().replace("6", "");

    if (zoneFilter.value !== "all" && zoneFilter.value !== normalizedZone) return false;
    if (protocolFilter.value !== "all" && protocolFilter.value !== protocol) return false;
    return true;
  }

  function updateSummary() {
    let internal = 0;
    let outbound = 0;
    let inbound = 0;
    let external = 0;

    state.allPackets.forEach((pkt) => {
      const rawZone = classifyZone(pkt);
      const zone = rawZone === "local-only" ? "internal" : rawZone;
      if (zone === "internal") internal += 1;
      else if (zone === "outbound") outbound += 1;
      else if (zone === "inbound") inbound += 1;
      else external += 1;
    });

    zoneInternal.textContent = String(internal);
    zoneOutbound.textContent = String(outbound);
    zoneInbound.textContent = String(inbound);
    zoneExternal.textContent = String(external);
  }

  function renderInspector(packet) {
    if (!packet) {
      [
        hId,
        hSource,
        hDestination,
        hFamily,
        hProtocol,
        hState,
        hZone,
        hDirection,
        hLocalPort,
        hRemotePort,
        hPid,
        hProcess,
        hRisk,
        hPolicy,
      ].forEach((el) => {
        el.textContent = "—";
      });
      return;
    }

    const zone = classifyZone(packet);
    const normalizedZone = zone === "local-only" ? "internal" : zone;
    hId.textContent = packet.id || "—";
    hSource.textContent = packet.source || "—";
    hDestination.textContent = packet.destination || "—";
    hFamily.textContent = packet.family || "—";
    hProtocol.textContent = String(packet.protocol || "—").toUpperCase();
    hState.textContent = connectionState(packet);
    hZone.textContent = normalizedZone.toUpperCase();
    hDirection.textContent = directionFor(zone);
    hLocalPort.textContent = packet.local_port ?? "—";
    hRemotePort.textContent = packet.remote_port ?? "—";
    hPid.textContent = packet.pid ?? "—";
    hProcess.textContent = packet.process_name || "—";
    hRisk.textContent = String(packet.risk || "low").toUpperCase();
    hPolicy.textContent = classifyPolicy(packet).toUpperCase();
  }

  function renderFeed() {
    state.filteredPackets = state.allPackets.filter(matchesFilters).slice(0, 30);
    packetFeed.innerHTML = "";

    if (!state.filteredPackets.length) {
      packetFeed.innerHTML = '<p class="rt-empty">No packets match the active filters.</p>';
      renderInspector(null);
      return;
    }

    state.filteredPackets.forEach((pkt) => {
      const zone = classifyZone(pkt);
      const div = document.createElement("div");
      div.className = "rt-item rt-item--clickable";
      div.dataset.id = String(pkt.id);
      div.innerHTML = `
        <div class="rt-item-top">
          <div class="rt-item-title">${pkt.source} <span class="rt-meta-inline">-></span> ${pkt.destination}</div>
          <span class="rt-badge ${zoneBadgeClass(zone)}">${zone.toUpperCase()}</span>
        </div>
        <div class="rt-item-bottom">
          <div class="rt-item-meta">${String(pkt.protocol || "UNK").toUpperCase()} • ${connectionState(pkt)} • PID:${pkt.pid ?? "-"}</div>
          <div class="rt-item-meta">${pkt.process_name || "unknown"}</div>
          <div class="rt-item-meta">${directionFor(zone)}</div>
        </div>
      `;

      div.addEventListener("click", () => {
        state.selectedId = String(pkt.id);
        document.querySelectorAll(".rt-item--active").forEach((n) => n.classList.remove("rt-item--active"));
        div.classList.add("rt-item--active");
        renderInspector(pkt);
      });

      packetFeed.appendChild(div);
    });

    const selected = state.filteredPackets.find((pkt) => String(pkt.id) === state.selectedId) || state.filteredPackets[0];
    state.selectedId = String(selected.id);
    renderInspector(selected);

    const active = packetFeed.querySelector(`.rt-item[data-id="${state.selectedId}"]`);
    if (active) active.classList.add("rt-item--active");
  }

  async function fetchPackets() {
    try {
      const res = await fetch("/api/pcap");
      if (!res.ok) return;
      const data = await res.json();
      state.allPackets = Array.isArray(data) ? data.slice().reverse() : [];
      snapshotTime.textContent = `as-of ${new Date().toTimeString().slice(0, 8)}`;
      updateSummary();
      renderFeed();
    } catch (err) {
      packetFeed.innerHTML = '<p class="rt-empty">Failed to load packet snapshot.</p>';
    }
  }

  function resetTimer() {
    if (state.timer) clearInterval(state.timer);
    state.timer = setInterval(fetchPackets, state.intervalSec * 1000);
  }

  zoneFilter.addEventListener("change", renderFeed);
  protocolFilter.addEventListener("change", renderFeed);

  pollInterval.addEventListener("input", () => {
    state.intervalSec = parseInt(pollInterval.value, 10);
    pollLabel.textContent = `${state.intervalSec}s`;
    resetTimer();
  });

  refreshNow.addEventListener("click", fetchPackets);

  pollLabel.textContent = `${state.intervalSec}s`;
  fetchPackets();
  resetTimer();
})();
