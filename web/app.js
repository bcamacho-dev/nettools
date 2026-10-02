const login = document.querySelector("#login");
const app = document.querySelector("#app");
const loginError = document.querySelector("#login-error");
const statusEl = document.querySelector("#status");
const netEl = document.querySelector("#net");
const hint = document.querySelector("#hint");
const toolStatus = document.querySelector("#tool-status");
let network = null;

document.querySelector("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  loginError.hidden = true;
  const token = document.querySelector("#token").value.trim();
  try {
    await api("/api/v1/session", { method: "POST", json: { token }, token });
    sessionStorage.setItem("token", token);
    await boot();
  } catch (err) {
    loginError.hidden = false;
    loginError.textContent = err.message;
  }
});

document.querySelector("#scan-btn").addEventListener("click", () => runScan());
document.querySelector("#dhcp-btn").addEventListener("click", () => runDHCP());
document.querySelector("#stab-btn").addEventListener("click", () => runStability());
document.querySelector("#speed-btn").addEventListener("click", () => runSpeed());
document.querySelector("#lan-btn").addEventListener("click", () => {
  refreshLAN().catch((err) => setStatus(err.message));
});
document.querySelector("#dns-btn").addEventListener("click", () => runDNS());
document.querySelector("#reach-btn").addEventListener("click", () => runReach());
document.querySelector("#path-btn").addEventListener("click", () => runPath(false));
document.querySelector("#exit-btn").addEventListener("click", () => runPath(true));
document.querySelector("#svc-btn").addEventListener("click", () => runServices());
document.querySelector("#arp-btn").addEventListener("click", () => runNeighbors());
document.querySelector("#wol-btn").addEventListener("click", () => runWake());

boot().catch((err) => {
  if (!err || err.status === 401) return;
  loginError.hidden = false;
  loginError.textContent = err.message;
});

async function boot() {
  const token = sessionStorage.getItem("token");
  if (!token) return;
  network = await api("/api/v1/network");
  renderNetwork(network);
  login.hidden = true;
  app.hidden = false;
  refreshLAN().catch(() => {});
  loadMap().catch(() => {});
  const [scan, stab, speed] = await Promise.allSettled([
    api("/api/v1/scans/latest"),
    api("/api/v1/stability/latest"),
    api("/api/v1/speed/latest"),
  ]);
  if (scan.status === "fulfilled") renderScan(scan.value);
  if (stab.status === "fulfilled") renderStability(stab.value);
  if (speed.status === "fulfilled") renderSpeed(speed.value);
}

function renderNetwork(net) {
  network = net;
  netEl.replaceChildren();
  const bits = [
    net.interface,
    net.ip,
    net.subnet,
    net.gateway ? "gw " + net.gateway : "",
  ].filter(Boolean);
  for (const bit of bits) {
    const span = document.createElement("span");
    span.className = "chip";
    span.textContent = bit;
    netEl.appendChild(span);
  }
  if (net.os === "linux") {
    hint.textContent = "ARP e DHCP usam socket cru. Se a varredura falhar, conceda cap_net_raw ou execute como root.";
  } else {
    hint.textContent = "Nesta máquina a varredura usa a API do Windows. O exame de DHCP com socket cru é o do servidor Linux.";
  }
  if (net.scan_error) setStatus(net.scan_error);
}

async function runScan() {
  setBusy(true);
  setStatus("Iniciando exame…");
  try {
    const scan = await api("/api/v1/scans", { method: "POST", json: {} });
    await poll(scan.id);
  } catch (err) {
    setStatus(err.message);
  } finally {
    setBusy(false);
  }
}

async function poll(id) {
  for (;;) {
    const scan = await api("/api/v1/scans/" + id);
    if (scan.status === "running") {
      setStatus(scan.detail || "Examinando…");
      await sleep(1000);
      continue;
    }
    renderScan(scan);
    setStatus(scan.status === "error" ? scan.error || "Falhou" : "Exame concluído");
    return;
  }
}

async function runDHCP() {
  setBusy(true);
  setStatus("Procurando DHCP…");
  try {
    const scan = await api("/api/v1/dhcp", { method: "POST", json: {} });
    renderDHCP(scan);
    setStatus(scan.dhcp_error || "DHCP concluído");
  } catch (err) {
    setStatus(err.message);
  } finally {
    setBusy(false);
  }
}

async function runStability() {
  setBusy(true);
  const target = toolHost();
  setStatus(target ? "Medindo " + target + "…" : "Medindo o caminho até o gateway…");
  try {
    const st = await api("/api/v1/stability", { method: "POST", json: { target, count: 10 } });
    renderStability(st);
    setStatus("Estabilidade concluída");
  } catch (err) {
    setStatus(err.message);
  } finally {
    setBusy(false);
  }
}

async function runSpeed() {
  const speedBtn = document.querySelector("#speed-btn");
  speedBtn.disabled = true;
  try {
    setStatus("Medindo descarga…");
    const down = await timedDownload(4000);
    setStatus("Medindo subida…");
    const up = await timedUpload(4000);
    setStatus("Medindo latência…");
    const rtt = await httpLatency();
    const saved = await api("/api/v1/speed", {
      method: "POST",
      json: { down_mbps: down, up_mbps: up, http_rtt_ms: rtt },
    });
    renderSpeed(saved);
    setStatus("Velocidade concluída");
  } catch (err) {
    setStatus(err.message);
  } finally {
    speedBtn.disabled = false;
  }
}

function renderScan(scan) {
  document.querySelector("#scan-when").textContent = scan.finished
    ? "último exame " + new Date(scan.finished).toLocaleString("pt-BR")
    : "";
  const err = document.querySelector("#scan-error");
  if (scan.status === "error" && scan.error) {
    err.hidden = false;
    err.textContent = scan.error;
  } else {
    err.hidden = true;
  }
  renderDevices(scan.devices || []);
  renderDHCP(scan);
  if (!scan.kind || scan.kind === "discover") loadMap().catch(() => {});
}

const mapKinds = {
  gateway: ["#3a2c16", "#e0a24a", "Gateway"],
  self: ["#243024", "#b7c48a", "Este servidor"],
  printer: ["#2a241c", "#d4b483", "Impressora"],
  computer: ["#1e2430", "#9eb0c9", "Computador"],
  media: ["#2a2030", "#c9a0c0", "Mídia"],
  other: ["#221f1a", "#8d8272", "Outro"],
};

async function loadMap() {
  renderMap(await api("/api/v1/map"));
}

function renderMap(diagram) {
  const wrap = document.querySelector("#map-wrap");
  const empty = document.querySelector("#map-empty");
  const note = document.querySelector("#map-note");
  const legend = document.querySelector("#map-legend");
  wrap.replaceChildren();
  legend.replaceChildren();
  const nodes = diagram.nodes || [];
  note.textContent = [diagram.subnet, diagram.note].filter(Boolean).join(" · ");
  empty.hidden = nodes.length > 0;
  if (!nodes.length) return;

  const seen = new Set();
  for (const node of nodes) {
    if (seen.has(node.kind) || !mapKinds[node.kind]) continue;
    seen.add(node.kind);
    const item = document.createElement("span");
    const swatch = document.createElement("i");
    swatch.className = "swatch";
    swatch.style.background = mapKinds[node.kind][0];
    swatch.style.borderColor = mapKinds[node.kind][1];
    item.append(swatch, document.createTextNode(mapKinds[node.kind][2]));
    legend.appendChild(item);
  }

  const svg = svgEl("svg", {
    width: diagram.width,
    height: diagram.height,
    viewBox: "0 0 " + diagram.width + " " + diagram.height,
    role: "img",
  });
  svg.setAttribute("aria-label", "Mapa da rede montado pelo servidor");
  for (const line of diagram.lines || []) {
    svg.appendChild(svgEl("line", {
      x1: line.x1, y1: line.y1, x2: line.x2, y2: line.y2,
      stroke: "#5c5346", "stroke-width": 1.5,
    }));
  }
  for (const node of nodes) {
    const colors = mapKinds[node.kind] || mapKinds.other;
    const group = svgEl("g", { class: "map-node", tabindex: "0" });
    group.style.cursor = "pointer";
    group.appendChild(svgEl("rect", {
      x: node.x, y: node.y, width: node.w, height: node.h, rx: 2,
      fill: colors[0], stroke: colors[1], "stroke-width": 1.5,
    }));
    group.appendChild(svgText(node.label, node.x + 10, node.y + 20, "#f4f0e6", 13));
    group.appendChild(svgText(node.detail, node.x + 10, node.y + 36, "#a89c88", 11));
    const tip = svgEl("title");
    tip.textContent = [node.label, node.ip, node.badge].filter(Boolean).join(" · ");
    group.append(tip);
    group.addEventListener("click", () => selectMapHost(node.ip));
    group.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        selectMapHost(node.ip);
      }
    });
    svg.appendChild(group);
  }
  wrap.appendChild(svg);
}

function selectMapHost(ip) {
  const host = document.querySelector("#tool-host");
  if (!host || !ip) return;
  host.value = ip;
  host.focus();
}

function svgEl(name, attrs = {}) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  return el;
}

function svgText(value, x, y, fill, size) {
  const text = svgEl("text", { x, y, fill, "font-size": size });
  text.textContent = value || "";
  return text;
}

function renderDevices(devices) {
  const body = document.querySelector("#devices");
  const empty = document.querySelector("#devices-empty");
  body.replaceChildren();
  document.querySelector("#devices-title").textContent = "Dispositivos (" + devices.length + ")";
  empty.hidden = devices.length > 0;
  for (const device of devices) {
    const tr = document.createElement("tr");
    mono(tr, device.ip);
    mono(tr, device.mac);
    text(tr, device.vendor);
    const name = text(tr, device.hostname || device.http_title);
    if (device.names && device.names.length) name.title = device.names.join("\n");
    text(tr, (device.ports || []).map((p) => p.port + " " + p.label).join(", "));
    text(tr, device.role);
    body.appendChild(tr);
  }
}

function renderDHCP(scan) {
  const servers = scan.dhcp || [];
  const body = document.querySelector("#dhcp");
  const empty = document.querySelector("#dhcp-empty");
  const banner = document.querySelector("#dhcp-banner");
  const err = document.querySelector("#dhcp-error");
  body.replaceChildren();
  empty.hidden = servers.length > 0;
  empty.textContent = scan && (scan.status === "done" || scan.status === "error")
    ? "Nenhum servidor DHCP respondeu."
    : "Nenhum exame de DHCP ainda.";
  if (scan.dhcp_error) {
    err.hidden = false;
    err.textContent = scan.dhcp_error;
  } else {
    err.hidden = true;
  }
  if (servers.length > 1) {
    banner.hidden = false;
    banner.textContent = "Há " + servers.length + " servidores DHCP respondendo nesta rede.";
  } else {
    banner.hidden = true;
  }
  for (const server of servers) {
    const tr = document.createElement("tr");
    mono(tr, server.server_id);
    mono(tr, server.source_ip);
    const mac = mono(tr, server.mac);
    if (server.vendor) mac.title = server.vendor;
    mono(tr, server.offered_ip);
    mono(tr, server.subnet_mask);
    text(tr, (server.dns || []).join(", "));
    text(tr, server.hostname);
    body.appendChild(tr);
  }
}

function renderStability(st) {
  document.querySelector("#loss").textContent = fmt(st.loss, 1);
  document.querySelector("#avg").textContent = fmt(st.avg_ms, 2);
  document.querySelector("#jitter").textContent = fmt(st.jitter_ms, 2);
  document.querySelector("#stab-detail").textContent =
    st.target + " · " + st.recv + "/" + st.sent + " respostas · " +
    fmt(st.min_ms, 2) + "–" + fmt(st.max_ms, 2) + " ms";
}

function renderSpeed(sp) {
  document.querySelector("#down").textContent = fmtMbps(sp.down_mbps);
  document.querySelector("#up").textContent = fmtMbps(sp.up_mbps);
  document.querySelector("#rtt").textContent = fmt(sp.http_rtt_ms, 1);
}

function text(tr, value) {
  const td = document.createElement("td");
  td.textContent = value || "—";
  tr.appendChild(td);
  return td;
}

function mono(tr, value) {
  const td = text(tr, value);
  td.className = "mono-cell";
  return td;
}

function setStatus(message) {
  statusEl.textContent = message || "";
}

function setBusy(busy) {
  for (const el of document.querySelectorAll("[data-exam]")) el.disabled = busy;
}

async function refreshLAN() {
  const lan = await api("/api/v1/lan");
  renderLAN(lan);
}

function renderLAN(lan) {
  const box = document.querySelector("#lan-facts");
  const banner = document.querySelector("#lan-banner");
  box.replaceChildren();
  const origin = { dhcp: "DHCP", manual: "manual" }[lan.origin] || "";
  const rows = [
    ["Nome", lan.hostname],
    ["DNS", (lan.dns || []).join(", ")],
    ["MTU", lan.mtu ? String(lan.mtu) : ""],
    ["Link", lan.link_mbps ? lan.link_mbps + " Mb/s" : ""],
    ["Estado", lan.up ? "no ar" : "baixo"],
    ["Origem do IP", origin],
    ["Servidor DHCP", lan.dhcp_server],
    ["IPv6", (lan.ipv6 || []).join(", ")],
    ["Broadcast", lan.broadcast],
  ];
  for (const [key, value] of rows) {
    if (!value) continue;
    const cell = document.createElement("div");
    const k = document.createElement("span");
    k.className = "k";
    k.textContent = key;
    const v = document.createElement("span");
    v.className = "v";
    v.textContent = value;
    cell.append(k, v);
    box.appendChild(cell);
  }
  if (lan.duplicate) {
    banner.hidden = false;
    banner.textContent = "O sistema marcou o endereço desta máquina como duplicado na rede.";
  } else {
    banner.hidden = true;
  }
}

async function runDNS() {
  await tool("Consultando DNS…", async () => {
    const name = toolHost();
    if (!name) throw new Error("informe um nome ou um IP");
    const result = await api("/api/v1/tools/dns", { method: "POST", json: { name } });
    showTable(
      ["Servidor", "Resposta", "ms"],
      (result.answers || []).map((row) => [
        row.server,
        row.error || (row.values || []).join(", ") || "sem registro",
        fmt(row.ms, 1),
      ]),
    );
    toolStatus.textContent = result.kind + " de " + result.name;
  });
}

async function runReach() {
  await tool("Testando portas na LAN…", async () => {
    const host = toolHost();
    if (!host) throw new Error("informe o IP ou o nome do aparelho");
    const raw = document.querySelector("#tool-port").value.trim();
    const port = raw ? Number(raw) : 0;
    if (raw && !Number.isInteger(port)) throw new Error("porta inválida");
    const result = await api("/api/v1/tools/reach", { method: "POST", json: { host, port } });
    showTable(
      ["Porta", "Serviço", "Estado", "ms"],
      (result.ports || []).map((row) => [
        String(row.port),
        row.label,
        row.open ? "aberta" : row.error || "fechada",
        fmt(row.ms, 1),
      ]),
    );
    toolStatus.textContent = result.ip ? host + " → " + result.ip : "";
  });
}

async function runPath(exit) {
  await tool(exit ? "Traçando a saída da rede…" : "Traçando o caminho na LAN…", async () => {
    const result = await api("/api/v1/tools/path", {
      method: "POST",
      json: { host: toolHost(), exit },
    });
    const banner = document.querySelector("#tool-banner");
    const first = (result.hops || []).find((hop) => hop.ip);
    if (!exit && network && network.gateway && first && first.ip !== network.gateway) {
      banner.hidden = false;
      banner.textContent = "O primeiro salto (" + first.ip + ") não é o gateway " + network.gateway + ".";
    } else if (exit && network && network.gateway && first && first.ip !== network.gateway) {
      banner.hidden = false;
      banner.textContent = "A saída não começa no gateway " + network.gateway + ". O primeiro salto é " + first.ip + ".";
    } else {
      banner.hidden = true;
    }
    showTable(
      ["Salto", "Endereço", "ms"],
      (result.hops || []).map((hop) => [String(hop.ttl), hop.timeout ? "sem resposta" : hop.ip, hop.timeout ? "—" : fmt(hop.ms, 1)]),
    );
    toolStatus.textContent = "Alvo " + result.target;
  });
}

async function runServices() {
  await tool("Ouvindo anúncios da rede…", async () => {
    const items = await api("/api/v1/tools/services", { method: "POST", json: {} });
    showTable(
      ["Nome", "Tipo", "IP", "Porta"],
      (items || []).map((item) => [item.name, serviceType(item.type), item.ip || item.host, item.port ? String(item.port) : ""]),
    );
    if (!items || !items.length) toolStatus.textContent = "Nenhum serviço anunciado respondeu.";
    else if (items.length >= 100) toolStatus.textContent = "Mostrando os primeiros 100 anúncios.";
  });
}

async function runNeighbors() {
  await tool("Lendo vizinhos que o sistema já conhece…", async () => {
    const items = await api("/api/v1/neighbors");
    showTable(
      ["IP", "MAC", "Fabricante", "Interface"],
      (items || []).map((item) => [item.ip, item.mac, item.vendor, item.interface]),
    );
    if (!items || !items.length) toolStatus.textContent = "A tabela de vizinhos está vazia.";
  });
}

async function runWake() {
  await tool("Enviando despertar…", async () => {
    const mac = document.querySelector("#tool-mac").value.trim();
    if (!mac) throw new Error("informe o MAC do aparelho");
    const result = await api("/api/v1/tools/wol", { method: "POST", json: { mac } });
    clearResult();
    const p = document.createElement("p");
    p.textContent = "Pacote enviado para " + result.mac + (result.broadcast ? " via " + result.broadcast : "") + ".";
    document.querySelector("#tool-result").appendChild(p);
  });
}

async function tool(label, fn) {
  setBusy(true);
  toolStatus.textContent = label;
  document.querySelector("#tool-banner").hidden = true;
  try {
    await fn();
    if (toolStatus.textContent === label) toolStatus.textContent = "Concluído";
  } catch (err) {
    toolStatus.textContent = err.message;
  } finally {
    setBusy(false);
  }
}

function toolHost() {
  return document.querySelector("#tool-host").value.trim();
}

function clearResult() {
  document.querySelector("#tool-result").replaceChildren();
}

function showTable(headers, rows) {
  clearResult();
  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const header of headers) {
    if (!header) continue;
    const th = document.createElement("th");
    th.textContent = header;
    head.appendChild(th);
  }
  const thead = document.createElement("thead");
  thead.appendChild(head);
  const body = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    row.forEach((value, index) => {
      if (!headers[index]) return;
      const td = document.createElement("td");
      td.textContent = value || "—";
      if (index < 2) td.className = "mono-cell";
      tr.appendChild(td);
    });
    body.appendChild(tr);
  }
  table.append(thead, body);
  wrap.appendChild(table);
  document.querySelector("#tool-result").appendChild(wrap);
}

function serviceType(value) {
  const names = {
    "_ipp._tcp": "impressora",
    "_ipps._tcp": "impressora",
    "_printer._tcp": "impressora",
    "_pdl-datastream._tcp": "impressora",
    "_googlecast._tcp": "Chromecast",
    "_airplay._tcp": "AirPlay",
    "_raop._tcp": "áudio",
    "_hap._tcp": "HomeKit",
    "_homekit._tcp": "HomeKit",
    "_smb._tcp": "arquivos",
    "_ssh._tcp": "SSH",
    "_http._tcp": "web",
    "_https._tcp": "web",
    "_workstation._tcp": "computador",
    "_device-info._tcp": "aparelho",
    "_spotify-connect._tcp": "Spotify",
  };
  return names[value] || value || "—";
}

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers);
  const token = opts.token || sessionStorage.getItem("token");
  if (token) headers.Authorization = "Bearer " + token;
  let body = opts.body;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  }
  const res = await fetch(path, { method: opts.method || "GET", headers, body, cache: "no-store" });
  if (res.status === 204) return null;
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!res.ok) {
    const err = new Error((data && data.error) || res.statusText);
    err.status = res.status;
    throw err;
  }
  return data;
}

async function timedDownload(ms) {
  const headers = authHeaders();
  const end = performance.now() + ms;
  let bytes = 0;
  async function one() {
    while (performance.now() < end) {
      const res = await fetch("/speed/download?bytes=" + (4 * 1024 * 1024), { headers, cache: "no-store" });
      if (!res.ok || !res.body) throw new Error("descarga falhou");
      const reader = res.body.getReader();
      while (performance.now() < end) {
        const chunk = await reader.read();
        if (chunk.done) break;
        bytes += chunk.value.byteLength;
      }
      await reader.cancel();
    }
  }
  const t0 = performance.now();
  await Promise.all([one(), one(), one(), one()]);
  return ((bytes * 8) / ((performance.now() - t0) / 1000)) / 1e6;
}

async function timedUpload(ms) {
  const headers = authHeaders();
  const chunk = randomBytes(256 * 1024);
  const blob = new Blob([chunk, chunk, chunk, chunk]);
  const end = performance.now() + ms;
  let bytes = 0;
  async function one() {
    while (performance.now() < end) {
      const res = await fetch("/speed/upload", { method: "POST", headers, body: blob, cache: "no-store" });
      if (!res.ok) throw new Error("subida falhou");
      bytes += blob.size;
    }
  }
  const t0 = performance.now();
  await Promise.all([one(), one(), one(), one()]);
  return ((bytes * 8) / ((performance.now() - t0) / 1000)) / 1e6;
}

async function httpLatency() {
  const headers = authHeaders();
  const samples = [];
  for (let i = 0; i < 8; i++) {
    const t = performance.now();
    const res = await fetch("/speed/empty", { headers, cache: "no-store" });
    if (!res.ok && res.status !== 204) throw new Error("latência falhou");
    samples.push(performance.now() - t);
  }
  const used = samples.slice(1);
  return used.reduce((sum, n) => sum + n, 0) / used.length;
}

function randomBytes(n) {
  const out = new Uint8Array(n);
  const limit = 65536;
  for (let offset = 0; offset < n; offset += limit) {
    crypto.getRandomValues(out.subarray(offset, Math.min(n, offset + limit)));
  }
  return out;
}

function authHeaders() {
  return { Authorization: "Bearer " + sessionStorage.getItem("token") };
}

function fmt(n, digits) {
  return Number.isFinite(n) ? n.toFixed(digits) : "—";
}

function fmtMbps(n) {
  if (!Number.isFinite(n)) return "—";
  return n >= 100 ? n.toFixed(0) : n.toFixed(1);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
