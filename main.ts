// OSINT Bot + Mini App — беспл үтхостинг Deno Deploy (без Base44).
// GET /            → Mini App (HTML)
// POST /api        → JSON API {action: nick|domain|ip|email, query}
// POST /hook?secret=... → Telegram webhook

const HOOK_SECRET = "osint_hook_7f3k9x";
const TOKEN = Deno.env.get("OSINT_BOT_TOKEN") || "";
const API = `https://api.telegram.org/bot${TOKEN}`;
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

const kv = await Deno.openKv();

const tg = (method: string, payload: any) =>
  fetch(`${API}/${method}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
    .then((r) => r.json()).catch(() => ({}));

const esc = (s: any) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const MODES: Record<string, { title: string; hint: string }> = {
  nick:   { title: "🔍 НИК ПО СОЦСЕТЯМ", hint: "Пришлите username (можно с @) — проверю, где он зарегистрирован." },
  domain: { title: "🌐 АНАЛИЗ ДОМЕНА", hint: "Пришлите домен, например example.com" },
  ip:     { title: "📡 ИНФО ПО IP", hint: "Пришлите IP-адрес, например 8.8.8.8" },
  email:  { title: "🕳 УТЕЧКИ EMAIL", hint: "Пришлите email — проверю по базе известных утечек." },
};

// ============ ПОИСКОВЫЕ ФУНКЦИИ ============
async function status(url: string, timeoutMs = 9000): Promise<number> {
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA }, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
    return r.status;
  } catch { return -1; }
}
async function statusAndBody(url: string, timeoutMs = 9000): Promise<{ code: number; body: string }> {
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA }, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
    return { code: r.status, body: (await r.text()).slice(0, 4000) };
  } catch { return { code: -1, body: "" }; }
}
function flagFromCode(code: string): string {
  return [...(code || "")].map((c) => String.fromCodePoint(127397 + c.toUpperCase().charCodeAt(0))).join("");
}

async function searchNick(raw: string) {
  const nick = raw.replace(/^@/, "").replace(/[^a-zA-Z0-9._-]/g, "");
  if (!nick) return { error: "Некорректный ник" };
  const checks = [
    { name: "GitHub", url: `https://github.com/${nick}`, fn: async () => { const c = await status(`https://api.github.com/users/${nick}`); return c === 200 ? "found" : c === 404 ? "not" : "unknown"; } },
    { name: "Telegram", url: `https://t.me/${nick}`, fn: async () => (await status(`https://t.me/${nick}`)) === 200 ? "found" : "not" },
    { name: "Reddit", url: `https://reddit.com/user/${nick}`, fn: async () => (await status(`https://www.reddit.com/user/${nick}/about.json`)) === 200 ? "found" : "not" },
    { name: "GitLab", url: `https://gitlab.com/${nick}`, fn: async () => (await status(`https://gitlab.com/${nick}`)) === 200 ? "found" : "not" },
    { name: "Steam", url: `https://steamcommunity.com/id/${nick}`, fn: async () => { const r = await statusAndBody(`https://steamcommunity.com/id/${nick}`); if (r.code === -1) return "unknown"; return r.body.includes("could not be found") || r.body.includes("The specified profile") ? "not" : "found"; } },
    { name: "YouTube", url: `https://youtube.com/@${nick}`, fn: async () => (await status(`https://www.youtube.com/@${nick}`)) === 200 ? "found" : "not" },
    { name: "TikTok", url: `https://tiktok.com/@${nick}`, fn: async () => { const c = await status(`https://www.tiktok.com/@${nick}`); return c === 200 ? "found" : c === 404 ? "not" : "unknown"; } },
  ];
  const results = await Promise.all(checks.map(async (c) => ({ name: c.name, url: c.url, status: await c.fn() })));
  for (const m of [["Instagram","instagram"],["X (Twitter)","x"],["VK","vk"],["Facebook","facebook"],["Pinterest","pinterest"]] as const) {
    results.push({ name: m[0], url: `https://${m[1]}.com/${nick}`, status: "manual" });
  }
  return { type: "nick", query: nick, results };
}

async function searchDomain(raw: string) {
  const dom = raw.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/[^a-z0-9.\-]/g, "");
  if (!dom.includes(".")) return { error: "Это не похоже на домен. Пример: example.com" };
  const out: any = { type: "domain", query: dom, registrar: "—", created: "—", expires: "—", a: [], mx: [], ns: [], note: "" };
  let rdap: any = null;
  for (const u of [`https://rdap.org/domain/${dom}`, `https://rdap.net/domain/${dom}`]) {
    try {
      const r = await fetch(u, { headers: { "User-Agent": UA, "Accept": "application/rdap+json, application/json" }, redirect: "follow", signal: AbortSignal.timeout(9000) });
      if (r.ok) { rdap = await r.json(); if (rdap) break; }
    } catch { /* next */ }
  }
  if (rdap) {
    out.created = rdap.events?.find((e: any) => e.eventAction === "registration")?.eventDate?.slice(0, 10) || "—";
    out.expires = rdap.events?.find((e: any) => e.eventAction === "expiration")?.eventDate?.slice(0, 10) || "—";
    const ent = (rdap.entities || []).find((e: any) => (e.roles || []).includes("registrar"));
    const fn = ent?.vcardArray?.[1]?.find((v: any) => v[0] === "fn");
    if (fn) out.registrar = fn[3];
  } else out.note = "RDAP: нет данных";
  const dns = async (type: string) => {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${dom}&type=${type}`, { signal: AbortSignal.timeout(9000) });
      const j: any = await r.json();
      return (j.Answer || []).map((a: any) => a.data);
    } catch { return []; }
  };
  [out.a, out.mx, out.ns] = await Promise.all([dns("A"), dns("MX"), dns("NS")]);
  return out;
}

async function searchIp(raw: string) {
  const ip = raw.trim();
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return { error: "Нужен IPv4-адрес, например 8.8.8.8" };
  try {
    const r = await fetch(`https://ipwho.is/${ip}`, { signal: AbortSignal.timeout(8000) });
    const j: any = await r.json();
    if (j && j.success) {
      return { type: "ip", query: j.ip, ipType: j.type, flag: j.flag?.emoji || flagFromCode(j.country_code), country: j.country || "—", region: j.region || "", city: j.city || "—", isp: j.connection?.isp || "—", org: j.connection?.org || "—", domain: j.connection?.domain || "—" };
    }
  } catch { /* fallback */ }
  try {
    const r = await fetch(`https://ipinfo.io/${ip}/json`, { signal: AbortSignal.timeout(8000) });
    const j: any = await r.json();
    if (j && j.ip) {
      return { type: "ip", query: j.ip, ipType: "IPv4", flag: flagFromCode(j.country), country: j.country || "—", region: j.region || "", city: j.city || "—", isp: j.org || "—", org: j.org || "—", domain: j.hostname || "—" };
    }
  } catch { /* next */ }
  return { error: "Сервис IP-информации недоступен" };
}

async function searchEmail(raw: string) {
  const email = raw.trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: "Некорректный email" };
  const key = Deno.env.get("HIBP_API_KEY") || "";
  if (!key) return { type: "email", query: email, needKey: true, breaches: [] };
  try {
    const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers: { "hibp-api-key": key, "User-Agent": "OSINT-Bot" },
      signal: AbortSignal.timeout(12000),
    });
    if (r.status === 404) return { type: "email", query: email, needKey: false, breaches: [], clean: true };
    if (!r.ok) return { error: r.status === 401 ? "Ключ HIBP неверный" : `Сервис HIBP ответил ошибкой (${r.status})` };
    const breaches: any[] = await r.json();
    return { type: "email", query: email, needKey: false, breaches: breaches.map((b) => ({ name: b.Title, date: b.BreachDate, count: b.PwnCount })) };
  } catch { return { error: "Сервис HIBP недоступен" }; }
}

async function runSearch(mode: string, query: string) {
  if (mode === "nick") return await searchNick(query);
  if (mode === "domain") return await searchDomain(query);
  if (mode === "ip") return await searchIp(query);
  if (mode === "email") return await searchEmail(query);
  return { error: "Неизвестный режим" };
}

// форматирование для чата
function formatResult(j: any): string {
  if (j.error) return `⚠️ ${esc(j.error)}`;
  if (j.type === "nick") {
    let out = `🔍 <b>Ник:</b> ${esc(j.query)}\n\n`;
    for (const r of j.results) {
      if (r.status === "found") out += `✅ ${esc(r.name)} — <a href="${r.url}">найден</a>\n`;
      else if (r.status === "not") out += `❌ ${esc(r.name)} — нет\n`;
      else if (r.status === "unknown") out += `⚠️ ${esc(r.name)} — <a href="${r.url}">проверить вручную</a>\n`;
      else out += `📎 ${esc(r.name)} — <a href="${r.url}">вручную</a>\n`;
    }
    return out;
  }
  if (j.type === "domain") {
    let out = `🌐 <b>Домен:</b> ${esc(j.query)}\n\n`;
    if (j.registrar && j.registrar !== "—") out += `🏢 Регистратор: ${esc(j.registrar)}\n📅 Создан: ${esc(j.created)}\n⏳ Истекает: ${esc(j.expires)}\n\n`;
    else if (j.note) out += `⚠️ ${esc(j.note)}\n\n`;
    out += `📍 A: ${esc((j.a || []).join(", ") || "—")}\n✉️ MX: ${esc((j.mx || []).map((m: string) => m.replace(/^\d+ /, "")).join(", ") || "—")}\n🗂 NS: ${esc((j.ns || []).join(", ") || "—")}`;
    return out;
  }
  if (j.type === "ip") {
    return `📡 <b>IP:</b> ${esc(j.query)} (${esc(j.ipType || "")})\n\n` +
      `${j.flag || "🌍"} Страна: ${esc(j.country)}${j.region ? ", " + esc(j.region) : ""}\n🏙 Город: ${esc(j.city || "—")}\n🏢 Провайдер: ${esc(j.isp || "—")}\n🧩 Организация: ${esc(j.org || "—")}\n🔗 Хост: ${esc(j.domain || "—")}`;
  }
  if (j.type === "email") {
    if (j.needKey) return "🕳 <b>Утечки email</b>\n\nДля проверки нужен бесплатный API-ключ Have I Been Pwned (haveibeenpwned.com → API Key). Получите и пришлите админу — включим.";
    if (j.clean) return `🕳 <b>Email:</b> ${esc(j.query)}\n\n🎉 Утечек не найдено.`;
    let out = `🕳 <b>Email:</b> ${esc(j.query)}\n\n😱 Найден в <b>${j.breaches.length}</b> утечк(ах):\n\n`;
    for (const b of j.breaches.slice(0, 15)) out += `• <b>${esc(b.name)}</b> — ${esc(b.date || "?")} (${b.count ? b.count.toLocaleString("en") : "?"} аккаунтов)\n`;
    out += "\n💡 Смените пароль и включите 2FA.";
    return out;
  }
  return "⚠️ Неизвестный ответ.";
}

// ============ СЕССИИ (Deno KV) ============
async function getSession(chatId: string): Promise<string | null> {
  const r = await kv.get(["session", chatId]);
  return r.value ? String(r.value) : null;
}
async function setSession(chatId: string, mode: string) {
  await kv.set(["session", chatId], mode);
}
async function clearSession(chatId: string) {
  await kv.delete(["session", chatId]);
}

// ============ TELEGRAM WEBHOOK ============
const MAIN_KB = (miniAppUrl: string) => ({
  inline_keyboard: [
    [{ text: "🔍 Ник по соцсетям", callback_data: "mode:nick" }],
    [{ text: "🌐 Домен / сайт", callback_data: "mode:domain" }],
    [{ text: "📡 IP-адрес", callback_data: "mode:ip" }],
    [{ text: "🕳 Утечки email", callback_data: "mode:email" }],
    [{ text: "🖥 Открыть OSINT Mini App", web_app: { url: miniAppUrl } }],
  ],
});

const START_TEXT =
  '👁 <b>OSINT</b> — разведка по открытым данным\n\n' +
  "Инструменты:\n" +
  "🔍 <b>Ник</b> — на каких площадках зарегистрирован username\n" +
  "🌐 <b>Домен</b> — регистратор, даты, DNS-записи\n" +
  "📡 <b>IP</b> — страна, город, провайдер\n" +
  "🕳 <b>Email</b> — проверка по базам утечек\n\n" +
  "Выбирайте кнопку 👇 или откройте Mini App.\n\n" +
  "<i>Только публичные источники. Личные данные людей не ищем.</i>";

async function handleUpdate(update: any, origin: string) {
  const miniAppUrl = `${origin}/`;
  const msg = update.message;
  if (msg && msg.text) {
    const chatId = msg.chat.id;
    const text = msg.text.trim();
    if (text.startsWith("/start")) {
      await clearSession(String(chatId));
      await tg("sendMessage", { chat_id: chatId, text: START_TEXT, parse_mode: "HTML", reply_markup: MAIN_KB(miniAppUrl), disable_web_page_preview: true });
      return;
    }
    const mode = await getSession(String(chatId));
    if (!mode) {
      await tg("sendMessage", { chat_id: chatId, text: "Выберите инструмент 👇", reply_markup: MAIN_KB(miniAppUrl) });
      return;
    }
    await clearSession(String(chatId));
    await tg("sendChatAction", { chat_id: chatId, action: "typing" });
    const j = await runSearch(mode, text);
    await tg("sendMessage", { chat_id: chatId, text: formatResult(j), parse_mode: "HTML", disable_web_page_preview: true, reply_markup: MAIN_KB(miniAppUrl) });
    try { await kv.set(["log", crypto.randomUUID()], { at: new Date().toISOString(), type: mode, query: text.slice(0, 200), user: String(msg.from?.id || "") }); } catch { /* ignore */ }
    return;
  }
  const cb = update.callback_query;
  if (cb) {
    await tg("answerCallbackQuery", { callback_query_id: cb.id });
    const data = cb.data || "";
    if (data.startsWith("mode:") && MODES[data.slice(5)]) {
      const mode = data.slice(5);
      await setSession(String(cb.message.chat.id), mode);
      await tg("editMessageText", {
        chat_id: cb.message.chat.id,
        message_id: cb.message.message_id,
        text: `<b>${MODES[mode].title}</b>\n\n${MODES[mode].hint}\n\n⬅️ /start — меню`,
        parse_mode: "HTML",
      });
    }
  }
}

// ============ MINI APP HTML ============
const HTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>OSINT</title>
<script src="https://telegram.org/js/telegram-web-app.js"><\/script>
<style>
  * { margin:0; padding:0; box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
  :root { --bg:#05070a; --panel:#0b0f14; --line:#1a2330; --green:#00ff9d; --cyan:#00d4ff; --red:#ff3b5c; --amber:#ffb020; --txt:#d7e2ee; --dim:#5b6b7d; }
  body { background:var(--bg); color:var(--txt); font-family:'JetBrains Mono','SF Mono',Menlo,Consolas,monospace; min-height:100vh;
    background-image:radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,255,157,.07), transparent),
      linear-gradient(rgba(0,255,157,.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,157,.025) 1px, transparent 1px);
    background-size:100% 100%,34px 34px,34px 34px; }
  .wrap { max-width:480px; margin:0 auto; padding:20px 16px 40px; }
  .logo { text-align:center; padding:14px 0 4px; }
  .logo .eye { font-size:34px; color:var(--green); text-shadow:0 0 18px rgba(0,255,157,.55); }
  .logo h1 { font-size:30px; letter-spacing:8px; color:var(--green); text-shadow:0 0 22px rgba(0,255,157,.45); margin-top:2px; }
  .logo h1 .cur { animation:blink 1s steps(1) infinite; color:#fff; }
  @keyframes blink { 50% { opacity:0; } }
  .logo p { font-size:11px; color:var(--dim); letter-spacing:2px; margin-top:6px; text-transform:uppercase; }
  .scan { height:1px; margin:14px 0 18px; background:linear-gradient(90deg,transparent,var(--green),transparent); position:relative; }
  .scan::after { content:''; position:absolute; left:-10%; top:-1px; width:12%; height:3px; background:var(--cyan); box-shadow:0 0 12px var(--cyan); animation:sweep 2.4s linear infinite; }
  @keyframes sweep { to { left:104%; } }
  .tabs { display:grid; grid-template-columns:repeat(4,1fr); gap:6px; margin-bottom:14px; }
  .tab { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px 2px; text-align:center; cursor:pointer; transition:.15s; color:var(--dim); font-size:11px; letter-spacing:1px; }
  .tab .ic { font-size:17px; display:block; margin-bottom:4px; }
  .tab.on { border-color:var(--green); color:var(--green); background:rgba(0,255,157,.06); box-shadow:0 0 14px rgba(0,255,157,.12) inset; }
  .bar { display:flex; gap:8px; margin-bottom:16px; }
  .bar input { flex:1; background:var(--panel); border:1px solid var(--line); border-radius:10px; color:var(--txt); padding:13px 14px; font-family:inherit; font-size:14px; outline:none; }
  .bar input:focus { border-color:var(--green); box-shadow:0 0 10px rgba(0,255,157,.15); }
  .bar button { background:var(--green); color:#001a0d; border:none; border-radius:10px; padding:0 20px; font-family:inherit; font-weight:700; font-size:13px; letter-spacing:1px; cursor:pointer; }
  .bar button:active { transform:scale(.96); }
  .bar button:disabled { opacity:.45; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px 16px; margin-bottom:10px; animation:pop .25s ease both; }
  @keyframes pop { from { opacity:0; transform:translateY(6px); } }
  .card .label { font-size:10px; color:var(--dim); letter-spacing:2px; text-transform:uppercase; margin-bottom:6px; }
  .card .big { font-size:16px; color:#fff; word-break:break-all; }
  .row { display:flex; align-items:center; gap:10px; padding:9px 0; border-bottom:1px dashed var(--line); }
  .row:last-child { border-bottom:none; }
  .dot { width:9px; height:9px; border-radius:50%; flex:none; }
  .dot.f { background:var(--green); box-shadow:0 0 8px rgba(0,255,157,.8); }
  .dot.n { background:var(--red); box-shadow:0 0 8px rgba(255,59,92,.6); }
  .dot.u { background:var(--amber); }
  .dot.m { background:var(--cyan); }
  .row a { color:var(--txt); text-decoration:none; flex:1; }
  .row .st { font-size:10px; letter-spacing:1px; color:var(--dim); flex:none; }
  .kv { display:flex; justify-content:space-between; gap:10px; padding:8px 0; border-bottom:1px dashed var(--line); font-size:13px; }
  .kv:last-child { border-bottom:none; }
  .kv .k { color:var(--dim); flex:none; }
  .kv .v { text-align:right; word-break:break-all; color:var(--txt); }
  .note { font-size:12px; color:var(--amber); background:rgba(255,176,32,.07); border:1px solid rgba(255,176,32,.25); border-radius:10px; padding:10px 12px; margin-bottom:10px; line-height:1.5; }
  .ok-note { font-size:13px; color:var(--green); }
  .empty { text-align:center; color:var(--dim); font-size:12px; padding:30px 10px; letter-spacing:1px; line-height:1.8; }
  .foot { text-align:center; color:var(--dim); font-size:10px; letter-spacing:1px; margin-top:18px; line-height:1.7; }
  .breach { padding:9px 0; border-bottom:1px dashed var(--line); font-size:13px; }
  .breach:last-child { border-bottom:none; }
  .breach b { color:var(--red); }
  .breach span { color:var(--dim); font-size:11px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">
    <div class="eye">◉</div>
    <h1>OSINT<span class="cur">_</span></h1>
    <p>разведка по открытым данным</p>
  </div>
  <div class="scan"></div>
  <div class="tabs">
    <div class="tab on" data-t="nick"><span class="ic">🔍</span>НИК</div>
    <div class="tab" data-t="domain"><span class="ic">🌐</span>ДОМЕН</div>
    <div class="tab" data-t="ip"><span class="ic">📡</span>IP</div>
    <div class="tab" data-t="email"><span class="ic">🕳</span>EMAIL</div>
  </div>
  <div class="bar">
    <input id="q" placeholder="введите ник…" autocomplete="off">
    <button id="go" onclick="scan()">СКАНИРОВАТЬ</button>
  </div>
  <div id="out"><div class="empty">:: ожидание команды _<br>введите запрос и нажмите СКАНИРОВАТЬ</div></div>
  <div class="foot">OSINT TERMINAL v2.0 · Deno Deploy<br>только публичные источники · без личных данных людей</div>
</div>
<script>
  var TAB = 'nick';
  var PH = { nick:'введите ник…', domain:'example.com…', ip:'8.8.8.8…', email:'email@…' };
  document.querySelectorAll('.tab').forEach(function(t){
    t.addEventListener('click', function(){
      document.querySelectorAll('.tab').forEach(function(x){ x.classList.remove('on'); });
      t.classList.add('on'); TAB = t.getAttribute('data-t');
      document.getElementById('q').placeholder = PH[TAB];
    });
  });
  document.getElementById('q').addEventListener('keydown', function(e){ if(e.key==='Enter') scan(); });
  if (window.Telegram && Telegram.WebApp) Telegram.WebApp.ready();
  var ST = { found:['f','НАЙДЕН'], not:['n','НЕТ'], unknown:['u','?'], manual:['m','ВРУЧНУЮ'] };
  function scan(){
    var q = document.getElementById('q').value.trim();
    if(!q) return;
    var btn = document.getElementById('go');
    btn.disabled = true; btn.textContent = '…';
    document.getElementById('out').innerHTML = '<div class="empty">:: сканирование ' + escapeHtml(q) + '_</div>';
    fetch('/api', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action: TAB, query: q }) })
      .then(function(r){ return r.json(); }).then(render)
      .catch(function(){ document.getElementById('out').innerHTML = '<div class="note">Ошибка соединения, попробуйте ещё раз.</div>'; })
      .finally(function(){ btn.disabled = false; btn.textContent = 'СКАНИРОВАТЬ'; });
  }
  function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function kv(k, v){ return '<div class="kv"><span class="k">' + k + '</span><span class="v">' + escapeHtml(v || '—') + '</span></div>'; }
  function render(j){
    var o = document.getElementById('out');
    if (j.error) { o.innerHTML = '<div class="note">' + escapeHtml(j.error) + '</div>'; return; }
    if (j.type === 'nick') {
      var h = '<div class="card"><div class="label">Цель</div><div class="big">🔍 ' + escapeHtml(j.query) + '</div></div><div class="card">';
      j.results.forEach(function(r){
        var s = ST[r.status] || ST.unknown;
        h += '<div class="row"><span class="dot ' + s[0] + '"></span><a href="' + r.url + '" target="_blank">' + escapeHtml(r.name) + '</a><span class="st">' + s[1] + '</span></div>';
      });
      o.innerHTML = h + '</div>'; return;
    }
    if (j.type === 'domain') {
      var h2 = '<div class="card"><div class="label">Домен</div><div class="big">🌐 ' + escapeHtml(j.query) + '</div></div>';
      if (j.note) h2 += '<div class="note">' + escapeHtml(j.note) + '</div>';
      h2 += '<div class="card">' + kv('Регистратор', j.registrar) + kv('Создан', j.created) + kv('Истекает', j.expires)
        + kv('A-записи', (j.a||[]).join(', ') || '—')
        + kv('MX', (j.mx||[]).map(function(m){return m.replace(/^\\d+ /,'');}).join(', ') || '—')
        + kv('NS', (j.ns||[]).join(', ') || '—') + '</div>';
      o.innerHTML = h2; return;
    }
    if (j.type === 'ip') {
      o.innerHTML = '<div class="card"><div class="label">IP-адрес</div><div class="big">📡 ' + escapeHtml(j.query) + ' (' + escapeHtml(j.ipType||'') + ')</div></div>'
        + '<div class="card">' + kv('Страна', j.flag + ' ' + j.country + (j.region ? ' / ' + j.region : ''))
        + kv('Город', j.city) + kv('Провайдер', j.isp) + kv('Организация', j.org) + kv('Домен провайдера', j.domain) + '</div>';
      return;
    }
    if (j.type === 'email') {
      if (j.needKey) { o.innerHTML = '<div class="card"><div class="label">Email</div><div class="big">🕳 ' + escapeHtml(j.query) + '</div></div><div class="note">Проверка утечек подключается после получения бесплатного ключа Have I Been Pwned.</div>'; return; }
      if (j.clean) { o.innerHTML = '<div class="card"><div class="big ok-note">🎉 Утечек не найдено</div></div>'; return; }
      var h3 = '<div class="card"><div class="label">Email</div><div class="big">🕳 ' + escapeHtml(j.query) + '</div></div><div class="card">';
      j.breaches.forEach(function(b){ h3 += '<div class="breach"><b>' + escapeHtml(b.name) + '</b> — ' + escapeHtml(b.date||'?') + ' <span>(' + (b.count ? b.count.toLocaleString('en') : '?') + ' аккаунтов)</span></div>'; });
      h3 += '</div><div class="note">Смените пароль на этом email и включите 2FA.</div>';
      o.innerHTML = h3; return;
    }
    o.innerHTML = '<div class="note">Неизвестный ответ сервера.</div>';
  }
<\/script>
</body>
</html>`;

// ============ РОУТЕР ============
Deno.serve(async (req) => {
  const url = new URL(req.url);
  const origin = url.origin;

  if (url.pathname === "/hook") {
    if (url.searchParams.get("secret") !== HOOK_SECRET) {
      return new Response(JSON.stringify({ ok: false, error: "forbidden" }), { status: 403 });
    }
    if (req.method !== "POST") return new Response(JSON.stringify({ ok: true }), { status: 200 });
    let update: any = {};
    try { update = await req.json(); } catch { /* ignore */ }
    try { await handleUpdate(update, origin); } catch (e) { console.error("update error:", e); }
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }

  if (url.pathname === "/api") {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" } });
    let data: any = {};
    try { data = await req.json(); } catch { /* ignore */ }
    const { action, query } = data || {};
    let result: any;
    try { result = await runSearch(String(action || ""), String(query || "")); }
    catch { result = { error: "Внутренняя ошибка" }; }
    return new Response(JSON.stringify({ ok: !result?.error, ...result }), {
      status: 200,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }

  return new Response(HTML, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Access-Control-Allow-Origin": "*" } });
});
