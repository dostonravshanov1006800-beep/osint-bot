// OSINT bot — GitHub Actions, polling getUpdates. Node 20+.
// Работает $0: публичный репозиторий = бесплатные минуты Actions.
const TOKEN = process.env.OSINT_BOT_TOKEN || "";
const HIBP_KEY = process.env.HIBP_API_KEY || "";
const API = `https://api.telegram.org/bot${TOKEN}`;
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
const MINI_APP = process.env.MINI_APP_URL || "https://dostonravshanov1006800-beep.github.io/osint-bot/";
const RUN_MS = 270000; // живём 4.5 мин, потом следующий cron-запуск

const tg = (method, payload) =>
  fetch(`${API}/${method}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
    .then((r) => r.json()).catch((e) => { console.error(method, e.message); return null; });

const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

// ---------- поиск ----------
async function status(url, timeoutMs = 9000) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA }, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
    return r.status;
  } catch { return -1; }
}
async function statusAndBody(url, timeoutMs = 9000) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA }, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
    return { code: r.status, body: (await r.text()).slice(0, 4000) };
  } catch { return { code: -1, body: "" }; }
}
function flagFromCode(code) {
  return [...(code || "")].map((c) => String.fromCodePoint(127397 + c.toUpperCase().charCodeAt(0))).join("");
}

async function searchNick(raw) {
  const nick = raw.replace(/^@/, "").replace(/[^a-zA-Z0-9._-]/g, "");
  if (!nick) return "⚠️ Некорректный ник.";
  const checks = [
    ["GitHub", `https://github.com/${nick}`, async () => { const c = await status(`https://api.github.com/users/${nick}`); return c === 200 ? "found" : c === 404 ? "not" : "unknown"; }],
    ["Telegram", `https://t.me/${nick}`, async () => (await status(`https://t.me/${nick}`)) === 200 ? "found" : "not"],
    ["Reddit", `https://reddit.com/user/${nick}`, async () => { const c = await status(`https://www.reddit.com/user/${nick}/about.json`); return c === 403 || c === 404 ? "not" : c === 200 ? "found" : "unknown"; }],
    ["GitLab", `https://gitlab.com/${nick}`, async () => (await status(`https://gitlab.com/${nick}`)) === 200 ? "found" : "not"],
    ["Steam", `https://steamcommunity.com/id/${nick}`, async () => { const r = await statusAndBody(`https://steamcommunity.com/id/${nick}`); if (r.code === -1) return "unknown"; return r.body.includes("could not be found") || r.body.includes("The specified profile") ? "not" : "found"; }],
    ["YouTube", `https://youtube.com/@${nick}`, async () => (await status(`https://www.youtube.com/@${nick}`)) === 200 ? "found" : "not"],
    ["TikTok", `https://tiktok.com/@${nick}`, async () => { const c = await status(`https://www.tiktok.com/@${nick}`); return c === 200 ? "found" : c === 404 ? "not" : "unknown"; }],
  ];
  const results = await Promise.all(checks.map(async ([name, url, fn]) => ({ name, url, r: await fn() })));
  let out = `🔍 <b>Ник:</b> ${esc(nick)}\n\n`;
  for (const res of results) {
    if (res.r === "found") out += `✅ ${esc(res.name)} — <a href="${res.url}">найден</a>\n`;
    else if (res.r === "not") out += `❌ ${esc(res.name)} — нет\n`;
    else out += `⚠️ ${esc(res.name)} — <a href="${res.url}">проверить вручную</a>\n`;
  }
  out += `\n📎 <b>Вручную (закрыты для ботов):</b>\n` +
    `<a href="https://instagram.com/${nick}">Instagram</a> · <a href="https://x.com/${nick}">X</a> · <a href="https://vk.com/${nick}">VK</a> · <a href="https://facebook.com/${nick}">Facebook</a> · <a href="https://pinterest.com/${nick}">Pinterest</a>`;
  return out;
}

async function searchDomain(raw) {
  const dom = raw.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/[^a-z0-9.\-]/g, "");
  if (!dom.includes(".")) return "⚠️ Это не похоже на домен. Пример: example.com";
  let out = `🌐 <b>Домен:</b> ${esc(dom)}\n\n`;
  let rdap = null;
  for (const u of [`https://rdap.org/domain/${dom}`, `https://rdap.net/domain/${dom}`]) {
    try {
      const r = await fetch(u, { headers: { "User-Agent": UA, "Accept": "application/rdap+json, application/json" }, redirect: "follow", signal: AbortSignal.timeout(9000) });
      if (r.ok) { rdap = await r.json(); if (rdap) break; }
    } catch { /* next */ }
  }
  if (rdap) {
    const ev = rdap.events || [];
    const reg = ev.find((e) => e.eventAction === "registration")?.eventDate?.slice(0, 10) || "—";
    const exp = ev.find((e) => e.eventAction === "expiration")?.eventDate?.slice(0, 10) || "—";
    let registrar = "—";
    const ent = (rdap.entities || []).find((e) => (e.roles || []).includes("registrar"));
    const fn = ent?.vcardArray?.[1]?.find((v) => v[0] === "fn");
    if (fn) registrar = fn[3];
    out += `🏢 Регистратор: ${esc(registrar)}\n📅 Создан: ${esc(reg)}\n⏳ Истекает: ${esc(exp)}\n\n`;
  } else out += "⚠️ RDAP: нет данных\n\n";
  const dns = async (type) => {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${dom}&type=${type}`, { signal: AbortSignal.timeout(9000) });
      const j = await r.json();
      return (j.Answer || []).map((a) => a.data);
    } catch { return []; }
  };
  const [a, mx, ns] = await Promise.all([dns("A"), dns("MX"), dns("NS")]);
  out += `📍 A: ${esc(a.join(", ") || "—")}\n✉️ MX: ${esc(mx.map((m) => m.replace(/^\d+ /, "")).join(", ") || "—")}\n🗂 NS: ${esc(ns.join(", ") || "—")}`;
  return out;
}

async function searchIp(raw) {
  const ip = raw.trim();
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return "⚠️ Нужен IPv4-адрес, например 8.8.8.8";
  let j = null, src = "who";
  try {
    const r = await fetch(`https://ipwho.is/${ip}`, { signal: AbortSignal.timeout(8000) });
    const t = await r.json();
    if (t && t.success) j = t;
  } catch { /* next */ }
  if (!j) {
    try {
      const r2 = await fetch(`https://ipinfo.io/${ip}/json`, { signal: AbortSignal.timeout(8000) });
      const t2 = await r2.json();
      if (t2 && t2.ip) { j = t2; src = "info"; }
    } catch { /* next */ }
  }
  if (!j) return "⚠️ Сервис IP-информации недоступен, попробуйте позже.";
  if (src === "who") {
    const c = j.connection || {};
    return `📡 <b>IP:</b> ${esc(j.ip)} (${esc(j.type)})\n\n` +
      `${j.flag?.emoji || flagFromCode(j.country_code)} Страна: ${esc(j.country)}${j.region ? ", " + esc(j.region) : ""}\n🏙 Город: ${esc(j.city || "—")}\n🏢 Провайдер: ${esc(c.isp || "—")}\n🧩 Организация: ${esc(c.org || "—")}\n🔗 Хост: ${esc(c.domain || "—")}`;
  }
  return `📡 <b>IP:</b> ${esc(j.ip)} (IPv4)\n\n` +
    `${flagFromCode(j.country)} Страна: ${esc(j.country || "—")}${j.region ? ", " + esc(j.region) : ""}\n🏙 Город: ${esc(j.city || "—")}\n🧩 Организация: ${esc(j.org || "—")}\n🔗 Хост: ${esc(j.hostname || "—")}`;
}

async function searchEmail(raw) {
  const email = raw.trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return "⚠️ Некорректный email.";
  if (!HIBP_KEY) return "🕳 <b>Утечки email</b>\n\nДля проверки нужен бесплатный ключ Have I Been Pwned (haveibeenpwned.com → API Key). Владелец добавит его в секреты репозитория (HIBP_API_KEY) — и проверка заработает.";
  try {
    const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers: { "hibp-api-key": HIBP_KEY, "User-Agent": "OSINT-Bot" },
      signal: AbortSignal.timeout(12000),
    });
    if (r.status === 404) return `🕳 <b>Email:</b> ${esc(email)}\n\n🎉 Утечек не найдено.`;
    if (!r.ok) return `⚠️ HIBP ответил ошибкой (${r.status}).${r.status === 401 ? " Ключ неверный." : ""}`;
    const breaches = await r.json();
    let out = `🕳 <b>Email:</b> ${esc(email)}\n\n😱 Найден в <b>${breaches.length}</b> утечк(ах):\n\n`;
    for (const b of breaches.slice(0, 15)) out += `• <b>${esc(b.Title)}</b> — ${esc(b.BreachDate || "?")} (${b.PwnCount ? b.PwnCount.toLocaleString("en") : "?"} аккаунтов)\n`;
    out += "\n💡 Смените пароль и включите 2FA.";
    return out;
  } catch { return "⚠️ Сервис HIBP недоступен, попробуйте позже."; }
}

// авто-определение типа запроса — бот без сессий и базы
function detect(q) {
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) return searchEmail(q);
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q)) return searchIp(q);
  if (/^(@|https?:\/\/)/.test(q) || /^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(\/.*)?$/i.test(q)) return searchDomain(q);
  return searchNick(q);
}

const MENU_KB = {
  inline_keyboard: [
    [{ text: "🔍 Ник по соцсетям", callback_data: "mode:nick" }],
    [{ text: "🌐 Домен / сайт", callback_data: "mode:domain" }],
    [{ text: "📡 IP-адрес", callback_data: "mode:ip" }],
    [{ text: "🕳 Утечки email", callback_data: "mode:email" }],
    [{ text: "🖥 Открыть OSINT Mini App", web_app: { url: MINI_APP } }],
  ],
};

const START_TEXT =
  '🛡 <b>OSINT Check</b> — проверка по открытым данным\n\n' +
  "Просто пришлите запрос, я сам определю тип:\n" +
  "🔍 <code>durov</code> или <code>@durov</code> — свободен ли ник на площадках\n" +
  "🌐 <code>example.com</code> — домен (регистратор, даты, DNS)\n" +
  "📡 <code>8.8.8.8</code> — IP-адрес (страна, провайдер)\n" +
  "🕳 <code>mail@example.com</code> — не утёк ли ваш email\n\n" +
  "Или откройте Mini App 👇\n\n" +
  "<i>Инструмент самопроверки: свои аккаунты, домены и утечки паролей.\nТолько публичные источники. Слежка и персональные данные людей не поддерживаются.</i>";

const HINTS = {
  "mode:nick": "🔍 Пришлите ник, например <code>durov</code> — проверю по 7 соцсетям.\n\n⬅️ /start — меню",
  "mode:domain": "🌐 Пришлите домен, например <code>example.com</code>\n\n⬅️ /start — меню",
  "mode:ip": "📡 Пришлите IP-адрес, например <code>8.8.8.8</code>\n\n⬅️ /start — меню",
  "mode:email": "🕳 Пришлите email — проверю по базам утечек.\n\n⬅️ /start — меню",
};

async function handleUpdate(u) {
  try {
    const msg = u.message;
    if (msg && msg.text) {
      const chatId = msg.chat.id;
      const text = msg.text.trim();
      if (text.startsWith("/start")) {
        await tg("sendMessage", { chat_id: chatId, text: START_TEXT, parse_mode: "HTML", reply_markup: MENU_KB, disable_web_page_preview: true });
        return;
      }
      if (text.startsWith("/")) return; // прочие команды игнорируем
      await tg("sendChatAction", { chat_id: chatId, action: "typing" });
      const result = await detect(text);
      await tg("sendMessage", { chat_id: chatId, text: result, parse_mode: "HTML", disable_web_page_preview: true, reply_markup: MENU_KB });
      return;
    }
    const cb = u.callback_query;
    if (cb) {
      await tg("answerCallbackQuery", { callback_query_id: cb.id });
      const hint = HINTS[cb.data];
      if (hint) {
        await tg("editMessageText", { chat_id: cb.message.chat.id, message_id: cb.message.message_id, text: hint, parse_mode: "HTML" });
      }
    }
  } catch (e) { console.error("handle:", e.message); }
}

async function dispatchReplacement() {
  // эстафета: запускаем себе замену, чтобы очередь никогда не отпускалась (cancel-in-progress сменит нас)
  const ghToken = process.env.GITHUB_TOKEN;
  if (!ghToken) return;
  try {
    const r = await fetch("https://api.github.com/repos/dostonravshanov1006800-beep/osint-bot/actions/workflows/bot.yml/dispatches", {
      method: "POST",
      headers: { "Authorization": `token ${ghToken}`, "Accept": "application/vnd.github+json" },
      body: JSON.stringify({ ref: "main" }),
    });
    console.log("replacement dispatched:", r.status);
  } catch (e) { console.error("dispatch err:", e.message); }
}

async function main() {
  if (!TOKEN) { console.error("Нет OSINT_BOT_TOKEN"); return; }
  console.log(`OSINT bot started ${new Date().toISOString()}`);
  const t0 = Date.now();
  let offset = 0;
  while (Date.now() - t0 < RUN_MS) {
    let updates = [];
    try {
      const r = await fetch(`${API}/getUpdates?offset=${offset}&timeout=25&allowed_updates=["message","callback_query"]`);
      const j = await r.json();
      if (!j.ok) {
        if (j.error_code === 409) { await new Promise((r2) => setTimeout(r2, 2000)); continue; } // очередь занята старым воркером — держим осаду
        console.error("getUpdates:", j.description); break;
      }
      updates = j.result;
    } catch (e) { console.error("poll:", e.message); break; }
    for (const u of updates) {
      offset = u.update_id + 1;
      await handleUpdate(u);
    }
    if (updates.length) console.log(`processed ${updates.length}, offset=${offset}`);
  }
  console.log(`OSINT bot finished, ${(Date.now() - t0) / 1000 | 0}s`);
}
main().then(() => dispatchReplacement());
