(() => {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const STORE_KEY = 'void.conversations.v1';
  const TOKEN_KEY = 'void.token';
  const SAFE_LINK_HOSTS = new Set(['report.cybertip.org', 'report.iwf.org.uk']);

  const el = {
    sidebar: $('#sidebar'), history: $('#history'), messages: $('#messages'),
    form: $('#composer'), input: $('#input'), send: $('#send'), search: $('#search-toggle'),
    title: $('#chat-title'), newChat: $('#new-chat'), menu: $('#menu'),
    pillTor: $('#pill-tor'), pillLlm: $('#pill-llm'),
    dialog: $('#token-dialog'), tokenInput: $('#token-input'), tokenBtn: $('#token-btn'),
    banner: $('#setup-banner'), bannerText: $('#banner-text'), llmBtn: $('#llm-btn'),
    llmDialog: $('#llm-dialog'), llmForm: $('#llm-form'), llmProvider: $('#llm-provider'),
    llmModel: $('#llm-model'), llmUrl: $('#llm-url'), llmKey: $('#llm-key'),
    llmKeyState: $('#llm-key-state'), llmMsg: $('#llm-msg'), llmLocked: $('#llm-locked'),
    llmSave: $('#llm-save'), llmTest: $('#llm-test'), llmClose: $('#llm-close'),
    llmRemove: $('#llm-remove'), llmFields: $('#llm-fields'),
  };

  const state = { convs: [], activeId: null, abort: null, streaming: false };

  /* ------------------------------------------------------------ storage */
  const load = () => {
    try { state.convs = JSON.parse(localStorage.getItem(STORE_KEY) || '[]'); } catch { state.convs = []; }
  };
  const save = () => {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(state.convs.slice(0, 50))); } catch { /* quota */ }
  };
  const getToken = () => { try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; } };
  const authHeaders = () => {
    const t = getToken();
    return t ? { Authorization: `Bearer ${t}` } : {};
  };
  const active = () => state.convs.find((c) => c.id === state.activeId) || null;

  /* ------------------------------------------------------------ safe markdown */
  const esc = (s) => s.replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const inline = (raw) => {
    let s = esc(raw);
    s = s.replace(/\[([^\]]+)\]\((https:\/\/[^)\s]+)\)/g, (m, label, url) => {
      try {
        const u = new URL(url.replace(/&amp;/g, '&'));
        if (SAFE_LINK_HOSTS.has(u.hostname)) {
          return `<a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
        }
      } catch { /* fall through */ }
      return `${label} (${url})`; // never create clickable links to arbitrary hosts
    });
    s = s.replace(/`([^`\n]+)`/g, '<code>$1</code>');
    s = s.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[^*\w])\*([^*\n]+)\*(?!\*)/g, '$1<em>$2</em>');
    s = s.replace(/\[(\d{1,2})\]/g, '<sup class="cite" data-n="$1">[$1]</sup>');
    return s;
  };

  const md = (src) => {
    const out = [];
    let list = null, inCode = false, code = [], para = [];
    const flushPara = () => {
      if (para.length) { out.push(`<p>${para.map(inline).join('<br>')}</p>`); para = []; }
    };
    const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
    const openList = (kind) => {
      if (list !== kind) { closeList(); out.push(`<${kind}>`); list = kind; }
    };
    for (const line of src.split('\n')) {
      if (/^```/.test(line)) {
        if (inCode) { out.push(`<pre><code>${esc(code.join('\n'))}</code></pre>`); code = []; inCode = false; }
        else { flushPara(); closeList(); inCode = true; }
        continue;
      }
      if (inCode) { code.push(line); continue; }
      let m;
      if ((m = line.match(/^(#{1,4})\s+(.*)$/))) {
        flushPara(); closeList();
        const lvl = Math.min(m[1].length + 1, 5);
        out.push(`<h${lvl}>${inline(m[2])}</h${lvl}>`);
      } else if ((m = line.match(/^\s*[-*•]\s+(.*)$/))) {
        flushPara(); openList('ul'); out.push(`<li>${inline(m[1])}</li>`);
      } else if ((m = line.match(/^\s*\d+[.)]\s+(.*)$/))) {
        flushPara(); openList('ol'); out.push(`<li>${inline(m[1])}</li>`);
      } else if (!line.trim()) {
        flushPara(); closeList();
      } else {
        closeList(); para.push(line);
      }
    }
    if (inCode) out.push(`<pre><code>${esc(code.join('\n'))}</code></pre>`);
    flushPara(); closeList();
    return out.join('');
  };

  /* ------------------------------------------------------------ rendering */
  const node = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  const paintSteps = (wrap, m, live) => {
    const box = wrap.querySelector('.steps');
    box.replaceChildren();
    if (!m.steps || !m.steps.length) return;
    const list = node('ul', 'step-list');
    m.steps.forEach((s, i) => {
      const li = node('li', s.step === 'warn' ? 'warn' : '', s.message);
      if (live && i === m.steps.length - 1) li.classList.add('active');
      list.append(li);
    });
    if (live) { box.append(list); return; }
    const d = node('details', 'steps-done');
    d.append(node('summary', '', `Investigation steps (${m.steps.length})`), list);
    box.append(d);
  };

  const paintSources = (wrap, m) => {
    const box = wrap.querySelector('.sources');
    box.replaceChildren();
    if (!m.sources || !m.sources.items.length) return;
    const card = node('details', 'src-card');
    card.open = true;
    card.append(node('summary', '', `Sources (${m.sources.items.length})`));
    for (const s of m.sources.items) {
      const row = node('div', 'src');
      row.dataset.n = s.n;
      const info = node('div', 'src-info');
      info.append(node('div', 'src-title', s.title || '(untitled)'), node('code', 'src-url', s.display));
      if (!s.fetched) info.append(node('span', 'tag', 'snippet only'));
      const copy = node('button', 'icon-btn small', 'Copy');
      copy.type = 'button';
      copy.title = 'Copy the raw URL (open only in Tor Browser, never a normal browser)';
      copy.addEventListener('click', () => navigator.clipboard && navigator.clipboard.writeText(s.url));
      row.append(node('span', 'src-n', String(s.n)), info, copy);
      card.append(row);
    }
    if (m.sources.more) card.append(node('div', 'src-more', `${m.sources.more} more result(s) found but not read.`));
    box.append(card);
  };

  const paintContent = (wrap, m) => {
    wrap.querySelector('.content').innerHTML = md(m.content || '');
    const err = wrap.querySelector('.error');
    err.hidden = !m.error;
    err.textContent = m.error || '';
  };

  const paintActions = (wrap, m) => {
    const box = wrap.querySelector('.actions');
    box.replaceChildren();
    if (!m.content) return;
    const copy = node('button', 'icon-btn small', 'Copy answer');
    copy.type = 'button';
    copy.addEventListener('click', () => {
      if (navigator.clipboard) navigator.clipboard.writeText(m.content);
      copy.textContent = 'Copied';
      setTimeout(() => { copy.textContent = 'Copy answer'; }, 1200);
    });
    box.append(copy);
    if (m.model) box.append(node('span', 'model-tag', `Answered by ${m.model}`));
  };

  const renderMessage = (m) => {
    const wrap = node('article', `msg ${m.role}`);
    if (m.role === 'user') {
      wrap.append(node('div', 'bubble', m.content));
      return wrap;
    }
    const avatar = node('div', 'avatar', 'V');
    avatar.setAttribute('aria-hidden', 'true');
    const body = node('div', 'body');
    const err = node('div', 'error');
    err.hidden = true;
    body.append(node('div', 'steps'), node('div', 'sources'), node('div', 'content prose'), err, node('div', 'actions'));
    wrap.append(avatar, body);
    paintSteps(wrap, m, false);
    paintSources(wrap, m);
    paintContent(wrap, m);
    paintActions(wrap, m);
    return wrap;
  };

  const EXAMPLES = [
    ['Brand exposure', 'Any recent dark web mentions of <your company name>?'],
    ['Credential leaks', 'Is there chatter about leaked credentials for <yourdomain.com>?'],
    ['Ransomware activity', 'What are ransomware groups saying about the healthcare sector?'],
    ['Threat actor profile', 'Summarise what is known about <threat actor name>.'],
  ];

  const renderMessages = () => {
    const conv = active();
    el.messages.replaceChildren();
    el.title.textContent = conv ? conv.title : 'New investigation';
    if (!conv || !conv.messages.length) {
      const hero = node('div', 'hero');
      const logo = document.createElement('img');
      logo.src = '/static/void-logo.png'; logo.alt = 'Void logo'; logo.width = 96; logo.height = 96;
      hero.append(logo, node('h2', '', 'What should we look into?'),
        node('p', '', 'Void searches many dark-web engines through Tor and writes a cited report. Replace <placeholders> with your own terms.'),
        node('p', 'byline', 'By Aniket Misra'));
      const chips = node('div', 'chips');
      for (const [label, prompt] of EXAMPLES) {
        const b = node('button', 'chip', label);
        b.type = 'button';
        b.append(node('small', '', prompt));
        b.addEventListener('click', () => { el.input.value = prompt; autosize(); el.input.focus(); });
        chips.append(b);
      }
      hero.append(chips);
      el.messages.append(hero);
      return;
    }
    const thread = node('div', 'thread');
    for (const m of conv.messages) thread.append(renderMessage(m));
    el.messages.append(thread);
    el.messages.scrollTop = el.messages.scrollHeight;
  };

  const renderSidebar = () => {
    el.history.replaceChildren();
    const sorted = [...state.convs].sort((a, b) => b.updated - a.updated);
    if (!sorted.length) { el.history.append(node('div', 'empty', 'No conversations yet.')); return; }
    for (const c of sorted) {
      const item = node('div', `item${c.id === state.activeId ? ' active' : ''}`);
      const open = node('button', 'open', c.title);
      open.type = 'button';
      open.addEventListener('click', () => { if (!state.streaming) { state.activeId = c.id; renderAll(); closeSidebar(); } });
      const del = node('button', 'del', '×');
      del.type = 'button'; del.title = 'Delete conversation'; del.setAttribute('aria-label', `Delete ${c.title}`);
      del.addEventListener('click', () => {
        if (state.streaming) return;
        state.convs = state.convs.filter((x) => x.id !== c.id);
        if (state.activeId === c.id) state.activeId = null;
        save(); renderAll();
      });
      item.append(open, del);
      el.history.append(item);
    }
  };

  const renderAll = () => { renderSidebar(); renderMessages(); };
  const closeSidebar = () => el.sidebar.classList.remove('open');

  /* ------------------------------------------------------------ chat */
  const newConv = () => {
    const c = { id: crypto.randomUUID(), title: 'New investigation', updated: Date.now(), messages: [] };
    state.convs.unshift(c);
    state.activeId = c.id;
    return c;
  };

  const setStreaming = (on) => {
    state.streaming = on;
    el.send.classList.toggle('stop', on);
    el.send.textContent = on ? '■' : '↑';
    el.send.setAttribute('aria-label', on ? 'Stop' : 'Send');
    el.input.disabled = on;
  };

  const readSSE = async (body, onEvent) => {
    const reader = body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const raw = buf.slice(0, i);
        buf = buf.slice(i + 2);
        let event = 'message', data = '';
        for (const line of raw.split('\n')) {
          if (line.startsWith('event:')) event = line.slice(6).trim();
          else if (line.startsWith('data:')) data += line.slice(5).trim();
        }
        if (data) { try { onEvent(event, JSON.parse(data)); } catch { /* ignore malformed frame */ } }
      }
    }
  };

  const askToken = () => new Promise((resolve) => {
    el.tokenInput.value = '';
    el.dialog.returnValue = '';
    el.dialog.addEventListener('close', () => {
      const ok = el.dialog.returnValue === 'ok' && el.tokenInput.value.trim();
      if (ok) { try { localStorage.setItem(TOKEN_KEY, el.tokenInput.value.trim()); } catch { /* ignore */ } }
      resolve(Boolean(ok));
    }, { once: true });
    el.dialog.showModal();
  });

  const send = async (raw) => {
    const text = raw.trim();
    if (!text || state.streaming) return;
    const conv = active() || newConv();
    const history = conv.messages.filter((m) => m.content && !m.error)
      .slice(-10).map(({ role, content }) => ({ role, content }));
    conv.messages.push({ role: 'user', content: text });
    if (conv.messages.length === 1) conv.title = text.slice(0, 48);
    const reply = { role: 'assistant', content: '', steps: [], sources: null, error: '' };
    conv.messages.push(reply);
    conv.updated = Date.now();
    renderAll();
    const wrap = el.messages.querySelector('.thread').lastElementChild;
    wrap.classList.add('streaming');
    const scroll = () => { el.messages.scrollTop = el.messages.scrollHeight; };

    let pending = false;
    const schedulePaint = () => {
      if (pending) return;
      pending = true;
      requestAnimationFrame(() => { pending = false; paintContent(wrap, reply); scroll(); });
    };

    state.abort = new AbortController();
    setStreaming(true);
    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ message: text, history, search: el.search.checked }),
        signal: state.abort.signal,
      });
      if (res.status === 401) {
        reply.error = 'This server requires an access token. Enter it, then resend your message.';
        await askToken();
      } else if (!res.ok) {
        const info = await res.json().catch(() => ({}));
        reply.error = typeof info.detail === 'string' ? info.detail : `Request rejected (HTTP ${res.status}).`;
      } else {
        await readSSE(res.body, (event, data) => {
          if (event === 'status') { reply.steps.push(data); paintSteps(wrap, reply, true); }
          else if (event === 'sources') { reply.sources = data; paintSources(wrap, reply); }
          else if (event === 'token') { reply.content += data.text; schedulePaint(); }
          else if (event === 'error') { reply.error = data.message; }
          else if (event === 'done') { reply.model = data.model || ''; }
        });
      }
    } catch (e) {
      if (e.name === 'AbortError') reply.content += reply.content ? '\n\n*(stopped)*' : '*(stopped)*';
      else reply.error = 'Connection lost. Is the server running?';
    } finally {
      state.abort = null;
      setStreaming(false);
      wrap.classList.remove('streaming');
      paintSteps(wrap, reply, false);
      paintContent(wrap, reply);
      paintActions(wrap, reply);
      conv.updated = Date.now();
      save();
      renderSidebar();
      el.input.focus();
    }
  };

  /* ------------------------------------------------------------ status pills */
  const setPill = (pill, cls, label) => { pill.className = `pill ${cls}`; pill.textContent = label; };
  let pollTimer = null;
  const pollStatus = async () => {
    clearTimeout(pollTimer);
    let delay = 30000;
    try {
      const res = await fetch('/api/status', { headers: authHeaders() });
      if (res.status === 401) {
        setPill(el.pillTor, 'warn', 'Locked'); setPill(el.pillLlm, 'warn', 'Token needed');
        el.banner.hidden = true; return;
      }
      if (res.status === 403) {
        setPill(el.pillTor, 'bad', 'Blocked'); setPill(el.pillLlm, 'bad', 'Host not allowed');
        el.banner.hidden = true; return;
      }
      const s = await res.json();
      const starting = !s.tor && s.tor_progress !== null && s.tor_progress !== undefined && !s.tor_error;
      if (s.tor) setPill(el.pillTor, 'ok', 'Tor connected');
      else if (starting) setPill(el.pillTor, 'warn', `Tor starting… ${s.tor_progress}%`);
      else setPill(el.pillTor, 'bad', 'Tor offline');
      el.banner.hidden = !s.tor_error;
      el.bannerText.textContent = s.tor_error || '';
      if (!s.tor && !s.tor_error) delay = 3000; // follow Tor's start-up progress closely
      const states = {
        ready: ['ok', s.label],
        needs_setup: ['warn', 'Add API key'],
        offline: ['bad', `${s.label} offline`],
        pulling: ['warn', `Pulling ${s.model}…`],
      };
      const [cls, label] = states[s.llm_state] || ['bad', 'AI unavailable'];
      setPill(el.pillLlm, cls, label);
    } catch {
      setPill(el.pillTor, 'bad', 'Server offline'); setPill(el.pillLlm, 'bad', 'Server offline');
    } finally {
      pollTimer = setTimeout(pollStatus, delay);
    }
  };

  /* ------------------------------------------------------------ AI model settings */
  const llm = { providers: [], current: null };
  const providerById = (id) => llm.providers.find((p) => p.id === id);

  const setMsg = (text, cls = '') => { el.llmMsg.textContent = text; el.llmMsg.className = `hint ${cls}`.trim(); };
  const jsonHeaders = () => ({ 'Content-Type': 'application/json', ...authHeaders() });

  const loadSettings = async () => {
    const res = await fetch('/api/settings', { headers: authHeaders() });
    if (res.status === 401) return (await askToken()) ? loadSettings() : false;
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    llm.providers = data.providers;
    llm.current = data.current;
    return true;
  };

  const keyState = (text) => { el.llmKeyState.textContent = text; };

  const fillForm = (providerId) => {
    const p = providerById(providerId);
    const cur = llm.current;
    const same = cur.provider === providerId;
    el.llmProvider.value = providerId;
    el.llmModel.value = same ? cur.model : (p.default_model || '');
    el.llmModel.placeholder = p.model_hint || 'model name';
    el.llmUrl.value = same ? cur.base_url : p.base_url;
    el.llmKey.value = '';
    el.llmKey.placeholder = p.needs_key ? 'Paste your API key' : 'Not needed for local servers';
    if (same && cur.has_key) keyState(`A key is saved (${cur.key_hint}). Leave this blank to keep it.`);
    else keyState(p.needs_key ? 'No key saved for this provider.' : '');
    el.llmRemove.hidden = !(same && cur.has_key) || !cur.can_edit;
    const builtin = p.kind === 'builtin';
    el.llmFields.hidden = builtin;
    el.llmTest.hidden = builtin;
  };

  const openSettings = async () => {
    setMsg('');
    try {
      if (!(await loadSettings())) return;
    } catch (e) {
      window.alert(`Could not load AI settings (${e.message}).`);
      return;
    }
    el.llmProvider.replaceChildren(...llm.providers.map((p) => {
      const o = document.createElement('option');
      o.value = p.id; o.textContent = p.label;
      return o;
    }));
    fillForm(llm.current.provider);
    const locked = !llm.current.can_edit;
    for (const f of [el.llmProvider, el.llmModel, el.llmUrl, el.llmKey, el.llmSave, el.llmTest]) f.disabled = locked;
    el.llmLocked.hidden = !locked;
    if (!el.llmDialog.open) el.llmDialog.showModal();
  };

  const putSettings = async (body) => {
    const res = await fetch('/api/settings', { method: 'PUT', headers: jsonHeaders(), body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setMsg(typeof data.detail === 'string' ? data.detail : 'Could not save these settings.', 'bad');
      return null;
    }
    llm.current = data;
    fillForm(data.provider);
    pollStatus();
    return data;
  };

  const saveSettings = async (andTest) => {
    setMsg('Saving…');
    const saved = await putSettings({
      provider: el.llmProvider.value,
      model: el.llmModel.value.trim(),
      base_url: el.llmUrl.value.trim(),
      api_key: el.llmKey.value.trim() || null,
    });
    if (!saved) return;
    if (!andTest) { setMsg('Saved. You can start asking questions.', 'ok'); return; }
    setMsg('Saved. Testing the connection…');
    try {
      const res = await fetch('/api/settings/test', { method: 'POST', headers: authHeaders() });
      const r = await res.json();
      setMsg(r.message || 'No response.', r.ok ? 'ok' : 'bad');
    } catch {
      setMsg('Could not run the connection test.', 'bad');
    }
  };

  el.llmProvider.addEventListener('change', () => { setMsg(''); fillForm(el.llmProvider.value); });
  el.llmUrl.addEventListener('input', () => {
    const cur = llm.current;
    if (cur && cur.has_key && cur.provider === el.llmProvider.value && el.llmUrl.value.trim().replace(/\/+$/, '') !== cur.base_url) {
      keyState('Changing the URL removes the saved key: paste the key again.');
    }
  });
  el.llmForm.addEventListener('submit', (e) => { e.preventDefault(); saveSettings(false); });
  el.llmTest.addEventListener('click', () => saveSettings(true));
  el.llmClose.addEventListener('click', () => el.llmDialog.close());
  el.llmRemove.addEventListener('click', async () => {
    const cur = llm.current;
    setMsg('Removing…');
    const done = await putSettings({ provider: cur.provider, model: cur.model || el.llmModel.value.trim(), base_url: cur.base_url, clear_key: true });
    if (done) setMsg('Saved key removed.', 'ok');
  });
  for (const opener of [el.llmBtn, el.pillLlm]) opener.addEventListener('click', openSettings);
  el.pillLlm.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openSettings(); }
  });

  /* ------------------------------------------------------------ events */
  const autosize = () => {
    el.input.style.height = 'auto';
    el.input.style.height = `${Math.min(el.input.scrollHeight, 200)}px`;
  };

  el.input.addEventListener('input', autosize);
  el.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); el.form.requestSubmit(); }
  });
  el.form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (state.streaming) { state.abort && state.abort.abort(); return; }
    const text = el.input.value;
    el.input.value = '';
    autosize();
    send(text);
  });
  el.newChat.addEventListener('click', () => {
    if (state.streaming) return;
    state.activeId = null; renderAll(); closeSidebar(); el.input.focus();
  });
  el.menu.addEventListener('click', () => el.sidebar.classList.toggle('open'));
  el.tokenBtn.addEventListener('click', async () => { await askToken(); pollStatus(); });
  el.messages.addEventListener('click', (e) => {
    const cite = e.target.closest('.cite');
    if (!cite) return;
    const row = cite.closest('.msg').querySelector(`.src[data-n="${CSS.escape(cite.dataset.n)}"]`);
    if (!row) return;
    row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    row.classList.add('flash');
    setTimeout(() => row.classList.remove('flash'), 1200);
  });

  /* ------------------------------------------------------------ boot */
  load();
  renderAll();
  pollStatus();
  el.input.focus();
})();
