(function () {
  'use strict';
  var VER = (document.currentScript && document.currentScript.dataset.ver) || '';
  var STORE = 'gushel-book-key';
  var $ = function (s) { return document.querySelector(s); };
  var gate = $('#gate'), loading = $('#loading'), msg = $('#gate-msg');
  var binPromise = null;

  function readHash() {
    var h = location.hash.replace(/^#/, ''), out = { k: null, p: null };
    h.split('&').forEach(function (part) {
      var kv = part.split('=');
      if (kv[0] === 'k' && kv[1]) out.k = decodeURIComponent(kv[1]);
      else if (/^p\d+$/.test(kv[0])) out.p = kv[0];
      else if (kv[0] === 'p' && kv[1]) out.p = 'p' + kv[1];
    });
    return out;
  }

  function normalize(code) {
    var c = String(code || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    return c.length === 12 ? c.slice(0, 4) + '-' + c.slice(4, 8) + '-' + c.slice(8) : String(code || '').trim().toLowerCase().replace(/^@/, '');
  }

  function fetchBin() {
    if (!binPromise) {
      binPromise = fetch('book.bin?v=' + VER, { cache: 'force-cache' }).then(function (r) {
        if (!r.ok) throw new Error('net');
        return r.arrayBuffer();
      });
      binPromise.catch(function () { binPromise = null; });
    }
    return binPromise;
  }

  async function decrypt(code) {
    if (!(window.crypto && crypto.subtle) || typeof DecompressionStream === 'undefined') throw new Error('old');
    var buf = new Uint8Array(await fetchBin());
    var magic = String.fromCharCode(buf[0], buf[1], buf[2], buf[3]);
    if (magic !== 'GSH1') throw new Error('format');
    var iter = new DataView(buf.buffer).getUint32(4);
    var salt = buf.slice(8, 24), iv = buf.slice(24, 36), data = buf.slice(36);
    var base = await crypto.subtle.importKey('raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveKey']);
    var key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    var plain;
    try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data); }
    catch (e) { throw new Error('badkey'); }
    var stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));
    return JSON.parse(await new Response(stream).text());
  }

  function buildToc(meta) {
    var list = $('#toc-list');
    list.innerHTML = '';
    (meta.toc || []).forEach(function (e) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = '#p' + e.p;
      a.innerHTML = '<span class="n"></span><span class="t"></span><span class="k"></span>';
      a.querySelector('.n').textContent = e.n;
      a.querySelector('.t').textContent = e.t;
      a.querySelector('.k').textContent = e.kind;
      a.addEventListener('click', function (ev) {
        ev.preventDefault();
        closeToc();
        var el = document.getElementById('p' + e.p);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        history.replaceState(null, '', '#p' + e.p);
      });
      li.appendChild(a);
      list.appendChild(li);
    });
  }

  function openToc() { $('#toc').hidden = false; $('#toc-btn').setAttribute('aria-expanded', 'true'); $('#toc-close').focus(); }
  function closeToc() { $('#toc').hidden = true; $('#toc-btn').setAttribute('aria-expanded', 'false'); }

  function show(data, page) {
    $('#book').innerHTML = data.html;
    buildToc(data.meta || {});
    gate.hidden = true;
    loading.hidden = true;
    $('#bar').hidden = false;
    $('#toc-btn').addEventListener('click', function () { $('#toc').hidden ? openToc() : closeToc(); });
    $('#toc-close').addEventListener('click', closeToc);
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeToc(); });
    if (page) {
      var el = document.getElementById(page);
      if (el) requestAnimationFrame(function () { el.scrollIntoView({ block: 'start' }); });
    }
  }

  function showGate(text) {
    loading.hidden = true;
    gate.hidden = false;
    msg.textContent = text || '';
  }

  function cleanUrl(page) {
    history.replaceState(null, '', location.pathname + location.search + (page ? '#' + page : ''));
  }

  async function tryOpen(code, page, fromUser) {
    code = normalize(code);
    try {
      var data = await decrypt(code);
      try { localStorage.setItem(STORE, code); } catch (e) {}
      cleanUrl(page);
      show(data, page);
      return true;
    } catch (e) {
      var m = e.message;
      if (m === 'badkey') return showGate(fromUser ? 'Код не подошёл. Проверьте буквы и цифры.' : 'Ссылка устарела или повреждена — введите код из книги.'), false;
      if (m === 'old') return showGate('Ваш браузер устарел. Откройте ссылку в свежей версии Chrome, Safari или Firefox.'), false;
      return showGate('Не удалось загрузить книгу. Проверьте интернет и попробуйте ещё раз.'), false;
    }
  }

  $('#gate-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var btn = this.querySelector('button');
    btn.disabled = true; msg.textContent = 'Проверяем…';
    var ok = await tryOpen($('#gate-code').value, readHash().p, true);
    btn.disabled = false;
    if (!ok) $('#gate-code').focus();
  });

  (async function init() {
    if (window.__PLAIN__) { show(window.__PLAIN__, readHash().p); return; }   // local preview only
    var h = readHash(), stored = null;
    try { stored = localStorage.getItem(STORE); } catch (e) {}
    if (h.k) {
      if (await tryOpen(h.k, h.p, false)) return;
      cleanUrl(h.p);
      return;
    }
    if (stored) {
      if (await tryOpen(stored, h.p, false)) return;
      try { localStorage.removeItem(STORE); } catch (e) {}
      return showGate('');
    }
    showGate('');
  })();
})();
