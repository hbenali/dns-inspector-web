/* DNS Lookup: client-side DNS record lookup over DNS-over-HTTPS (dns.google).
   No dependencies, no inline code (CSP: script-src 'self'). All DOM is built with textContent. */
(function () {
  'use strict';

  var DOH = 'https://dns.google/resolve';
  var $ = function (id) { return document.getElementById(id); };

  var TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, DNSKEY: 48, TLSA: 52, SVCB: 64, HTTPS: 65, CAA: 257 };
  var TYPE_NAMES = {};
  Object.keys(TYPES).forEach(function (k) { TYPE_NAMES[TYPES[k]] = k; });
  Object.assign(TYPE_NAMES, { 39: 'DNAME', 46: 'RRSIG', 47: 'NSEC', 50: 'NSEC3' });
  var COMMON = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];

  var STATUS = {
    0: ['NOERROR', 'The query succeeded. If no records are listed, the name exists but has no record of this type (NODATA).'],
    1: ['FORMERR', 'The DNS server could not understand the query (format error).'],
    2: ['SERVFAIL', 'The resolver could not get a usable answer: the domain\'s name servers are unreachable or broken, the delegation is lame, or DNSSEC validation failed.'],
    3: ['NXDOMAIN', 'The name does not exist in DNS (or a parent label is not delegated). Check the spelling and the zone.'],
    4: ['NOTIMP', 'The server does not support this kind of query.'],
    5: ['REFUSED', 'The server refused to answer this query (policy or access restriction).']
  };

  var ALG = { 5: 'RSASHA1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSASHA256', 10: 'RSASHA512', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448' };
  var DIGEST = { 1: 'SHA-1', 2: 'SHA-256', 3: 'GOST R 34.11-94', 4: 'SHA-384' };
  var TLSA_USAGE = { 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' };
  var TLSA_SEL = { 0: 'full certificate', 1: 'public key (SPKI)' };
  var TLSA_MATCH = { 0: 'exact match', 1: 'SHA-256', 2: 'SHA-512' };

  // ---- Input handling ----
  function normalizeInput(input) {
    var d = String(input || '').trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '');
    d = d.replace(/^\[|\]$/g, '');
    if (d.indexOf(':') === -1) d = d.replace(/\.+$/, '');
    return d;
  }
  function validDomain(d) {
    if (!d || d.length > 253) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(l); });
  }
  function toAscii(d) {
    // IDN to punycode through the URL parser; only used when the input has non-ASCII characters.
    if (/^[\x00-\x7f]*$/.test(d)) return d;
    try { return new URL('http://' + d).hostname; } catch (e) { return d; }
  }
  function isIPv4(s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    return !!m && m.slice(1).every(function (x) { return Number(x) <= 255 && String(Number(x)) === x; });
  }
  // Returns the 32 nibbles of an IPv6 address, or null if it is not a valid address.
  function ipv6Nibbles(s) {
    if (!/^[0-9a-f:]+$/.test(s) || s.indexOf(':::') !== -1) return null;
    var halves = s.split('::');
    if (halves.length > 2) return null;
    var head = halves[0] ? halves[0].split(':') : [];
    var tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    var fill;
    if (halves.length === 2) {
      if (head.length + tail.length > 7) return null;
      fill = new Array(8 - head.length - tail.length).fill('0');
    } else {
      if (head.length !== 8) return null;
      fill = [];
    }
    var groups = head.concat(fill, tail);
    if (groups.length !== 8 || !groups.every(function (g) { return /^[0-9a-f]{1,4}$/.test(g); })) return null;
    return groups.map(function (g) { return ('0000' + g).slice(-4); }).join('');
  }
  function reverseName(ip) {
    if (isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
    var hex = ipv6Nibbles(ip);
    return hex ? hex.split('').reverse().join('.') + '.ip6.arpa' : null;
  }

  // ---- DNS over HTTPS ----
  async function doh(name, type) {
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, 12000);
    try {
      var res = await fetch(DOH + '?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type), { signal: ctl.signal, headers: { accept: 'application/dns-json' } });
      if (!res.ok) throw new Error('dns.google answered HTTP ' + res.status);
      return await res.json();
    } catch (e) {
      if (e && e.name === 'AbortError') throw new Error('dns.google did not answer within 12 seconds');
      throw e;
    } finally { clearTimeout(timer); }
  }

  // ---- Record parsing (data -> readable parts) ----
  function unquote(s) {
    var strings = [], re = /"((?:[^"\\]|\\.)*)"/g, m;
    while ((m = re.exec(s))) strings.push(m[1].replace(/\\(.)/g, '$1'));
    return strings.length ? strings : [s];
  }
  function fmtDuration(s) {
    s = Number(s);
    if (!isFinite(s)) return String(s);
    var parts = [], units = [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]];
    for (var i = 0; i < units.length; i++) {
      var n = Math.floor(s / units[i][1]);
      if (n) { parts.push(n + units[i][0]); s -= n * units[i][1]; }
    }
    return parts.length ? parts.join(' ') : '0s';
  }
  // Returns { text: string used for copy, parts: [[label, value], ...] | null, main: string }
  function parseData(type, data) {
    var f = String(data).split(/\s+/);
    switch (type) {
      case 15:
        if (f.length === 2) return { main: f[1] === '.' ? '. (null MX: this domain accepts no mail)' : f[1], parts: [['priority', f[0]]] };
        break;
      case 6:
        if (f.length === 7) return { main: null, parts: [['primary NS', f[0]], ['admin mailbox', f[1]], ['serial', f[2]], ['refresh', f[3] + 's (' + fmtDuration(f[3]) + ')'], ['retry', f[4] + 's (' + fmtDuration(f[4]) + ')'], ['expire', f[5] + 's (' + fmtDuration(f[5]) + ')'], ['negative TTL', f[6] + 's (' + fmtDuration(f[6]) + ')']] };
        break;
      case 257: {
        var m = /^(\d+)\s+(\S+)\s+(.*)$/.exec(data);
        if (m) return { main: unquote(m[3]).join(''), parts: [['flags', m[1] + (m[1] === '128' ? ' (critical)' : '')], ['tag', m[2]]] };
        break;
      }
      case 33:
        if (f.length === 4) return { main: f[3] + ':' + f[2], parts: [['priority', f[0]], ['weight', f[1]]] };
        break;
      case 16: {
        var strs = unquote(data), joined = strs.join('');
        return { main: joined, parts: strs.length > 1 ? [['joined from', strs.length + ' strings']] : null, copy: joined };
      }
      case 43:
        if (f.length === 4) return { main: f[3], parts: [['key tag', f[0]], ['algorithm', f[1] + (ALG[f[1]] ? ' ' + ALG[f[1]] : '')], ['digest type', f[2] + (DIGEST[f[2]] ? ' ' + DIGEST[f[2]] : '')]] };
        break;
      case 48:
        if (f.length >= 4) {
          var role = f[0] === '257' ? 'KSK (key signing key)' : f[0] === '256' ? 'ZSK (zone signing key)' : 'flags ' + f[0];
          return { main: f.slice(3).join(''), parts: [['role', role], ['algorithm', f[2] + (ALG[f[2]] ? ' ' + ALG[f[2]] : '')]] };
        }
        break;
      case 52:
        if (f.length >= 4) return { main: f.slice(3).join(''), parts: [['usage', f[0] + ' ' + (TLSA_USAGE[f[0]] || '')], ['selector', f[1] + ' ' + (TLSA_SEL[f[1]] || '')], ['matching', f[2] + ' ' + (TLSA_MATCH[f[2]] || '')]] };
        break;
      case 64:
      case 65:
        if (f.length >= 2) return { main: f.slice(1).join(' '), parts: [['priority', f[0] === '0' ? '0 (alias mode)' : f[0]]] };
        break;
    }
    return { main: String(data), parts: null };
  }

  // ---- One lookup ----
  async function lookup(name, typeName) {
    var out = { type: typeName, status: null, ad: false, tc: false, answers: [], authority: [], comment: '', error: null };
    try {
      var j = await doh(name, TYPES[typeName]);
      out.status = j.Status; out.ad = !!j.AD; out.tc = !!j.TC; out.comment = j.Comment || '';
      out.answers = (j.Answer || []).map(function (r) { return { name: r.name, type: r.type, ttl: r.TTL, data: r.data }; });
      out.authority = (j.Authority || []).filter(function (r) { return r.type === 6; }).map(function (r) { return { name: r.name, type: r.type, ttl: r.TTL, data: r.data }; });
    } catch (e) { out.error = (e && e.message) || 'Lookup failed'; }
    return out;
  }

  // CNAME chain: follow CNAME records in the answer starting from the queried name.
  function cnameChain(name, results) {
    var map = Object.create(null); // names come from DNS answers: no prototype keys like __proto__
    results.forEach(function (r) {
      r.answers.forEach(function (a) { if (a.type === 5) map[a.name.toLowerCase().replace(/\.$/, '')] = a.data.replace(/\.$/, ''); });
    });
    var chain = [name], seen = Object.create(null);
    var cur = name;
    while (map[cur] && !seen[cur]) { seen[cur] = true; cur = map[cur].toLowerCase(); chain.push(cur); }
    return chain.length > 1 ? chain : null;
  }

  // ---- Rendering ----
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  var views = { placeholder: $('placeholderState'), records: $('recordsContainer'), error: $('errorContainer') };
  function setView(name) { Object.keys(views).forEach(function (k) { views[k].hidden = k !== name; }); }

  function typeLabel(n) { return TYPE_NAMES[n] || ('TYPE' + n); }

  function renderRecord(rec, authority) {
    var row = el('div', 'rr' + (authority ? ' rr-auth' : ''));
    row.append(el('span', 'rr-ttl', rec.ttl + 's'));
    row.append(el('span', 'rr-type', typeLabel(rec.type) + (authority ? ' (authority)' : '')));
    var p = parseData(rec.type, rec.data);
    var cell = el('div', 'rr-data');
    if (p.main) cell.append(el('span', 'rr-main', p.main));
    if (p.parts) {
      var kv = el('div', 'rr-kv');
      p.parts.forEach(function (kvp) {
        var s = el('span', 'kv');
        s.append(el('span', 'k', kvp[0] + ' '));
        s.append(kvp[1]);
        kv.append(s);
      });
      cell.append(kv);
    }
    row.append(cell);
    return row;
  }

  function renderSection(res, showName) {
    var sec = el('section', 'dns-sec');
    var info = STATUS[res.status] || ['RCODE ' + res.status, 'The server returned an uncommon response code.'];
    var level = res.error ? 'fail' : res.status !== 0 ? (res.status === 3 ? 'warn' : 'fail') : res.answers.length ? 'ok' : 'warn';
    var head = el('div', 'dns-head');
    head.append(el('h3', 'dns-type', res.type));
    if (res.error) {
      head.append(el('span', 'pill fail', 'ERROR'));
      sec.append(head);
      var e = el('p', 'dns-expl', res.error);
      e.setAttribute('role', 'alert');
      sec.append(e);
      return sec;
    }
    head.append(el('span', 'pill ' + level, info[0]));
    head.append(el('span', 'pill ' + (res.ad ? 'ok' : 'info'), res.ad ? 'AD: DNSSEC validated' : 'AD: not validated'));
    head.append(el('span', 'dns-count', res.answers.length + (res.answers.length === 1 ? ' record' : ' records')));
    sec.append(head);
    var expl = info[1];
    if (res.status === 0) expl = res.answers.length ? 'The query succeeded.' : 'The query succeeded but the name has no ' + res.type + ' record (NODATA): the name may exist with other record types.';
    sec.append(el('p', 'dns-expl', expl));
    if (res.tc) sec.append(el('p', 'dns-expl warn', 'The answer was truncated (TC flag): the result may be incomplete.'));
    if (res.answers.length) {
      var list = el('div', 'rr-list');
      res.answers.forEach(function (a) { list.append(renderRecord(a, false)); });
      sec.append(list);
    } else if (res.authority.length) {
      var l2 = el('div', 'rr-list');
      res.authority.forEach(function (a) { l2.append(renderRecord(a, true)); });
      sec.append(l2);
    }
    return sec;
  }

  function resultText(name, results, chain) {
    var lines = ['; DNS lookup for ' + name + ' via dns.google (DNS-over-HTTPS)'];
    if (chain) lines.push('; CNAME chain: ' + chain.join(' -> '));
    results.forEach(function (r) {
      if (r.error) { lines.push('; ' + r.type + ': ERROR ' + r.error); return; }
      var info = STATUS[r.status] || ['RCODE ' + r.status];
      lines.push('; ' + r.type + ': ' + info[0] + ', AD=' + (r.ad ? 'yes' : 'no') + ', ' + r.answers.length + ' record(s)');
      r.answers.forEach(function (a) {
        var p = parseData(a.type, a.data);
        lines.push(a.name + '\t' + a.ttl + '\tIN\t' + typeLabel(a.type) + '\t' + (p.copy != null ? '"' + p.copy.replace(/(["\\])/g, '\\$1') + '"' : a.data));
      });
      if (!r.answers.length) r.authority.forEach(function (a) { lines.push(';; authority: ' + a.name + '\t' + a.ttl + '\tIN\tSOA\t' + a.data); });
    });
    return lines.join('\n') + '\n';
  }

  function siblingLinks(domain) {
    var wrap = el('p', 'provider');
    wrap.append('Also check ' + domain + ': ');
    [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC'], ['bimi', 'BIMI'], ['dnssec', 'DNSSEC'], ['caa', 'CAA'], ['mx', 'MX'], ['ssl', 'SSL'], ['rdap', 'RDAP'], ['ip', 'IP']].forEach(function (t, i) {
      if (i) wrap.append(' · ');
      var a = el('a', 'link', t[1]);
      a.href = 'https://' + t[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(domain);
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      wrap.append(a);
    });
    return wrap;
  }

  var lastText = '';
  function renderResults(name, display, results, note, isIp) {
    var box = views.records;
    box.replaceChildren();
    var state = el('div', 'state');
    state.append(el('h2', 'state-title', results.length > 1 ? 'Records for ' + display : results[0].type + ' records for ' + display));
    var bad = results.filter(function (r) { return r.error || (r.status !== 0 && r.status !== 3); }).length;
    state.classList.add(bad ? 'fail' : results.some(function (r) { return r.answers.length; }) ? 'ok' : 'warn');
    if (name !== display) {
      var q = el('p');
      q.append('Queried as ');
      q.append(el('code', null, name));
      state.append(q);
    }
    if (note) state.append(el('p', null, note));
    var chain = cnameChain(name, results.filter(function (r) { return !r.error; }));
    if (chain) {
      var cp = el('div', 'chain');
      cp.append(el('span', 'chain-label', 'CNAME chain'));
      var seq = el('span', 'chain-seq');
      chain.forEach(function (h, i) {
        if (i) seq.append(el('span', 'arrow', ' → '));
        seq.append(el('code', null, h));
      });
      cp.append(seq);
      state.append(cp);
    }
    box.append(state);

    var secs = el('div', 'dns-secs');
    results.forEach(function (r) { secs.append(renderSection(r)); });
    box.append(secs);

    lastText = resultText(name, results, chain);
    var actions = el('div', 'actions copy-row');
    var copy = el('button', 'btn quiet', 'Copy as text');
    copy.type = 'button';
    var msg = el('span', 'copy-msg');
    msg.setAttribute('role', 'status');
    copy.addEventListener('click', function () {
      var done = function (ok) { msg.textContent = ok ? 'Copied.' : 'Copy failed: select the text manually.'; };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(lastText).then(function () { done(true); }, function () { done(false); });
      else done(false);
    });
    actions.append(copy, msg);
    box.append(actions);

    var honest = el('p', 'provider');
    honest.append('Answers come from Google Public DNS, not from the domain\'s authoritative servers: TTLs are the remaining cache time and AD reflects Google\'s DNSSEC validation. AD "not validated" does not by itself mean the zone is unsigned.');
    box.append(honest);
    if (!isIp) box.append(siblingLinks(display));
  }

  function renderError(msg) {
    var box = views.error;
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', 'Cannot run this lookup'));
    s.append(el('p', null, msg));
    box.append(s);
  }

  // ---- Lookup flow ----
  var domainInput = $('domainInput'), typeSelect = $('typeSelect'), lookupBtn = $('lookupBtn'), allBtn = $('allBtn');
  var btnText = $('btnText'), btnLoader = $('btnLoader');
  var running = false;

  function setLoading(on) {
    running = on;
    lookupBtn.disabled = on; allBtn.disabled = on;
    btnText.textContent = on ? 'Looking up' : 'Look up';
    btnLoader.hidden = !on;
    btnLoader.className = on ? 'loader' : '';
  }

  function updateUrl(domain, type) {
    try {
      var u = new URL(window.location.href);
      u.searchParams.set('domain', domain);
      u.searchParams.set('type', type);
      window.history.replaceState(null, '', u.pathname + u.search);
    } catch (e) { /* ignore */ }
  }

  async function performLookup(mode) {
    if (running) return;
    var raw = normalizeInput(domainInput.value);
    if (!raw) { renderError('Enter a domain name or an IP address.'); setView('error'); return; }
    var name, display = raw, note = null, types;
    var wantAll = mode === 'ALL';
    if (isIPv4(raw) || (raw.indexOf(':') !== -1 && ipv6Nibbles(raw))) {
      name = reverseName(raw);
      types = ['PTR'];
      typeSelect.value = 'PTR';
      note = 'IP address detected: looking up the reverse DNS (PTR) record at the name below.';
    } else if (raw.indexOf(':') !== -1 || /^\d+(\.\d+)*$/.test(raw)) {
      renderError('"' + raw + '" is not a valid IP address or domain name.'); setView('error'); return;
    } else {
      name = toAscii(raw);
      if (!validDomain(name)) { renderError('"' + raw + '" is not a valid domain name (letters, digits, hyphens and underscores in labels of at most 63 characters).'); setView('error'); return; }
      types = wantAll ? COMMON : [mode];
      if (name !== raw) display = raw;
    }
    if (!wantAll && !Object.prototype.hasOwnProperty.call(TYPES, types[0])) { renderError('Unsupported record type.'); setView('error'); return; }
    domainInput.value = display;
    if (types.length === 1) typeSelect.value = types[0];
    updateUrl(display, wantAll && types.length > 1 ? 'ALL' : types[0]);
    setLoading(true);
    try {
      var results = await Promise.all(types.map(function (t) { return lookup(name, t); }));
      if (results.every(function (r) { return r.error; })) {
        renderError(results[0].error + '. Check your connection, or whether a blocker is stopping requests to dns.google.');
        setView('error');
      } else {
        renderResults(name, display, results, note, !!note);
        setView('records');
      }
    } catch (err) {
      renderError((err && err.message) || 'Unknown error');
      setView('error');
    } finally {
      setLoading(false);
    }
  }

  $('lookupForm').addEventListener('submit', function (e) { e.preventDefault(); performLookup(typeSelect.value); });
  allBtn.addEventListener('click', function () { performLookup('ALL'); });

  // ---- Populate the type selector ----
  Object.keys(TYPES).forEach(function (t) {
    var o = document.createElement('option');
    o.value = t; o.textContent = t;
    typeSelect.append(o);
  });
  typeSelect.value = 'A';

  setView('placeholder');

  var params = new URLSearchParams(window.location.search);
  var pDomain = params.get('domain'), pType = (params.get('type') || '').toUpperCase();
  if (pDomain) {
    domainInput.value = pDomain;
    if (Object.prototype.hasOwnProperty.call(TYPES, pType)) typeSelect.value = pType;
    performLookup(pType === 'ALL' ? 'ALL' : typeSelect.value);
  }

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
})();
