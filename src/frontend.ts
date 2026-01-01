export const html = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Mimi - Encrypted Treehole</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    .fade { transition: opacity .2s ease; }
  </style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen flex flex-col items-center py-10 px-4">
  <div id="app" class="w-full max-w-2xl">
    <header class="mb-8 flex justify-between items-center">
      <div>
        <h1 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">Mimi</h1>
        <p class="text-gray-400 text-sm mt-1">Encrypted Treehole</p>
      </div>
      <button id="toggleAdminBtn" class="text-xs px-3 py-1 rounded border border-gray-700 hover:bg-gray-800 transition-colors">Admin Login</button>
    </header>

    <main class="space-y-8">
      <section id="guestSection">
        <div class="bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-700">
          <h2 class="text-xl font-semibold mb-4">Leave a message</h2>

          <div id="keysLoading" class="text-sm text-gray-400 animate-pulse">Fetching public keys...</div>
          <div id="keysMissing" class="hidden text-sm text-red-400">
            No active encryption keys found. Ask the admin to publish a key first.
          </div>

          <div id="keysReady" class="hidden space-y-4">
            <div class="text-xs text-gray-500 font-mono break-all">
              Using Key: <span id="activeKid" class="text-emerald-400"></span> (<span id="activeAlg"></span>)
            </div>

            <textarea
              id="messageInput"
              class="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-white placeholder-gray-500 focus:ring-2 focus:ring-emerald-500 focus:outline-none transition-all h-32"
              placeholder="Type your secret message here..."
            ></textarea>

            <div class="flex justify-between items-center">
              <span class="text-xs text-gray-500">End-to-End Encrypted. Server never sees plaintext.</span>
              <button
                id="sendBtn"
                class="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg font-medium transition-all flex items-center gap-2"
              >
                <span id="sendSpinner" class="hidden w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                <span id="sendLabel">Send</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <section id="adminSection" class="hidden space-y-6">
        <div class="bg-gray-800 p-6 rounded-xl border border-gray-700 space-y-4">
          <h2 class="text-xl font-semibold">Admin</h2>
          <div class="grid gap-4 md:grid-cols-2">
            <div>
              <label class="block text-xs text-gray-400 mb-1">Supabase Access Token (Bearer)</label>
              <input id="adminTokenInput" type="password" class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-sm font-mono" placeholder="eyJ..." />
            </div>
            <div>
              <label class="block text-xs text-gray-400 mb-1">Private Key (PEM)</label>
              <textarea id="privateKeyPem" class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-xs font-mono h-24" placeholder="-----BEGIN PRIVATE KEY-----..."></textarea>
            </div>
          </div>
          <div class="flex flex-wrap gap-2">
            <button id="checkAdminBtn" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm font-medium inline-flex items-center gap-2">
              <span id="checkSpinner" class="hidden w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
              <span id="checkLabel">Check Token</span>
            </button>
            <button id="fetchMessagesBtn" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-medium inline-flex items-center gap-2">
              <span id="fetchSpinner" class="hidden w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
              <span id="fetchLabel">Fetch Messages</span>
            </button>
            <button id="toggleKeyGenBtn" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm font-medium">Key Generator</button>
          </div>
          <div id="adminStatus" class="text-xs text-gray-400 font-mono break-words"></div>
        </div>

        <div id="keyGenPanel" class="hidden bg-gray-800 p-6 rounded-xl border border-gray-600 space-y-4">
          <h3 class="font-semibold text-lg">Generate RSA-OAEP Key Pair</h3>
          <p class="text-sm text-gray-400">Generate a keypair, then run the SQL in Supabase to publish the public key.</p>
          <button id="generateKeyPairBtn" class="px-4 py-2 bg-purple-600 hover:bg-purple-500 rounded text-sm font-medium">Generate New Pair</button>

          <div id="genKeyOut" class="hidden grid gap-4 md:grid-cols-2 mt-4">
            <div>
              <label class="block text-xs text-purple-300 mb-1">SQL (Public Key)</label>
              <pre id="genSql" class="bg-black p-2 rounded border border-gray-700 overflow-auto text-xs font-mono h-40 whitespace-pre-wrap"></pre>
            </div>
            <div>
              <label class="block text-xs text-red-300 mb-1">Private Key (SAVE SECURELY)</label>
              <pre id="genPriv" class="bg-black p-2 rounded border border-gray-700 overflow-auto text-xs font-mono h-40 whitespace-pre-wrap"></pre>
            </div>
          </div>
        </div>

        <div>
          <div id="noMessages" class="text-center text-gray-500 py-6">No messages found (or not fetched yet).</div>
          <div id="messagesList" class="space-y-4"></div>
          <div id="pagination" class="hidden flex justify-center gap-4 pt-4">
            <button id="prevBtn" class="disabled:opacity-50 text-sm underline">Prev</button>
            <span id="pageNum" class="text-sm text-gray-500">1</span>
            <button id="nextBtn" class="text-sm underline">Next</button>
          </div>
        </div>
      </section>
    </main>
  </div>

  <div class="fixed bottom-4 left-0 right-0 flex flex-col items-center pointer-events-none">
    <div id="successToast" class="hidden mb-2 p-3 bg-emerald-900 border border-emerald-500 text-emerald-100 rounded-lg shadow-xl pointer-events-auto fade"></div>
    <div id="errorToast" class="hidden mb-2 p-3 bg-red-900 border border-red-500 text-red-100 rounded-lg shadow-xl pointer-events-auto fade"></div>
  </div>

  <script>
    const $ = (id) => document.getElementById(id);
    const state = { isAdmin: false, activeKey: null, loadingKeys: true, sending: false, adminBusy: null, offset: 0, messages: [] };

    function show(el, on) { if (el) el.classList.toggle('hidden', !on); }
    function toast(kind, msg) {
      const ok = $('successToast'), err = $('errorToast');
      show(ok, false); show(err, false);
      if (!msg) return;
      const t = kind === 'success' ? ok : err;
      t.textContent = msg;
      show(t, true);
      window.setTimeout(() => show(t, false), kind === 'success' ? 2500 : 5000);
    }

    function u8ToBase64(u8) { let b = ''; for (let i = 0; i < u8.byteLength; i++) b += String.fromCharCode(u8[i]); return btoa(b); }
    function base64ToU8(b64) { return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)); }
    function stripPem(pem, label) { return (pem || '').replace(new RegExp('-----BEGIN ' + label + '-----|-----END ' + label + '-----|\\\\s+', 'g'), ''); }

    async function importPublicKey(pem) {
      const b64 = stripPem(pem, 'PUBLIC KEY');
      return crypto.subtle.importKey('spki', base64ToU8(b64), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']);
    }
    async function importPrivateKey(pem) {
      const b64 = stripPem(pem, 'PRIVATE KEY');
      return crypto.subtle.importKey('pkcs8', base64ToU8(b64), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['unwrapKey']);
    }

    function setAdminMode(on) {
      state.isAdmin = on;
      show($('guestSection'), !on);
      show($('adminSection'), on);
      $('toggleAdminBtn').textContent = on ? 'Exit Admin' : 'Admin Login';
    }

    function renderKeyState() {
      show($('keysLoading'), state.loadingKeys);
      show($('keysMissing'), !state.loadingKeys && !state.activeKey);
      show($('keysReady'), !state.loadingKeys && !!state.activeKey);
      if (state.activeKey) { $('activeKid').textContent = state.activeKey.kid || ''; $('activeAlg').textContent = state.activeKey.alg || ''; }
      const msg = ($('messageInput')?.value || '').trim();
      $('sendBtn').disabled = state.sending || !state.activeKey || !msg;
      show($('sendSpinner'), state.sending);
      $('sendLabel').textContent = state.sending ? 'Encrypting & Sending...' : 'Send';

      const busy = state.adminBusy !== null;
      $('checkAdminBtn').disabled = busy;
      $('fetchMessagesBtn').disabled = busy;

      show($('checkSpinner'), state.adminBusy === 'check');
      $('checkLabel').textContent = state.adminBusy === 'check' ? 'Checking...' : 'Check Token';

      show($('fetchSpinner'), state.adminBusy === 'fetch');
      $('fetchLabel').textContent = state.adminBusy === 'fetch' ? 'Fetching...' : 'Fetch Messages';
    }

    function setAdminStatus(text) {
      if ($('adminStatus')) $('adminStatus').textContent = text || '';
    }

    async function fetchJsonWithTimeout(url, init, timeoutMs) {
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(url, Object.assign({}, init, { signal: controller.signal, cache: 'no-store' }));
        const json = await res.json().catch(() => ({}));
        return { res, json };
      } finally {
        window.clearTimeout(timer);
      }
    }

    function setPaging() {
      $('pageNum').textContent = String(Math.floor(state.offset / 50) + 1);
      $('prevBtn').disabled = state.offset === 0;
      show($('pagination'), state.messages.length > 0);
      show($('noMessages'), state.messages.length === 0);
    }

    function renderMessages() {
      const list = $('messagesList');
      list.innerHTML = '';
      for (const msg of state.messages) {
        const card = document.createElement('div');
        card.className = 'bg-gray-800 p-4 rounded-xl border border-gray-700 hover:border-gray-600 transition-colors';

        const header = document.createElement('div');
        header.className = 'flex justify-between items-start mb-2';

        const meta = document.createElement('div');
        meta.className = 'text-xs text-gray-500 font-mono';
        const created = msg.created_at ? new Date(msg.created_at).toLocaleString() : '';
        meta.innerHTML = 'ID: ' + String(msg.id || '').slice(0, 8) + '...<br>' + created;

        const actions = document.createElement('div');
        actions.className = 'flex gap-2';

        if (!msg.decrypted) {
          const dec = document.createElement('button');
          dec.className = 'text-xs bg-emerald-900 text-emerald-200 px-2 py-1 rounded hover:bg-emerald-800';
          dec.textContent = 'Decrypt';
          dec.onclick = async () => {
            try {
              const pem = ($('privateKeyPem').value || '').trim();
              if (!pem) return toast('error', 'Please paste your Private Key first.');
              const privKey = await importPrivateKey(pem);
              const aesKey = await crypto.subtle.unwrapKey('raw', base64ToU8(msg.wrapped_key), privKey, { name: 'RSA-OAEP' }, { name: 'AES-GCM' }, true, ['decrypt']);
              const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToU8(msg.nonce) }, aesKey, base64ToU8(msg.ciphertext));
              msg.decrypted = true;
              msg.decryptedContent = new TextDecoder().decode(plainBuf);
              renderMessages();
            } catch {
              toast('error', 'Decryption failed. Check Private Key and message integrity.');
            }
          };
          actions.appendChild(dec);
        }

        const del = document.createElement('button');
        del.className = 'text-xs bg-red-900 text-red-200 px-2 py-1 rounded hover:bg-red-800';
        del.textContent = 'Delete';
        del.onclick = async () => {
          if (!confirm('Delete?')) return;
          try {
            const token = ($('adminTokenInput').value || '').trim();
            const res = await fetch('/v1/messages/' + msg.id, { method: 'DELETE', headers: { Authorization: 'Bearer ' + token } });
            if (!res.ok) throw new Error();
            state.messages = state.messages.filter((m) => m.id !== msg.id);
            renderMessages();
            setPaging();
          } catch {
            toast('error', 'Delete failed.');
          }
        };
        actions.appendChild(del);

        header.appendChild(meta);
        header.appendChild(actions);
        card.appendChild(header);

        if (msg.decrypted) {
          const content = document.createElement('div');
          content.className = 'mt-2 p-3 bg-gray-900 rounded text-gray-200 whitespace-pre-wrap font-sans';
          content.textContent = msg.decryptedContent || '';
          card.appendChild(content);
        } else {
          const preview = document.createElement('div');
          preview.className = 'mt-2 text-xs text-gray-600 font-mono break-all line-clamp-2';
          preview.textContent = '[Encrypted] ' + (msg.ciphertext || '');
          card.appendChild(preview);
        }

        list.appendChild(card);
      }
      setPaging();
    }

    async function fetchPublicKeys() {
      state.loadingKeys = true;
      renderKeyState();
      try {
        const res = await fetch('/v1/crypto/public-keys', { cache: 'no-store' });
        const json = await res.json();
        const list = Array.isArray(json.data) ? json.data : [];
        state.activeKey = list.find((k) => String(k.alg || '').toUpperCase().includes('RSA')) || list[0] || null;
      } catch {
        toast('error', 'Failed to load encryption keys.');
        state.activeKey = null;
      } finally {
        state.loadingKeys = false;
        renderKeyState();
      }
    }

    async function submitMessage() {
      if (!state.activeKey) return;
      const message = ($('messageInput').value || '').trim();
      if (!message) return;
      state.sending = true;
      renderKeyState();
      try {
        const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, new TextEncoder().encode(message));
        const pubKey = await importPublicKey(state.activeKey.public_key);
        const wrappedKeyBuf = await crypto.subtle.wrapKey('raw', aesKey, pubKey, { name: 'RSA-OAEP' });

        const res = await fetch('/v1/messages', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            kid: state.activeKey.kid,
            alg: 'AES-GCM',
            version: 1,
            wrapped_key: u8ToBase64(new Uint8Array(wrappedKeyBuf)),
            nonce: u8ToBase64(iv),
            ciphertext: u8ToBase64(new Uint8Array(ciphertextBuf)),
            aad: null
          })
        });
        const json = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(json.error || 'Send failed');
        $('messageInput').value = '';
        toast('success', 'Message sent!');
      } catch (e) {
        toast('error', (e && e.message) ? e.message : 'Send failed');
      } finally {
        state.sending = false;
        renderKeyState();
      }
    }

    async function fetchMessages() {
      if (state.adminBusy) return;
      try {
        const token = ($('adminTokenInput').value || '').trim();
        if (!token) return toast('error', 'Please paste admin access token first.');

        state.adminBusy = 'fetch';
        setAdminStatus('Requesting /v1/messages ...');
        renderKeyState();

        const started = Date.now();
        const { res, json } = await fetchJsonWithTimeout(
          '/v1/messages?limit=50&offset=' + state.offset,
          { headers: { Authorization: 'Bearer ' + token } },
          15000,
        );
        const ms = Date.now() - started;

        if (!res.ok) {
          const msg = json?.error || ('Fetch failed (HTTP ' + res.status + ')');
          setAdminStatus('Fetch failed in ' + ms + 'ms: ' + msg);
          throw new Error(msg);
        }

        state.messages = (json.data || []).map((m) => Object.assign({}, m, { decrypted: false, decryptedContent: null }));
        renderMessages();
        setAdminStatus('Fetched ' + state.messages.length + ' messages in ' + ms + 'ms.');
      } catch (e) {
        toast('error', (e && e.message) ? e.message : 'Fetch failed');
      } finally {
        state.adminBusy = null;
        renderKeyState();
      }
    }

    async function checkAdmin() {
      if (state.adminBusy) return;
      try {
        const token = ($('adminTokenInput').value || '').trim();
        if (!token) return toast('error', 'Please paste admin access token first.');

        state.adminBusy = 'check';
        setAdminStatus('Checking token (/v1/admin/status) ...');
        renderKeyState();

        const started = Date.now();
        const { res, json } = await fetchJsonWithTimeout(
          '/v1/admin/status',
          { headers: { Authorization: 'Bearer ' + token } },
          15000,
        );
        const ms = Date.now() - started;

        if (!res.ok) {
          const msg = json?.error || ('Check failed (HTTP ' + res.status + ')');
          setAdminStatus('Check failed in ' + ms + 'ms: ' + msg);
          throw new Error(msg);
        }

        setAdminStatus('Token OK in ' + ms + 'ms. is_admin=' + String(!!json?.is_admin));
      } catch (e) {
        toast('error', (e && e.message) ? e.message : 'Check failed');
      } finally {
        state.adminBusy = null;
        renderKeyState();
      }
    }

    async function generateKeyPair() {
      try {
        const kp = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['wrapKey', 'unwrapKey']);
        const pubB64 = u8ToBase64(new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey)));
        const privB64 = u8ToBase64(new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey)));
        const fmt = (b64, label) => '-----BEGIN ' + label + '-----\\n' + b64.match(/.{1,64}/g).join('\\n') + '\\n-----END ' + label + '-----';
        const pubPem = fmt(pubB64, 'PUBLIC KEY');
        const privPem = fmt(privB64, 'PRIVATE KEY');
        const sql =
          \"insert into public.encryption_public_keys (kid, alg, public_key, active) values ('web-1','RSA-OAEP', $$\" +
          pubPem +
          \"$$, true) on conflict (kid) do update set alg=excluded.alg, public_key=excluded.public_key, active=true;\\n\";
        $('genSql').textContent = sql;
        $('genPriv').textContent = privPem;
        show($('genKeyOut'), true);
      } catch {
        toast('error', 'Key generation failed.');
      }
    }

    function init() {
      $('toggleAdminBtn').onclick = () => setAdminMode(!state.isAdmin);
      $('messageInput').oninput = renderKeyState;
      $('sendBtn').onclick = submitMessage;

      $('adminTokenInput').value = localStorage.getItem('mimi_admin_token') || '';
      $('adminTokenInput').oninput = () => localStorage.setItem('mimi_admin_token', $('adminTokenInput').value || '');
      $('checkAdminBtn').onclick = checkAdmin;
      $('fetchMessagesBtn').onclick = fetchMessages;
      $('toggleKeyGenBtn').onclick = () => show($('keyGenPanel'), $('keyGenPanel').classList.contains('hidden'));
      $('generateKeyPairBtn').onclick = generateKeyPair;

      $('nextBtn').onclick = () => { state.offset += 50; fetchMessages(); };
      $('prevBtn').onclick = () => { state.offset = Math.max(0, state.offset - 50); fetchMessages(); };

      setAdminMode(false);
      setAdminStatus('');
      renderKeyState();
      renderMessages();
      fetchPublicKeys();
    }

    window.addEventListener('DOMContentLoaded', init);
  </script>
</body>
</html>`;
