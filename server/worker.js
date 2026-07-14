/*
 * ACE TECH 하자관리 시스템 - 백엔드(Cloudflare Worker)
 *
 * 이 파일은 브라우저(정적 사이트)와 GitHub 저장소 사이의 유일한 중개자입니다.
 * GitHub에 쓰기 권한이 있는 토큰은 이 Worker의 환경변수(Secret)에만 저장되고,
 * 브라우저에는 절대 전달되지 않습니다. 브라우저는 이 Worker가 제공하는
 * HTTP API만 호출합니다.
 *
 * 데이터는 이 저장소의 `data/` 폴더 아래 JSON 파일로 저장됩니다.
 *   data/users.json                 - 계정 목록 (아이디, 비밀번호 해시, 역할, 소속 사업소)
 *   data/sites/{siteId}/meta.json   - 사업소(현장) 정보
 *   data/sites/{siteId}/defects.json- 사업소별 하자 목록
 *
 * 필요한 환경변수(Secret/Var)는 server/README.md 를 참고하세요.
 */

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonResponse(env, data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({}, JSON_HEADERS, corsHeaders(env)),
  });
}

function errorResponse(env, message, status) {
  return jsonResponse(env, { error: message }, status || 400);
}

/* ---------- base64url / crypto 유틸 ---------- */

function bytesToBase64Url(bytes) {
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64UrlToBytes(b64url) {
  var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function utf8ToBytes(str) { return new TextEncoder().encode(str); }
function bytesToUtf8(bytes) { return new TextDecoder().decode(bytes); }

async function pbkdf2Hash(password, saltBytes) {
  var keyMaterial = await crypto.subtle.importKey('raw', utf8ToBytes(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  var salt = crypto.getRandomValues(new Uint8Array(16));
  var hash = await pbkdf2Hash(password, salt);
  return bytesToBase64Url(salt) + '.' + bytesToBase64Url(hash);
}

async function verifyPassword(password, stored) {
  var parts = String(stored || '').split('.');
  if (parts.length !== 2) return false;
  var salt = base64UrlToBytes(parts[0]);
  var expected = base64UrlToBytes(parts[1]);
  var actual = await pbkdf2Hash(password, salt);
  if (actual.length !== expected.length) return false;
  var diff = 0;
  for (var i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

async function hmacSign(env, data) {
  var key = await crypto.subtle.importKey('raw', utf8ToBytes(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var sig = await crypto.subtle.sign('HMAC', key, utf8ToBytes(data));
  return bytesToBase64Url(new Uint8Array(sig));
}

async function signToken(env, payload) {
  var body = bytesToBase64Url(utf8ToBytes(JSON.stringify(payload)));
  var sig = await hmacSign(env, body);
  return body + '.' + sig;
}

async function verifyToken(env, token) {
  if (!token) return null;
  var parts = String(token).split('.');
  if (parts.length !== 2) return null;
  var expectedSig = await hmacSign(env, parts[0]);
  if (expectedSig !== parts[1]) return null;
  var payload;
  try { payload = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[0]))); } catch (e) { return null; }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

function getBearerToken(request) {
  var h = request.headers.get('Authorization') || '';
  var m = h.match(/^Bearer\s+(.+)$/);
  return m ? m[1] : null;
}

async function requireAuth(env, request) {
  var payload = await verifyToken(env, getBearerToken(request));
  if (!payload) return null;
  return payload;
}

/* ---------- GitHub Contents API ---------- */

function githubApiUrl(env, path) {
  return 'https://api.github.com/repos/' + env.GITHUB_OWNER + '/' + env.GITHUB_REPO + '/contents/' + path;
}

function githubHeaders(env) {
  return {
    'Authorization': 'token ' + env.GITHUB_TOKEN,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'ace-tech-haza-worker',
  };
}

// returns { data, sha } or { data: null, sha: null } if file doesn't exist yet
async function readJsonFile(env, path) {
  var res = await fetch(githubApiUrl(env, path) + '?ref=' + (env.DATA_BRANCH || 'main'), { headers: githubHeaders(env) });
  if (res.status === 404) return { data: null, sha: null };
  if (!res.ok) throw new Error('GitHub read failed (' + res.status + '): ' + path);
  var body = await res.json();
  var content = bytesToUtf8(base64UrlToBytesFromStandardBase64(body.content));
  return { data: JSON.parse(content), sha: body.sha };
}

// GitHub returns standard base64 (with newlines), not base64url — decode accordingly
function base64UrlToBytesFromStandardBase64(b64) {
  var clean = b64.replace(/\n/g, '');
  var bin = atob(clean);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function writeJsonFile(env, path, dataObj, message, sha) {
  var contentStr = JSON.stringify(dataObj, null, 2);
  var contentB64 = btoa(unescape(encodeURIComponent(contentStr)));
  var body = {
    message: message,
    content: contentB64,
    branch: env.DATA_BRANCH || 'main',
  };
  if (sha) body.sha = sha;
  var res = await fetch(githubApiUrl(env, path), {
    method: 'PUT',
    headers: Object.assign({ 'Content-Type': 'application/json' }, githubHeaders(env)),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    var errText = await res.text();
    throw new Error('GitHub write failed (' + res.status + '): ' + path + ' - ' + errText);
  }
  var result = await res.json();
  return result.content.sha;
}

/* ---------- 데이터 헬퍼 ---------- */

async function loadUsers(env) {
  var r = await readJsonFile(env, 'data/users.json');
  return { users: r.data || [], sha: r.sha };
}

function sanitizeSiteId(name) {
  var base = String(name || '').trim().toLowerCase()
    .replace(/[^a-z0-9가-힣\-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  return (base || 'site') + '-' + Math.random().toString(36).slice(2, 8);
}

/* ---------- 라우트 핸들러 ---------- */

async function handleLogin(env, request) {
  var body = await request.json().catch(function () { return {}; });
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!id || !password) return errorResponse(env, '아이디와 비밀번호를 입력하세요.', 400);

  var { users } = await loadUsers(env);
  var user = users.find(function (u) { return u.id === id; });
  if (!user) return errorResponse(env, '아이디 또는 비밀번호가 올바르지 않습니다.', 401);

  var ok = await verifyPassword(password, user.passwordHash);
  if (!ok) return errorResponse(env, '아이디 또는 비밀번호가 올바르지 않습니다.', 401);

  var token = await signToken(env, {
    uid: user.id, role: user.role, siteId: user.siteId, siteName: user.siteName,
    exp: Date.now() + 1000 * 60 * 60 * 12, // 12시간
  });
  return jsonResponse(env, { token: token, role: user.role, siteId: user.siteId, siteName: user.siteName });
}

// 최초 1회: users.json 이 저장소에 아직 없을 때만 동작 (첫 관리자 계정 생성)
async function handleBootstrapAdmin(env, request) {
  var { users, sha } = await loadUsers(env);
  if (users.length) return errorResponse(env, '이미 초기화되었습니다. 관리자 계정으로 로그인해 사용자를 추가하세요.', 403);

  var body = await request.json().catch(function () { return {}; });
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!id || !password) return errorResponse(env, '아이디와 비밀번호를 입력하세요.', 400);

  var passwordHash = await hashPassword(password);
  var adminUser = { id: id, passwordHash: passwordHash, role: 'admin', siteId: null, siteName: null, createdAt: new Date().toISOString() };
  await writeJsonFile(env, 'data/users.json', [adminUser], '최초 관리자 계정 생성: ' + id, sha);
  return jsonResponse(env, { ok: true });
}

async function handleCreateUser(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);

  var body = await request.json().catch(function () { return {}; });
  var siteName = String(body.siteName || '').trim();
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!siteName || !id || !password) return errorResponse(env, '사업소명, 아이디, 비밀번호를 모두 입력하세요.', 400);

  var { users, sha } = await loadUsers(env);
  if (users.some(function (u) { return u.id === id; })) return errorResponse(env, '이미 존재하는 아이디입니다.', 409);

  var siteId = sanitizeSiteId(siteName);
  var passwordHash = await hashPassword(password);
  var newUser = { id: id, passwordHash: passwordHash, role: 'user', siteId: siteId, siteName: siteName, createdAt: new Date().toISOString() };
  users.push(newUser);
  await writeJsonFile(env, 'data/users.json', users, '사용자 계정 생성: ' + id + ' (' + siteName + ')', sha);

  await writeJsonFile(env, 'data/sites/' + siteId + '/meta.json', { complexName: siteName, useApprovalDate: '', inspectionDate: '' }, '사업소 정보 초기화: ' + siteName, null);
  await writeJsonFile(env, 'data/sites/' + siteId + '/defects.json', [], '하자 목록 초기화: ' + siteName, null);

  return jsonResponse(env, { ok: true, siteId: siteId });
}

async function handleListUsers(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);

  var { users } = await loadUsers(env);
  var list = [];
  for (var i = 0; i < users.length; i++) {
    var u = users[i];
    if (u.role === 'admin') continue;
    var defectCount = 0;
    try {
      var r = await readJsonFile(env, 'data/sites/' + u.siteId + '/defects.json');
      defectCount = (r.data || []).length;
    } catch (e) { /* ignore, show 0 */ }
    list.push({ id: u.id, siteName: u.siteName, siteId: u.siteId, defectCount: defectCount, createdAt: u.createdAt });
  }
  return jsonResponse(env, { users: list });
}

async function handleGetMeta(env, request, url) {
  var auth = await requireAuth(env, request);
  if (!auth) return errorResponse(env, '로그인이 필요합니다.', 401);
  var siteId = (auth.role === 'admin' ? url.searchParams.get('siteId') : auth.siteId);
  if (!siteId) return errorResponse(env, 'siteId가 필요합니다.', 400);
  var r = await readJsonFile(env, 'data/sites/' + siteId + '/meta.json');
  return jsonResponse(env, { meta: r.data || { complexName: '', useApprovalDate: '', inspectionDate: '' } });
}

async function handleSaveMeta(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'user') return errorResponse(env, '사업소 계정만 사용할 수 있습니다.', 403);
  var body = await request.json().catch(function () { return {}; });
  var r = await readJsonFile(env, 'data/sites/' + auth.siteId + '/meta.json');
  var meta = {
    complexName: String(body.complexName || ''),
    useApprovalDate: String(body.useApprovalDate || ''),
    inspectionDate: String(body.inspectionDate || ''),
  };
  await writeJsonFile(env, 'data/sites/' + auth.siteId + '/meta.json', meta, '현장 정보 저장: ' + auth.siteId, r.sha);
  return jsonResponse(env, { ok: true });
}

async function handleGetDefects(env, request, url) {
  var auth = await requireAuth(env, request);
  if (!auth) return errorResponse(env, '로그인이 필요합니다.', 401);
  var siteId = (auth.role === 'admin' ? url.searchParams.get('siteId') : auth.siteId);
  if (!siteId) return errorResponse(env, 'siteId가 필요합니다.', 400);
  var r = await readJsonFile(env, 'data/sites/' + siteId + '/defects.json');
  return jsonResponse(env, { defects: r.data || [] });
}

async function handleImportDefects(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'user') return errorResponse(env, '사업소 계정만 사용할 수 있습니다.', 403);
  var body = await request.json().catch(function () { return {}; });
  var incoming = Array.isArray(body.defects) ? body.defects : [];
  if (!incoming.length) return errorResponse(env, '가져올 하자 목록이 없습니다.', 400);

  var r = await readJsonFile(env, 'data/sites/' + auth.siteId + '/defects.json');
  var existing = r.data || [];
  var nextId = existing.reduce(function (max, d) { return Math.max(max, d.id || 0); }, 0) + 1;
  var added = incoming.map(function (d) {
    return {
      id: nextId++,
      dong: String(d.dong || ''), ho: String(d.ho || ''), area: String(d.area || ''),
      defectType: String(d.defectType || '미분류'), severity: String(d.severity || '보통'),
      foundDate: String(d.foundDate || ''), description: String(d.description || ''),
      createdAt: new Date().toISOString(),
    };
  });
  var updated = existing.concat(added);
  await writeJsonFile(env, 'data/sites/' + auth.siteId + '/defects.json', updated, '하자 ' + added.length + '건 가져오기: ' + auth.siteId, r.sha);
  return jsonResponse(env, { ok: true, imported: added.length, total: updated.length });
}

/* ---------- 진입점 ---------- */

export default {
  async fetch(request, env) {
    var url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(env) });
    }
    try {
      if (url.pathname === '/api/login' && request.method === 'POST') return await handleLogin(env, request);
      if (url.pathname === '/api/bootstrap-admin' && request.method === 'POST') return await handleBootstrapAdmin(env, request);
      if (url.pathname === '/api/admin/users' && request.method === 'GET') return await handleListUsers(env, request);
      if (url.pathname === '/api/admin/users' && request.method === 'POST') return await handleCreateUser(env, request);
      if (url.pathname === '/api/site/meta' && request.method === 'GET') return await handleGetMeta(env, request, url);
      if (url.pathname === '/api/site/meta' && request.method === 'POST') return await handleSaveMeta(env, request);
      if (url.pathname === '/api/site/defects' && request.method === 'GET') return await handleGetDefects(env, request, url);
      if (url.pathname === '/api/site/defects/import' && request.method === 'POST') return await handleImportDefects(env, request);
      return errorResponse(env, 'Not found', 404);
    } catch (err) {
      return errorResponse(env, '서버 오류: ' + (err && err.message ? err.message : String(err)), 500);
    }
  },
};
