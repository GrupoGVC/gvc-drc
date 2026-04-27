// ═══════════════════════════════════════════════════
// GVC DRC — API Client v2.0
// Substitui localStorage por chamadas ao backend PHP
// ═══════════════════════════════════════════════════

// ── CONFIGURE AQUI a URL da sua API no VPS ──────────
const API_BASE = 'https://api.drc-gvc.tech/api.php';
// ────────────────────────────────────────────────────

// Token armazenado em sessionStorage (não persiste entre abas diferentes)
const _getToken  = ()    => sessionStorage.getItem('gvc_token');
const _setToken  = (t)   => sessionStorage.setItem('gvc_token', t);
const _clearAuth = ()    => { sessionStorage.removeItem('gvc_token'); sessionStorage.removeItem('gvc_user'); };
const getUser    = ()    => { try { return JSON.parse(sessionStorage.getItem('gvc_user')); } catch { return null; } };

// ── Requisição base ──────────────────────────────────
async function _req(action, method = 'GET', body = null) {
  const url = `${API_BASE}?action=${action}`;
  const opts = {
    method,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${_getToken() || ''}`,
    },
  };
  if (body && method !== 'GET') opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const json = await res.json().catch(() => ({ ok: false, error: 'Resposta inválida do servidor' }));
  if (!json.ok) throw new Error(json.error || `Erro HTTP ${res.status}`);
  return json.data;
}

// ── Auth ─────────────────────────────────────────────
const GvcAuth = {
  async login(email, senha) {
    const data = await _req('login', 'POST', { email, senha });
    _setToken(data.token);
    sessionStorage.setItem('gvc_user', JSON.stringify({ nome: data.nome, role: data.role }));
    return data;
  },
  async logout() {
    try { await _req('logout', 'POST'); } catch {}
    _clearAuth();
    location.href = 'login.html';
  },
  async check() {
    const token = _getToken();
    if (!token) return null;
    try {
      const data = await _req('me', 'GET');
      sessionStorage.setItem('gvc_user', JSON.stringify(data));
      return data;
    } catch {
      _clearAuth();
      return null;
    }
  },
  isGestor()   { return getUser()?.role === 'gestor'; },
  isAnalista() { return getUser()?.role === 'analista'; },
  nome()       { return getUser()?.nome || ''; },
};

// ── DRCs ─────────────────────────────────────────────
const GvcDRC = {
  async list() {
    return await _req('list_drcs', 'GET');
  },
  async get(id) {
    return await _req(`get_drc&id=${encodeURIComponent(id)}`, 'GET');
  },
  async save(drc) {
    return await _req('save_drc', 'POST', { drc });
  },
  async delete(id) {
    return await _req(`delete_drc&id=${encodeURIComponent(id)}`, 'DELETE');
  },
  async contadores() {
    return await _req('contadores', 'GET');
  },
};

// ── Cadastros ────────────────────────────────────────
const GvcCadastros = {
  async get() {
    return await _req('get_cadastros', 'GET');
  },
  async save(cadastros) {
    return await _req('save_cadastros', 'POST', { cadastros });
  },
};

// ── Usuários ─────────────────────────────────────────
const GvcUsuarios = {
  async list() {
    return await _req('list_usuarios', 'GET');
  },
  async create(nome, email, senha, role) {
    return await _req('create_usuario', 'POST', { nome, email, senha, role });
  },
  async toggle(id) {
    return await _req('toggle_usuario', 'POST', { id });
  },
  async changeSenha(senha_atual, senha_nova) {
    return await _req('change_senha', 'POST', { senha_atual, senha_nova });
  },
};

// ── Guard de autenticação ────────────────────────────
// Chame no início de cada página protegida:
//   await requireAuth(['gestor']) — só gestores
//   await requireAuth()           — qualquer usuário logado
async function requireAuth(roles = []) {
  const user = await GvcAuth.check();
  if (!user) {
    location.href = 'login.html?next=' + encodeURIComponent(location.pathname + location.search);
    return null;
  }
  if (roles.length && !roles.includes(user.role)) {
    location.href = 'login.html?erro=acesso_negado';
    return null;
  }
  return user;
}
