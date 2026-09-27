import { useState, useEffect, useCallback } from 'react';
import { api, setAccessToken, clearAccessToken } from './api.js';

// ─── Permission helpers ───────────────────────────────────────────────────────
// The console NEVER computes permissions — it reads what the server sends.
// These helpers just read the resolved set from /auth/me.
const allowed = (permissions, key) => permissions?.[key]?.effect === 'allow';

// ─── Login ────────────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [email, setEmail]     = useState('');
  const [password, setPass]   = useState('');
  const [error, setError]     = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    try {
      const { accessToken } = await api.login(email, password);
      setAccessToken(accessToken);
      onLogin();
    } catch (err) {
      // Same message for wrong email and wrong password — no enumeration oracle.
      setError(err.message ?? 'sign-in failed');
    }
  }

  return (
    <div style={{ maxWidth: 360, margin: '80px auto', padding: 24 }}>
      <h1>RemoteOps</h1>
      <form onSubmit={submit}>
        <input placeholder="email" value={email} onChange={e => setEmail(e.target.value)}
          style={{ display: 'block', width: '100%', marginBottom: 8 }} />
        <input type="password" placeholder="password" value={password}
          onChange={e => setPass(e.target.value)}
          style={{ display: 'block', width: '100%', marginBottom: 8 }} />
        <button type="submit" style={{ width: '100%' }}>Sign in</button>
      </form>
      {/* login-error stays on screen until the next attempt */}
      {error && (
        <p data-testid="login-error" style={{ color: 'red', marginTop: 8 }}>{error}</p>
      )}
    </div>
  );
}

// ─── Create Org modal ─────────────────────────────────────────────────────────
const THEMES = ['cobalt', 'amber', 'emerald', 'rose', 'violet'];

function CreateOrgModal({ onCreated, onClose }) {
  const [name, setName]   = useState('');
  const [theme, setTheme] = useState('cobalt');
  const [error, setError] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    try {
      await api.createOrg(name, theme);
      onCreated();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.4)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#fff', padding: 24, borderRadius: 8, minWidth: 320 }}>
        <h2>New organisation</h2>
        <form onSubmit={submit}>
          <input placeholder="Name" value={name} onChange={e => setName(e.target.value)}
            style={{ display: 'block', width: '100%', marginBottom: 8 }} />
          <select value={theme} onChange={e => setTheme(e.target.value)}
            style={{ display: 'block', width: '100%', marginBottom: 8 }}>
            {THEMES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          {error && <p style={{ color: 'red' }}>{error}</p>}
          <button type="submit">Create</button>
          <button type="button" onClick={onClose} style={{ marginLeft: 8 }}>Cancel</button>
        </form>
      </div>
    </div>
  );
}

// ─── Devices panel ────────────────────────────────────────────────────────────
function Devices({ orgId, permissions }) {
  const [devices, setDevices] = useState([]);
  const [error, setError]     = useState(null);
  const [sessionMsg, setMsg]  = useState(null);

  useEffect(() => {
    if (!allowed(permissions, 'device:list')) return;
    api.getDevices(orgId).then(d => setDevices(d.devices)).catch(e => setError(e.message));
  }, [orgId, permissions]);

  async function startSession(deviceId, mode) {
    setMsg(null);
    try {
      const { session } = await api.startSession(orgId, deviceId, mode);
      setMsg(`Session ${session.id} started`);
    } catch (err) {
      setMsg(err.message);
    }
  }

  if (!allowed(permissions, 'device:list')) return null;

  return (
    <section>
      <h2>Devices</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {sessionMsg && <p>{sessionMsg}</p>}
      <table>
        <thead><tr><th>Name</th><th>Kind</th><th>Online</th><th>Actions</th></tr></thead>
        <tbody>
          {devices.map(d => (
            <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
              <td>{d.name}</td>
              <td>{d.kind}</td>
              <td>{d.online ? '●' : '○'}</td>
              <td>
                {/* Buttons are present only when the resolved permission allows — never disabled */}
                {allowed(d.permissions, 'device:view') && allowed(d.permissions, 'session:start') && (
                  <button data-permission="device:view" data-state="unlocked"
                    onClick={() => startSession(d.id, 'view')}>View</button>
                )}
                {allowed(d.permissions, 'device:control') && allowed(d.permissions, 'session:start') && (
                  <button data-permission="device:control" data-state="unlocked"
                    onClick={() => startSession(d.id, 'control')}>Control</button>
                )}
                {allowed(d.permissions, 'device:terminal') && allowed(d.permissions, 'session:start') && (
                  <button data-permission="device:terminal" data-state="unlocked"
                    onClick={() => startSession(d.id, 'terminal')}>Terminal</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ─── People panel ─────────────────────────────────────────────────────────────
function People({ orgId, permissions }) {
  const [members, setMembers] = useState([]);

  useEffect(() => {
    if (!allowed(permissions, 'user:read')) return;
    api.getMembers(orgId).then(d => setMembers(d.members)).catch(() => {});
  }, [orgId, permissions]);

  if (!allowed(permissions, 'user:read')) return null;

  return (
    <section>
      <h2>People</h2>
      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th></tr></thead>
        <tbody>
          {members.map(m => (
            <tr key={m.id} data-testid="user-row" data-user-id={m.id}>
              <td>{m.name}</td><td>{m.email}</td><td>{m.role}</td><td>{m.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ─── Sessions panel ───────────────────────────────────────────────────────────
function Sessions({ orgId, permissions }) {
  const [sessions, setSessions] = useState([]);

  useEffect(() => {
    if (!allowed(permissions, 'session:view')) return;
    api.getSessions(orgId).then(d => setSessions(d.sessions)).catch(() => {});
  }, [orgId, permissions]);

  if (!allowed(permissions, 'session:view')) return null;

  return (
    <section>
      <h2>Sessions</h2>
      <table>
        <thead><tr><th>ID</th><th>Device</th><th>Mode</th><th>State</th></tr></thead>
        <tbody>
          {sessions.map(s => (
            <tr key={s.id}><td>{s.id}</td><td>{s.device_id}</td><td>{s.mode}</td><td>{s.state}</td></tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ─── Audit panel ──────────────────────────────────────────────────────────────
function Audit({ orgId, permissions }) {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    if (!allowed(permissions, 'audit:read')) return;
    api.getAudit(orgId).then(d => setEvents(d.events)).catch(() => {});
  }, [orgId, permissions]);

  if (!allowed(permissions, 'audit:read')) return null;

  return (
    <section>
      <h2>Audit Log</h2>
      <table>
        <thead><tr><th>Action</th><th>Result</th><th>At</th></tr></thead>
        <tbody>
          {events.map(e => (
            <tr key={e.id}><td>{e.action}</td><td>{e.result}</td><td>{e.at}</td></tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ─── Admin panel ──────────────────────────────────────────────────────────────
function Admin({ orgId, permissions }) {
  if (!allowed(permissions, 'org:update') && !allowed(permissions, 'org:delete')) return null;
  return (
    <section>
      <h2>Admin</h2>
      {allowed(permissions, 'org:update') && <p>Org settings available</p>}
      {allowed(permissions, 'org:delete') && <p style={{ color: 'red' }}>Delete org available</p>}
    </section>
  );
}

// ─── Nav ──────────────────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { key: 'devices',  label: 'Devices',  perm: 'device:list' },
  { key: 'people',   label: 'People',   perm: 'user:read' },
  { key: 'sessions', label: 'Sessions', perm: 'session:view' },
  { key: 'audit',    label: 'Audit',    perm: 'audit:read',  testid: 'nav-audit' },
  { key: 'admin',    label: 'Admin',    perm: 'org:update' },
];

// ─── Shell ────────────────────────────────────────────────────────────────────
// Theme colours — per-org, visually distinguishable at a glance.
const THEME_COLORS = {
  cobalt:  '#1e40af',
  amber:   '#b45309',
  emerald: '#065f46',
  rose:    '#9f1239',
  violet:  '#5b21b6',
};

export default function App() {
  const [authed, setAuthed]       = useState(false);
  const [me, setMe]               = useState(null);       // { user, org, role, orgs, permissions }
  const [activeOrg, setActiveOrg] = useState(null);       // full org object from me.orgs
  const [view, setView]           = useState('devices');
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError]         = useState(null);

  const loadMe = useCallback(async () => {
    try {
      const data = await api.me();
      setMe(data);
      setActiveOrg(data.orgs.find(o => o.id === data.org.id) ?? data.orgs[0]);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => { if (authed) loadMe(); }, [authed, loadMe]);

  async function switchOrg(orgId) {
    try {
      const { accessToken } = await api.switchOrg(orgId);
      setAccessToken(accessToken);
      await loadMe();
      setView('devices');
    } catch (err) {
      setError(err.message);
    }
  }

  function logout() {
    clearAccessToken();
    setAuthed(false);
    setMe(null);
  }

  if (!authed) return <Login onLogin={() => setAuthed(true)} />;
  if (!me) return <p>Loading…</p>;

  const theme     = activeOrg?.theme ?? 'cobalt';
  const themeColor = THEME_COLORS[theme] ?? '#1e40af';
  const perms     = me.permissions ?? {};

  return (
    // data-testid and data-org-* are what the test suite reads — do not remove.
    <div data-testid="app-shell" data-org-id={activeOrg?.id} data-org-theme={theme}
      style={{ fontFamily: 'sans-serif', minHeight: '100vh' }}>

      {/* Header — per-org accent colour makes the active org visually distinct */}
      <header style={{ background: themeColor, color: '#fff', padding: '12px 24px',
        display: 'flex', alignItems: 'center', gap: 16 }}>
        <strong>RemoteOps</strong>
        <span style={{ flex: 1 }}>{activeOrg?.name}</span>

        {/* Org switcher */}
        {me.orgs.map(o => (
          <button key={o.id} data-testid="org-option" data-org-id={o.id}
            onClick={() => switchOrg(o.id)}
            style={{
              background: o.id === activeOrg?.id ? 'rgba(255,255,255,.3)' : 'transparent',
              color: '#fff', border: '1px solid rgba(255,255,255,.5)',
              borderRadius: 4, padding: '4px 10px', cursor: 'pointer',
            }}>
            {o.name}
          </button>
        ))}

        {/* Create org — always available to authenticated users */}
        <button data-testid="create-org" onClick={() => setShowCreate(true)}
          style={{ background: 'rgba(255,255,255,.2)', color: '#fff',
            border: '1px solid rgba(255,255,255,.5)', borderRadius: 4,
            padding: '4px 10px', cursor: 'pointer' }}>
          + New org
        </button>

        <button onClick={logout} style={{ marginLeft: 'auto', color: '#fff',
          background: 'transparent', border: 'none', cursor: 'pointer' }}>
          Sign out
        </button>
      </header>

      <div style={{ display: 'flex', minHeight: 'calc(100vh - 52px)' }}>
        {/* Sidebar nav — items are present only when the permission allows */}
        <nav style={{ width: 180, background: '#f1f5f9', padding: 16 }}>
          <p style={{ fontSize: 12, color: '#64748b', marginBottom: 8 }}>
            {me.role} · {me.user.email}
          </p>
          {NAV_ITEMS.map(item => {
            if (!allowed(perms, item.perm)) return null;
            const testid = item.testid ?? `nav-${item.key}`;
            return (
              <button key={item.key}
                data-testid={testid}
                data-permission={item.perm}
                data-state="unlocked"
                onClick={() => setView(item.key)}
                style={{
                  display: 'block', width: '100%', textAlign: 'left',
                  padding: '8px 12px', marginBottom: 4, borderRadius: 4,
                  background: view === item.key ? themeColor : 'transparent',
                  color: view === item.key ? '#fff' : '#1e293b',
                  border: 'none', cursor: 'pointer',
                }}>
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Main content */}
        <main style={{ flex: 1, padding: 24 }}>
          {error && <p style={{ color: 'red' }}>{error}</p>}
          {view === 'devices'  && <Devices  orgId={activeOrg?.id} permissions={perms} />}
          {view === 'people'   && <People   orgId={activeOrg?.id} permissions={perms} />}
          {view === 'sessions' && <Sessions orgId={activeOrg?.id} permissions={perms} />}
          {view === 'audit'    && <Audit    orgId={activeOrg?.id} permissions={perms} />}
          {view === 'admin'    && <Admin    orgId={activeOrg?.id} permissions={perms} />}
        </main>
      </div>

      {showCreate && (
        <CreateOrgModal
          onCreated={async () => { setShowCreate(false); await loadMe(); }}
          onClose={() => setShowCreate(false)}
        />
      )}
    </div>
  );
}
