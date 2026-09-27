// All API calls in one place. Access token lives in memory — never localStorage.
// Errors are always thrown as { code, message, reason } so components can render them.

let _accessToken = null;

export function setAccessToken(t) { _accessToken = t; }
export function getAccessToken()  { return _accessToken; }
export function clearAccessToken() { _accessToken = null; }

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`;

  const res = await fetch(path, {
    method,
    headers,
    credentials: 'include', // sends the httpOnly refresh cookie
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const err = data?.error ?? {};
    throw Object.assign(new Error(err.message ?? 'request failed'), {
      code:   err.code,
      reason: err.reason,
      status: res.status,
    });
  }

  return data;
}

const get  = (path)        => request('GET',    path);
const post = (path, body)  => request('POST',   path, body);
const patch = (path, body) => request('PATCH',  path, body);
const del  = (path, body)  => request('DELETE', path, body);

export const api = {
  login:         (email, password)    => post('/v1/auth/login', { email, password }),
  refresh:       ()                   => post('/v1/auth/refresh'),
  switchOrg:     (orgId)              => post('/v1/auth/token', { orgId }),
  me:            ()                   => get('/v1/auth/me'),

  getOrgs:       ()                   => get('/v1/orgs'),
  createOrg:     (name, theme)        => post('/v1/orgs', { name, theme }),
  updateOrg:     (orgId, data)        => patch(`/v1/orgs/${orgId}`, data),
  deleteOrg:     (orgId)              => del(`/v1/orgs/${orgId}`),

  getMembers:    (orgId)              => get(`/v1/orgs/${orgId}/members`),
  changeRole:    (orgId, userId, role) => patch(`/v1/orgs/${orgId}/members/${userId}`, { role }),
  suspendMember: (orgId, userId)      => post(`/v1/orgs/${orgId}/members/${userId}/suspend`),
  reinstateMember:(orgId, userId)     => del(`/v1/orgs/${orgId}/members/${userId}/suspend`),
  removeMember:  (orgId, userId)      => del(`/v1/orgs/${orgId}/members/${userId}`),
  leaveOrg:      (orgId)              => del(`/v1/orgs/${orgId}/members/me`),

  createInvite:  (orgId, email, role) => post(`/v1/orgs/${orgId}/invites`, { email, role }),
  getInvites:    (orgId)              => get(`/v1/orgs/${orgId}/invites`),
  cancelInvite:  (orgId, id)          => del(`/v1/orgs/${orgId}/invites/${id}`),
  getInvite:     (token)              => get(`/v1/invites/${token}`),
  acceptInvite:  (token, name, password) => post(`/v1/invites/${token}/accept`, { name, password }),

  getDevices:    (orgId)              => get(`/v1/orgs/${orgId}/devices`),
  getDevice:     (orgId, id)          => get(`/v1/orgs/${orgId}/devices/${id}`),
  createDevice:  (orgId, data)        => post(`/v1/orgs/${orgId}/devices`, data),
  updateDevice:  (orgId, id, data)    => patch(`/v1/orgs/${orgId}/devices/${id}`, data),
  deleteDevice:  (orgId, id)          => del(`/v1/orgs/${orgId}/devices/${id}`),

  createGrant:   (orgId, data)        => post(`/v1/orgs/${orgId}/grants`, data),
  getGrants:     (orgId)              => get(`/v1/orgs/${orgId}/grants`),
  revokeGrant:   (orgId, id)          => del(`/v1/orgs/${orgId}/grants/${id}`),

  startSession:  (orgId, deviceId, mode) => post(`/v1/orgs/${orgId}/sessions`, { deviceId, mode }),
  getSessions:   (orgId)              => get(`/v1/orgs/${orgId}/sessions`),
  getSession:    (id)                 => get(`/v1/sessions/${id}`),
  endSession:    (id)                 => del(`/v1/sessions/${id}`),

  getEffective:  (orgId, userId)      => get(`/v1/orgs/${orgId}/users/${userId}/effective`),
  getAudit:      (orgId)              => get(`/v1/orgs/${orgId}/audit`),
};
