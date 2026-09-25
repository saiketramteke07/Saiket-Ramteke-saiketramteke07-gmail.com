// The one permission resolution engine. This is the ONLY place allow/deny is decided.
// PERMISSIONS.md §3 defines the algorithm; §4 defines the rules (D1-D10).
//
// Two public entry points:
//   resolve(db, { userId, orgId, deviceId? })
//     -> { role, permissions: { [key]: { effect, source, reason } } }
//
//   can(db, { userId, orgId }, permission, deviceId?)
//     -> boolean (throws nothing — callers gate on the result)
//
//   assertCanStartSession(db, { userId, orgId }, mode, deviceId)
//     -> void, or throws forbidden() with a specific reason string

import { forbidden } from './http.js';

// Expand a wildcard pattern to the concrete permission keys it covers.
// 'device:*' -> all device:* keys; '*' -> all keys; exact -> [exact].
function expandPattern(pattern, allPermissions) {
  if (pattern === '*') return allPermissions;
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // 'device:' 
    return allPermissions.filter(p => p.startsWith(prefix));
  }
  return [pattern];
}

// Load every concrete permission key from the DB (the single source of truth).
function loadAllPermissions(db) {
  return db.prepare('SELECT key FROM permissions').all().map(r => r.key);
}

// Load active, time-valid grants for a (user, org) pair.
// Filters out revoked, not-yet-started, and expired grants here in SQL
// so the resolution loop never sees stale data (D7).
function loadGrants(db, userId, orgId) {
  const now = new Date().toISOString();
  return db.prepare(`
    SELECT g.id, g.device_id, g.effect, gp.permission
    FROM grants g
    JOIN grant_permissions gp ON gp.grant_id = g.id
    WHERE g.user_id = ? AND g.org_id = ?
      AND g.revoked_at IS NULL
      AND (g.starts_at IS NULL OR g.starts_at <= ?)
      AND (g.expires_at IS NULL OR g.expires_at > ?)
  `).all(userId, orgId, now, now);
}

// Core resolution for a single (user, org, deviceId?) question.
// Returns { role, permissions: { [permKey]: { effect, source, reason } } }
export function resolve(db, { userId, orgId, deviceId = null }) {
  const allPermissions = loadAllPermissions(db);

  // Step 1: membership check — no membership means total deny with reason 'not_a_member'.
  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
  ).get(orgId, userId);

  if (!membership) {
    return {
      role: null,
      permissions: Object.fromEntries(
        allPermissions.map(p => [p, { effect: 'deny', source: null, reason: 'not_a_member' }])
      ),
    };
  }

  // Step 2: suspended/removed membership — empty permission set.
  if (membership.status === 'suspended') {
    return {
      role: membership.role,
      permissions: Object.fromEntries(
        allPermissions.map(p => [p, { effect: 'deny', source: null, reason: 'suspended' }])
      ),
    };
  }
  if (membership.status !== 'active') {
    return {
      role: membership.role,
      permissions: Object.fromEntries(
        allPermissions.map(p => [p, { effect: 'deny', source: null, reason: 'not_a_member' }])
      ),
    };
  }

  // Step 3: load role baseline — which permissions the role grants by default.
  const rolePerms = new Set(
    db.prepare(`SELECT permission FROM role_permissions WHERE role = ?`)
      .all(membership.role)
      .map(r => r.permission)
  );

  // Step 4: load active grants and expand wildcards into concrete permission keys.
  const rawGrants = loadGrants(db, userId, orgId);

  // Build two maps: deny grants and allow grants, keyed by permission.
  // A grant applies to a question if it is org-wide (device_id IS NULL)
  // or device-scoped to the exact device being asked about (D6).
  const denyGrants = {};  // permKey -> grant id (first explicit deny wins)
  const allowGrants = {}; // permKey -> grant id

  for (const row of rawGrants) {
    const appliesToDevice = row.device_id === null || row.device_id === deviceId;
    if (!appliesToDevice) continue;

    const keys = expandPattern(row.permission, allPermissions);
    for (const key of keys) {
      if (row.effect === 'deny' && !denyGrants[key]) {
        denyGrants[key] = row.id;
      } else if (row.effect === 'allow' && !allowGrants[key]) {
        allowGrants[key] = row.id;
      }
    }
  }

  // Step 5: resolve each permission using the algorithm from PERMISSIONS.md §3.
  //   D1: deny wins — any applicable deny beats everything, regardless of scope.
  //   D3: allow grant widens past the role baseline.
  //   D4: absent means denied, reported as implicit.
  const permissions = {};
  for (const perm of allPermissions) {
    if (denyGrants[perm]) {
      // D1: explicit deny always wins.
      permissions[perm] = { effect: 'deny', source: `grant:${denyGrants[perm]}`, reason: 'explicit_deny' };
    } else if (rolePerms.has(perm) || allowGrants[perm]) {
      // Role baseline or allow grant.
      const source = allowGrants[perm] ? `grant:${allowGrants[perm]}` : `role:${membership.role}`;
      permissions[perm] = { effect: 'allow', source, reason: null };
    } else {
      // D4: implicit deny — nobody granted this.
      permissions[perm] = { effect: 'deny', source: null, reason: 'implicit' };
    }
  }

  return { role: membership.role, permissions };
}

// Convenience: resolve once and check a single permission.
// deviceId is required for device-scoped permissions (D6).
export function can(db, { userId, orgId }, permission, deviceId = null) {
  const { permissions } = resolve(db, { userId, orgId, deviceId });
  return permissions[permission]?.effect === 'allow';
}

// Org-level view: union across all devices — used for nav gating.
// A permission is 'allow' at org level if it is allowed on ANY device in the org,
// or if it is a non-device permission that resolves to allow.
export function resolveOrgLevel(db, { userId, orgId }) {
  // For non-device permissions, a single resolve with no deviceId is correct.
  // For device permissions, we take the union: allowed on any device = allowed at org level.
  const base = resolve(db, { userId, orgId, deviceId: null });

  const devices = db.prepare(
    `SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL`
  ).all(orgId);

  if (devices.length === 0) return base;

  // Merge: if any device resolves allow for a permission, org-level is allow.
  const merged = { ...base.permissions };
  for (const { id: deviceId } of devices) {
    const { permissions } = resolve(db, { userId, orgId, deviceId });
    for (const [perm, result] of Object.entries(permissions)) {
      if (result.effect === 'allow' && merged[perm].effect !== 'allow') {
        merged[perm] = result;
      }
    }
  }

  return { role: base.role, permissions: merged };
}

// Session start requires TWO independent permissions on the same device (AUTH-DATA-MODEL.md §9).
// The reason strings are what the shipped tests assert — do not change them.
const MODE_DEVICE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

export function assertCanStartSession(db, { userId, orgId }, mode, deviceId) {
  const { permissions } = resolve(db, { userId, orgId, deviceId });

  const hasStart = permissions['session:start']?.effect === 'allow';
  const devicePerm = MODE_DEVICE_PERMISSION[mode];
  const hasDevice = permissions[devicePerm]?.effect === 'allow';

  // Report which permission was missing — the caller needs to distinguish the two.
  if (!hasStart) throw forbidden('missing session:start permission', 'missing_permission');
  if (!hasDevice) throw forbidden(`missing ${devicePerm} permission`, 'missing_device_permission');
}
