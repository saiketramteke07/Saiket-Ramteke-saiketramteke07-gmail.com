// Turns a Bearer token into a verified caller object.
// Called once per authenticated request in server/index.js before the route handler runs.
//
// Returns: { caller: { userId, orgId, role, membership }, claims }
// Throws:  unauthenticated() or tokenStale() — both become 401 responses.
//
// Isolation guarantee (AUTH-DATA-MODEL.md §4): the token's `org` claim is the ONLY
// org this request can address. Cross-org resources are 404, not 403.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, forbidden, notFound } from './http.js';

// Middleware factory — returns a function that extracts and validates the caller.
// Used in server/index.js: `authenticate(db, secret)(req, params)`
export function authenticate(db, secret) {
  return function (req) {
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader.startsWith('Bearer ')) throw unauthenticated('missing Bearer token');

    const token = authHeader.slice(7);
    const claims = verifyAccessToken(token, secret);

    // Load the membership for (sub, org) — this is the freshness and status check.
    const membership = db.prepare(
      `SELECT role, status, perm_version FROM memberships
        WHERE org_id = ? AND user_id = ?`
    ).get(claims.org, claims.sub);

    // assertFresh throws TOKEN_STALE if perm_version has changed (AUTH-DATA-MODEL.md §3).
    assertFresh(claims, membership);

    // Suspended membership: token is structurally valid but the caller has no authority.
    if (membership.status === 'suspended') {
      throw forbidden('account suspended', 'suspended');
    }

    // Removed membership: treat as unauthenticated — the token is no longer valid here.
    if (membership.status !== 'active') {
      throw unauthenticated('membership is not active');
    }

    return {
      caller: {
        userId: claims.sub,
        orgId:  claims.org,
        role:   claims.role,
        membership,
      },
      claims,
    };
  };
}

// Route-level helper: assert the caller's active org matches the org in the URL.
// A mismatch is 404 — cross-org resources are invisible, not forbidden (PERMISSIONS.md §5).
export function assertOrgMatch(caller, orgId) {
  if (caller.orgId !== orgId) throw notFound();
}
