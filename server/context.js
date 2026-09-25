import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated } from './http.js';
export function authenticate(db, secret) {
  return function (req) { throw unauthenticated('not implemented'); };
}
export function assertOrgMatch(caller, orgId) {}
