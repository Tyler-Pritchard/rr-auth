/**
 * Roles and Permissions
 *
 * Single source of truth for authorization in rr-auth.
 * - Roles are job titles assigned to users (stored on the User document).
 * - Permissions are capabilities that other services check (e.g. rr-events checks events:write).
 * Services should only ever check permissions, never role names.
 */

// Every permission in the system. Other services must use these exact strings.
const PERMISSIONS = Object.freeze({
  EVENTS_WRITE: 'events:write',
  INVENTORY_WRITE: 'inventory:write',
  CONTENT_WRITE: 'content:write',
  USERS_MANAGE: 'users:manage',
});

// Which permissions each role grants. Adding a new job title means adding one line here.
const ROLE_PERMISSIONS = Object.freeze({
  admin: Object.values(PERMISSIONS),              // everything
  tour_manager: [PERMISSIONS.EVENTS_WRITE],
  merch_manager: [PERMISSIONS.INVENTORY_WRITE],
  content_manager: [PERMISSIONS.CONTENT_WRITE],
});

// All valid role names, derived from the map above
const ROLES = Object.freeze(Object.keys(ROLE_PERMISSIONS));

/**
 * Combine the permissions for a user's roles into one de-duplicated, sorted list.
 * Unknown roles grant nothing (fail closed).
 * @param {string[]} roles
 * @returns {string[]}
 */
function permissionsForRoles(roles = []) {
  const permissions = new Set();
  for (const role of roles) {
    for (const permission of ROLE_PERMISSIONS[role] || []) {
      permissions.add(permission);
    }
  }
  return [...permissions].sort();
}

module.exports = { PERMISSIONS, ROLE_PERMISSIONS, ROLES, permissionsForRoles };