import { Given, When, Then, Before, After } from '@cucumber/cucumber';
import { Page, Browser, BrowserContext, chromium, expect } from '@playwright/test';
import { BasePage } from '../pages/BasePage';
import { HomePage } from '../pages/HomePage';
import { GenericActions } from '../utils/GenericActions';
import { AssertionHelpers } from '../utils/AssertionHelpers';
import { WaitHelpers } from '../utils/WaitHelpers';

// TODO: Replace with Object Repository when available
// import { LOCATORS } from '../object-repository/locators';

let browser: Browser;
let context: BrowserContext;
let page: Page;
let basePage: BasePage;
let homePage: HomePage;
let actions: GenericActions;
let assertions: AssertionHelpers;
let waits: WaitHelpers;

Before(async function () {
  browser = await chromium.launch({ headless: process.env.HEADLESS !== 'false' });
  context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,
  });
  page = await context.newPage();
  
  actions = new GenericActions(page, context);
  assertions = new AssertionHelpers(page);
  waits = new WaitHelpers(page);
  
  basePage = new BasePage(page, context);
  homePage = new HomePage(page, context);
  
  this.testData = {
    users: {
      admin: { username: 'admin', password: 'admin123' },
      nonadmin: { username: 'testuser', password: 'testpass' },
      departmentAAdmin: { username: 'deptA_admin', password: 'deptA123' }
    },
    apiTokens: {},
    apiResponses: {},
    roleIds: {},
    auditLogBaseline: null,
    requestTimestamps: {}
  };
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await page.screenshot();
    this.attach(screenshot, 'image/png');
  }
  await page.close();
  await context.close();
  await browser.close();
});

// ==================== GIVEN STEPS ====================

/**************************************************/
/*  SHARED SETUP STEPS
/*  Category: Background
/**************************************************/

Given('application is deployed and accessible', async function () {
  await homePage.navigate();
  await waits.waitForNetworkIdle();
  await assertions.assertVisible(page.locator('//body'));
});

Given('audit logging system is enabled and operational', async function () {
  const response = await page.request.get('/api/system/audit/status');
  expect(response.status()).toBe(200);
  const data = await response.json();
  expect(data.enabled).toBe(true);
});

/**************************************************/
/*  TEST CASE: TC-SEC-001
/*  Title: Non-admin user cannot assign permissions via direct API call
/*  Priority: Critical
/*  Category: Security - Elevation of Privilege
/**************************************************/

Given('test user account with non-admin role exists and is authenticated', async function () {
  const response = await page.request.post('/api/auth/login', {
    data: {
      username: this.testData.users.nonadmin.username,
      password: this.testData.users.nonadmin.password
    }
  });
  expect(response.status()).toBe(200);
  const data = await response.json();
  this.testData.apiTokens.nonadmin = data.token;
});

Given('valid role ID exists in the system', async function () {
  const response = await page.request.get('/api/roles');
  expect(response.status()).toBe(200);
  const roles = await response.json();
  this.testData.roleIds.validRole = roles[0]?.id || 'role-123';
});

/**************************************************/
/*  TEST CASE: TC-SEC-002
/*  Title: SQL injection attempts in permission assignment are blocked
/*  Priority: Critical
/*  Category: Security - SQL Injection
/**************************************************/

Given('administrator account is authenticated', async function () {
  const response = await page.request.post('/api/auth/login', {
    data: {
      username: this.testData.users.admin.username,
      password: this.testData.users.admin.password
    }
  });
  expect(response.status()).toBe(200);
  const data = await response.json();
  this.testData.apiTokens.admin = data.token;
});

Given('permission assignment API endpoint is accessible', async function () {
  const response = await page.request.options('/api/roles/test/permissions', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  expect([200, 204]).toContain(response.status());
});

Given('database contains multiple roles and permissions', async function () {
  const rolesResponse = await page.request.get('/api/roles', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  const permissionsResponse = await page.request.get('/api/permissions', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  expect(rolesResponse.status()).toBe(200);
  expect(permissionsResponse.status()).toBe(200);
  const roles = await rolesResponse.json();
  const permissions = await permissionsResponse.json();
  expect(roles.length).toBeGreaterThan(0);
  expect(permissions.length).toBeGreaterThan(0);
});

/**************************************************/
/*  TEST CASE: TC-SEC-003
/*  Title: Administrator cannot modify permissions for roles outside their scope
/*  Priority: Critical
/*  Category: Security - Authorization IDOR
/**************************************************/

Given('multi-tenant role structure exists', async function () {
  const response = await page.request.get('/api/system/tenants');
  expect(response.status()).toBe(200);
  const tenants = await response.json();
  expect(tenants.length).toBeGreaterThan(1);
});

Given('administrator account with limited scope for {string} is created', async function (department: string) {
  const response = await page.request.post('/api/auth/login', {
    data: {
      username: this.testData.users.departmentAAdmin.username,
      password: this.testData.users.departmentAAdmin.password
    }
  });
  expect(response.status()).toBe(200);
  const data = await response.json();
  this.testData.apiTokens.departmentAAdmin = data.token;
  this.testData.departmentScope = department;
});

Given('role exists in {string} with ID {string}', async function (department: string, roleId: string) {
  if (department === 'Department A') {
    this.testData.roleIds.departmentA = roleId;
  } else if (department === 'Department B') {
    this.testData.roleIds.departmentB = roleId;
  }
});

Given('authorization boundaries are defined in the system', async function () {
  const response = await page.request.get('/api/system/authorization/boundaries', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.departmentAAdmin}` }
  });
  expect(response.status()).toBe(200);
});

/**************************************************/
/*  TEST CASE: TC-SEC-004
/*  Title: Permission assignment creates comprehensive immutable audit trail
/*  Priority: High
/*  Category: Security - Audit Non-Repudiation
/**************************************************/

Given('administrator account {string} is authenticated', async function (email: string) {
  const response = await page.request.post('/api/auth/login', {
    data: {
      username: email,
      password: this.testData.users.admin.password
    }
  });
  expect(response.status()).toBe(200);
  const data = await response.json();
  this.testData.apiTokens.adminEmail = data.token;
  this.testData.adminEmail = email;
});

Given('multiple roles with different permission sets exist', async function () {
  const response = await page.request.get('/api/roles', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` }
  });
  expect(response.status()).toBe(200);
  const roles = await response.json();
  expect(roles.length).toBeGreaterThan(1);
});

Given('baseline audit log state is captured', async function () {
  const response = await page.request.get('/api/audit/logs', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` }
  });
  expect(response.status()).toBe(200);
  this.testData.auditLogBaseline = await response.json();
});

// ==================== WHEN STEPS ====================

/**************************************************/
/*  SHARED ACTION STEPS
/*  Category: Common Actions
/**************************************************/

When('user authenticates as {string}', async function (userType: string) {
  const userKey = userType.toLowerCase().replace(/\s+/g, '').replace('-', '');
  const credentials = this.testData.users[userKey] || this.testData.users.nonadmin;
  const response = await page.request.post('/api/auth/login', {
    data: {
      username: credentials.username,
      password: credentials.password
    }
  });
  this.testData.apiResponses.auth = response;
  if (response.status() === 200) {
    const data = await response.json();
    this.testData.apiTokens.current = data.token;
  }
});

When('user captures authentication token', async function () {
  if (this.testData.apiResponses.auth) {
    const data = await this.testData.apiResponses.auth.json();
    this.testData.apiTokens.captured = data.token;
  }
});

When('user sends POST request to {string} endpoint with non-admin token', async function (endpoint: string) {
  const url = endpoint.replace('{valid_role_id}', this.testData.roleIds.validRole);
  const response = await page.request.post(url, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.nonadmin}` },
    data: { permissions: [] }
  });
  this.testData.apiResponses.permissionAssignment = response;
});

When('request contains permission payload with {string} and {string} permissions', async function (perm1: string, perm2: string) {
  const url = `/api/roles/${this.testData.roleIds.validRole}/permissions`;
  const response = await page.request.post(url, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.nonadmin}` },
    data: { permissions: [perm1, perm2] }
  });
  this.testData.apiResponses.permissionAssignment = response;
});

When('user attempts to modify Authorization header by tampering with token', async function () {
  const originalToken = this.testData.apiTokens.nonadmin;
  this.testData.apiTokens.tampered = originalToken + 'TAMPERED';
});

When('user resends the request with tampered token', async function () {
  const url = `/api/roles/${this.testData.roleIds.validRole}/permissions`;
  const response = await page.request.post(url, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.tampered}` },
    data: { permissions: ['DELETE_USER', 'MODIFY_ROLES'] }
  });
  this.testData.apiResponses.tamperedRequest = response;
});

When('user verifies database for permission assignments on target role', async function () {
  const response = await page.request.get(`/api/roles/${this.testData.roleIds.validRole}/permissions`, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  this.testData.apiResponses.rolePermissions = response;
});

When('user checks security audit logs for attempted unauthorized access', async function () {
  const response = await page.request.get('/api/audit/logs?event=PERMISSION_ASSIGNMENT_ATTEMPT', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  this.testData.apiResponses.auditLogs = response;
});

When('administrator authenticates and obtains valid admin token', async function () {
  const response = await page.request.post('/api/auth/login', {
    data: {
      username: this.testData.users.admin.username,
      password: this.testData.users.admin.password
    }
  });
  expect(response.status()).toBe(200);
  const data = await response.json();
  this.testData.apiTokens.admin = data.token;
});

When('administrator sends POST request to {string} endpoint', async function (endpoint: string) {
  const response = await page.request.post(endpoint, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` },
    data: { permissions: [] }
  });
  this.testData.apiResponses.sqlInjection = response;
});

When('request contains permission payload with {string} permission', async function (permissionName: string) {
  this.testData.maliciousPermission = permissionName;
});

When('administrator verifies database integrity', async function () {
  const response = await page.request.get('/api/system/database/integrity', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  this.testData.apiResponses.dbIntegrity = response;
});

When('administrator authenticates as {string} administrator', async function (department: string) {
  const response = await page.request.post('/api/auth/login', {
    data: {
      username: this.testData.users.departmentAAdmin.username,
      password: this.testData.users.departmentAAdmin.password
    }
  });
  expect(response.status()).toBe(200);
  const data = await response.json();
  this.testData.apiTokens.currentAdmin = data.token;
});

When('administrator captures authentication token', async function () {
  this.testData.apiTokens.captured = this.testData.apiTokens.currentAdmin;
});

When('administrator identifies authorized role ID {string} from {string}', async function (roleId: string, department: string) {
  this.testData.roleIds.authorized = roleId;
});

When('administrator identifies unauthorized role ID {string} from {string}', async function (roleId: string, department: string) {
  this.testData.roleIds.unauthorized = roleId;
});

When('administrator sends POST request to {string} endpoint with {string} admin token', async function (endpoint: string, department: string) {
  const response = await page.request.post(endpoint, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.currentAdmin}` },
    data: { permissions: ['READ_DATA', 'WRITE_DATA'] }
  });
  this.testData.apiResponses.authorizedAssignment = response;
});

When('request contains valid permission payload', async function () {
  this.testData.permissionPayload = { permissions: ['READ_DATA', 'WRITE_DATA'] };
});

When('administrator attempts to assign permissions to {string} role', async function (department: string) {
  const roleId = department === 'Department B' ? this.testData.roleIds.departmentB : this.testData.roleIds.departmentA;
  const response = await page.request.post(`/api/roles/${roleId}/permissions`, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.currentAdmin}` },
    data: { permissions: ['READ_DATA', 'WRITE_DATA'] }
  });
  this.testData.apiResponses.unauthorizedAssignment = response;
});

When('administrator sends POST request to {string} endpoint with same token', async function (endpoint: string) {
  const response = await page.request.post(endpoint, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.currentAdmin}` },
    data: { permissions: ['READ_DATA', 'WRITE_DATA'] }
  });
  this.testData.apiResponses.unauthorizedAssignment = response;
});

When('administrator verifies database for {string} role permissions', async function (department: string) {
  const roleId = this.testData.roleIds.departmentB;
  const response = await page.request.get(`/api/roles/${roleId}/permissions`, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  this.testData.apiResponses.departmentBPermissions = response;
});

When('administrator checks audit logs for unauthorized access attempt', async function () {
  const response = await page.request.get('/api/audit/logs?event=UNAUTHORIZED_PERMISSION_ASSIGNMENT', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  this.testData.apiResponses.unauthorizedAuditLogs = response;
});

When('administrator authenticates as {string}', async function (email: string) {
  const response = await page.request.post('/api/auth/login', {
    data: {
      username: email,
      password: this.testData.users.admin.password
    }
  });
  expect(response.status()).toBe(200);
  const data = await response.json();
  this.testData.apiTokens.adminEmail = data.token;
  this.testData.adminEmail = email;
});

When('administrator records authentication timestamp', async function () {
  this.testData.requestTimestamps.auth = new Date().toISOString();
});

When('administrator assigns permissions {string} and {string} to role {string}', async function (perm1: string, perm2: string, roleName: string) {
  this.testData.assignedPermissions = [perm1, perm2];
  this.testData.targetRoleName = roleName;
});

When('administrator sends POST request to {string} endpoint', async function (endpoint: string) {
  const response = await page.request.post(endpoint, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` },
    data: { permissions: this.testData.assignedPermissions }
  });
  this.testData.apiResponses.permissionAssignment = response;
});

When('administrator notes exact timestamp of request', async function () {
  this.testData.requestTimestamps.permissionAssignment = new Date().toISOString();
});

When('administrator queries audit logs for permission assignment event', async function () {
  const response = await page.request.get('/api/audit/logs?event=PERMISSION_ASSIGNMENT', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` }
  });
  this.testData.apiResponses.auditLogs = response;
});

When('administrator attempts to modify audit log entry using administrator privileges', async function () {
  const logs = await this.testData.apiResponses.auditLogs.json();
  const logId = logs[0]?.id;
  const response = await page.request.put(`/api/audit/logs/${logId}`, {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` },
    data: { modified: true }
  });
  this.testData.apiResponses.auditModification = response;
});

When('administrator performs conflicting permission assignment to same role', async function () {
  const response = await page.request.post('/api/roles/manager-role-id/permissions', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` },
    data: { permissions: ['CONFLICTING_PERMISSION'] }
  });
  this.testData.apiResponses.conflictingAssignment = response;
});

When('administrator verifies log integrity using cryptographic signatures', async function () {
  const response = await page.request.get('/api/audit/logs/verify-integrity', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` }
  });
  this.testData.apiResponses.logIntegrity = response;
});

When('administrator exports audit logs for compliance reporting', async function () {
  const response = await page.request.get('/api/audit/logs/export', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` }
  });
  this.testData.apiResponses.auditExport = response;
});

// ==================== THEN STEPS ====================

/**************************************************/
/*  SHARED ASSERTION STEPS
/*  Category: Common Assertions
/**************************************************/

Then('API should return {string} status code', async function (statusCode: string) {
  const response = this.testData.apiResponses.permissionAssignment || 
                   this.testData.apiResponses.tamperedRequest || 
                   this.testData.apiResponses.sqlInjection ||
                   this.testData.apiResponses.authorizedAssignment ||
                   this.testData.apiResponses.unauthorizedAssignment;
  expect(response.status()).toBe(parseInt(statusCode));
});

Then('error message indicating insufficient privileges should be displayed', async function () {
  const response = this.testData.apiResponses.permissionAssignment;
  const data = await response.json();
  expect(data.error).toContain('insufficient privileges');
});

Then('token validation failure message should be displayed', async function () {
  const response = this.testData.apiResponses.tamperedRequest;
  const data = await response.json();
  expect(data.error).toContain('token validation');
});

Then('no unauthorized permission changes should be persisted in database', async function () {
  const response = this.testData.apiResponses.rolePermissions;
  const data = await response.json();
  expect(data.permissions).not.toContain('DELETE_USER');
  expect(data.permissions).not.toContain('MODIFY_ROLES');
});

Then('security log should contain entry with timestamp and user ID', async function () {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs.length).toBeGreaterThan(0);
  expect(logs[0]).toHaveProperty('timestamp');
  expect(logs[0]).toHaveProperty('userId');
});

Then('log entry should show attempted action with {string} status', async function (status: string) {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0].status).toBe(status);
});

Then('{string} error should be displayed', async function (errorType: string) {
  const response = this.testData.apiResponses.sqlInjection;
  const data = await response.json();
  expect(data.error).toContain(errorType.replace(' error', ''));
});

Then('no SQL query should be executed with malicious input', async function () {
  const response = this.testData.apiResponses.dbIntegrity;
  expect(response.status()).toBe(200);
});

Then('all database tables should exist', async function () {
  const response = this.testData.apiResponses.dbIntegrity;
  const data = await response.json();
  expect(data.tablesIntact).toBe(true);
});

Then('no unauthorized data modifications should be present', async function () {
  const response = this.testData.apiResponses.dbIntegrity;
  const data = await response.json();
  expect(data.unauthorizedModifications).toBe(false);
});

Then('permissions table structure should be unchanged', async function () {
  const response = this.testData.apiResponses.dbIntegrity;
  const data = await response.json();
  expect(data.permissionsTableIntact).toBe(true);
});

Then('all injection attempts should be logged as security events', async function () {
  const response = await page.request.get('/api/audit/logs?event=SQL_INJECTION_ATTEMPT', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.admin}` }
  });
  const logs = await response.json();
  expect(logs.length).toBeGreaterThan(0);
});

Then('permissions should be successfully assigned to {string} role', async function (department: string) {
  const response = this.testData.apiResponses.authorizedAssignment;
  const data = await response.json();
  expect(data.success).toBe(true);
});

Then('confirmation message should be displayed', async function () {
  const response = this.testData.apiResponses.authorizedAssignment || this.testData.apiResponses.permissionAssignment;
  const data = await response.json();
  expect(data.message).toBeTruthy();
});

Then('error message {string} should be displayed', async function (errorMessage: string) {
  const response = this.testData.apiResponses.unauthorizedAssignment;
  const data = await response.json();
  expect(data.error).toContain(errorMessage);
});

Then('{string} role permissions should remain unchanged', async function (department: string) {
  const response = this.testData.apiResponses.departmentBPermissions;
  const originalData = await response.json();
  expect(originalData.modified).toBe(false);
});

Then('audit log should contain entry with {string} admin ID', async function (department: string) {
  const response = this.testData.apiResponses.unauthorizedAuditLogs;
  const logs = await response.json();
  expect(logs[0]).toHaveProperty('adminId');
});

Then('log entry should show attempted role ID {string}', async function (roleId: string) {
  const response = this.testData.apiResponses.unauthorizedAuditLogs;
  const logs = await response.json();
  expect(logs[0].targetRoleId).toBe(roleId);
});

Then('log entry should show action {string} with status {string}', async function (action: string, status: string) {
  const response = this.testData.apiResponses.unauthorizedAuditLogs || this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0].action).toBe(action);
  expect(logs[0].status).toBe(status);
});

Then('audit log entry should exist with user ID {string}', async function (userId: string) {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs.some((log: any) => log.userId === userId)).toBe(true);
});

Then('audit log entry should contain username {string}', async function (username: string) {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0].username).toBe(username);
});

Then('audit log entry should contain role ID {string}', async function (roleId: string) {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0].roleId).toBe(roleId);
});

Then('audit log entry should contain role name {string}', async function (roleName: string) {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0].roleName).toBe(roleName);
});

Then('audit log entry should contain permissions added {string} and {string}', async function (perm1: string, perm2: string) {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0].permissionsAdded).toContain(perm1);
  expect(logs[0].permissionsAdded).toContain(perm2);
});

Then('audit log entry should contain timestamp in ISO 8601 format', async function () {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
  expect(iso8601Regex.test(logs[0].timestamp)).toBe(true);
});

Then('audit log entry should contain source IP address', async function () {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0]).toHaveProperty('sourceIp');
});

Then('audit log entry should contain user agent', async function () {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0]).toHaveProperty('userAgent');
});

Then('audit log entry should contain action result {string}', async function (result: string) {
  const response = this.testData.apiResponses.auditLogs;
  const logs = await response.json();
  expect(logs[0].result).toBe(result);
});

Then('audit log entry cannot be modified', async function () {
  const response = this.testData.apiResponses.auditModification;
  expect([403, 405]).toContain(response.status());
});

Then('system should prevent tampering with appropriate error message', async function () {
  const response = this.testData.apiResponses.auditModification;
  const data = await response.json();
  expect(data.error).toContain('cannot be modified');
});

Then('audit log should contain entry for failed assignment', async function () {
  const response = await page.request.get('/api/audit/logs?result=FAILED', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` }
  });
  const logs = await response.json();
  expect(logs.length).toBeGreaterThan(0);
});

Then('log entry should contain error reason {string}', async function (reason: string) {
  const response = await page.request.get('/api/audit/logs?result=FAILED', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` }
  });
  const logs = await response.json();
  expect(logs[0].errorReason).toContain(reason);
});

Then('log entry should contain permissions attempted', async function () {
  const response = await page.request.get('/api/audit/logs?result=FAILED', {
    headers: { 'Authorization': `Bearer ${this.testData.apiTokens.adminEmail}` }
  });
  const logs = await response.json();
  expect(logs[0]).toHaveProperty('permissionsAttempted');
});

Then('log integrity verification should pass', async function () {
  const response = this.testData.apiResponses.logIntegrity;
  const data = await response.json();
  expect(data.integrityValid).toBe(true);
});

Then('no tampering should be detected', async function () {
  const response = this.testData.apiResponses.logIntegrity;
  const data = await response.json();
  expect(data.tamperingDetected).toBe(false);
});

Then('audit logs should be exported in standard format', async function () {
  const response = this.testData.apiResponses.auditExport;
  expect(response.status()).toBe(200);
  const contentType = response.headers()['content-type'];
  expect(['application/json', 'text/csv']).toContain(contentType);
});

Then('all permission assignment events should be included with complete metadata', async function () {
  const response = this.testData.apiResponses.auditExport;
  const exportData = await response.json();
  expect(exportData.events.length).toBeGreaterThan(0);
  expect(exportData.events[0]).toHaveProperty('timestamp');
  expect(exportData.events[0]).toHaveProperty('userId');
  expect(exportData.events[0]).toHaveProperty('action');
  expect(exportData.events[0]).toHaveProperty('result');
});