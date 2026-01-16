import { test, expect } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/api';

test.describe('Compliance Manager - GDPR and HIPAA Compliance', () => {
  let unauthorizedToken: string;
  let authorizedToken: string;
  let adminToken: string;
  let testEmployeeId: string;

  test.beforeAll(async ({ request }) => {
    // Setup test tokens and test employee
    const unauthorizedResponse = await request.post(`${API_BASE_URL}/auth/login`, {
      data: { username: 'unauthorized_user', password: 'test123' }
    });
    unauthorizedToken = (await unauthorizedResponse.json()).token;

    const authorizedResponse = await request.post(`${API_BASE_URL}/auth/login`, {
      data: { username: 'readonly_user', password: 'test123' }
    });
    authorizedToken = (await authorizedResponse.json()).token;

    const adminResponse = await request.post(`${API_BASE_URL}/auth/login`, {
      data: { username: 'admin_user', password: 'admin123' }
    });
    adminToken = (await adminResponse.json()).token;

    testEmployeeId = 'test-emp-12345';
  });

  test('Validate enforcement of data minimization and access controls', async ({ page, request }) => {
    // Step 1: Attempt unauthorized API data access to employee endpoint
    const unauthorizedEmployeeResponse = await request.get(`${API_BASE_URL}/employees/${testEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${unauthorizedToken}` }
    });
    expect(unauthorizedEmployeeResponse.status()).toBe(403);
    const unauthorizedEmployeeBody = await unauthorizedEmployeeResponse.json();
    expect(unauthorizedEmployeeBody.error).toContain('Access denied');

    // Step 2: Attempt unauthorized access to timekeeping data
    const unauthorizedTimekeepingResponse = await request.get(`${API_BASE_URL}/timekeeping/records`, {
      headers: { 'Authorization': `Bearer ${unauthorizedToken}` }
    });
    expect(unauthorizedTimekeepingResponse.status()).toBe(403);

    // Step 3: Navigate to audit logs and verify unauthorized access attempts are logged
    await page.goto(`${BASE_URL}/compliance/audit-logs`);
    await page.fill('[data-testid="audit-log-search"]', 'unauthorized_user');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-entry"]');
    const logEntries = await page.locator('[data-testid="audit-log-entry"]').count();
    expect(logEntries).toBeGreaterThanOrEqual(2);
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Access denied');

    // Step 4: Access data with authorized credentials
    const authorizedResponse = await request.get(`${API_BASE_URL}/employees/${testEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${authorizedToken}` }
    });
    expect(authorizedResponse.status()).toBe(200);
    const authorizedData = await authorizedResponse.json();
    expect(authorizedData).toHaveProperty('id');
    expect(authorizedData).toHaveProperty('name');

    // Step 5: Verify data minimization - response contains only necessary fields
    expect(authorizedData).not.toHaveProperty('ssn');
    expect(authorizedData).not.toHaveProperty('salary');
    expect(authorizedData).not.toHaveProperty('health_data');

    // Step 6: Attempt to access fields beyond granted permissions
    const overreachResponse = await request.get(`${API_BASE_URL}/employees/${testEmployeeId}?fields=ssn,salary`, {
      headers: { 'Authorization': `Bearer ${authorizedToken}` }
    });
    expect(overreachResponse.status()).toBe(403);

    // Step 7: Admin access to complete employee record
    const adminResponse = await request.get(`${API_BASE_URL}/employees/${testEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    expect(adminResponse.status()).toBe(200);
    const adminData = await adminResponse.json();
    expect(adminData).toHaveProperty('ssn');
    expect(adminData).toHaveProperty('salary');

    // Step 8: Review audit logs for all access attempts
    await page.goto(`${BASE_URL}/compliance/audit-logs`);
    await page.fill('[data-testid="audit-log-date-from"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-entry"]');
    const allLogEntries = await page.locator('[data-testid="audit-log-entry"]').count();
    expect(allLogEntries).toBeGreaterThanOrEqual(4);

    // Step 9: Generate access control compliance report
    await page.goto(`${BASE_URL}/compliance/dashboard`);
    await page.click('[data-testid="generate-report-button"]');
    await page.selectOption('[data-testid="report-type-select"]', 'access-control');
    await page.fill('[data-testid="report-date-from"]', new Date().toISOString().split('T')[0]);
    await page.fill('[data-testid="report-date-to"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="generate-button"]');
    await page.waitForSelector('[data-testid="report-generated"]', { timeout: 10000 });
    await expect(page.locator('[data-testid="report-status"]')).toContainText('Report generated successfully');
  });

  test('Test encryption of sensitive data in transit and storage', async ({ page, request, context }) => {
    // Step 1-3: Make API call and verify HTTPS encryption
    const employeeResponse = await request.get(`${API_BASE_URL}/employees/${testEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    expect(employeeResponse.status()).toBe(200);
    expect(employeeResponse.url()).toContain('https');

    // Step 4: Verify no plaintext sensitive data in transit (simulated check)
    const responseHeaders = employeeResponse.headers();
    expect(responseHeaders['content-type']).toContain('application/json');
    expect(responseHeaders['strict-transport-security']).toBeDefined();

    // Step 5-6: Create new employee record with sensitive information
    const newEmployeeData = {
      name: 'Test Employee Encryption',
      email: 'test.encryption@example.com',
      ssn: '123-45-6789',
      salary: 75000,
      health_data: 'Sensitive health information'
    };
    const createResponse = await request.post(`${API_BASE_URL}/employees`, {
      headers: { 'Authorization': `Bearer ${adminToken}` },
      data: newEmployeeData
    });
    expect(createResponse.status()).toBe(201);
    const createdEmployee = await createResponse.json();
    const newEmployeeId = createdEmployee.id;

    // Step 7-9: Navigate to encryption verification page
    await page.goto(`${BASE_URL}/compliance/encryption-status`);
    await page.waitForSelector('[data-testid="encryption-dashboard"]');
    await expect(page.locator('[data-testid="database-encryption-status"]')).toContainText('Enabled');
    await expect(page.locator('[data-testid="transit-encryption-status"]')).toContainText('TLS 1.3');

    // Step 10: Verify encryption metadata
    await page.click('[data-testid="view-encryption-details"]');
    await page.waitForSelector('[data-testid="encryption-algorithm"]');
    await expect(page.locator('[data-testid="encryption-algorithm"]')).toContainText('AES-256');

    // Step 11: Retrieve employee record through API to verify decryption works
    const retrieveResponse = await request.get(`${API_BASE_URL}/employees/${newEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    expect(retrieveResponse.status()).toBe(200);
    const retrievedData = await retrieveResponse.json();
    expect(retrievedData.name).toBe(newEmployeeData.name);
    expect(retrievedData.ssn).toBe(newEmployeeData.ssn);

    // Step 12: Review encryption audit logs
    await page.goto(`${BASE_URL}/compliance/audit-logs`);
    await page.fill('[data-testid="audit-log-search"]', 'encryption');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-entry"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Data encrypted');
  });

  test('Verify support for data subject rights', async ({ page, request }) => {
    // Step 1: Verify test employee data exists
    const verifyResponse = await request.get(`${API_BASE_URL}/employees/${testEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    expect(verifyResponse.status()).toBe(200);
    const employeeData = await verifyResponse.json();
    expect(employeeData.id).toBe(testEmployeeId);

    // Step 2: Document all data locations (simulated by checking multiple endpoints)
    const timekeepingResponse = await request.get(`${API_BASE_URL}/timekeeping/records?employeeId=${testEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    expect(timekeepingResponse.status()).toBe(200);
    const timekeepingRecords = await timekeepingResponse.json();
    expect(timekeepingRecords.length).toBeGreaterThan(0);

    // Step 3: Submit data deletion request
    const deletionRequestPayload = {
      requestType: 'deletion',
      subjectId: testEmployeeId,
      reason: 'GDPR Article 17 request'
    };
    const deletionResponse = await request.post(`${API_BASE_URL}/data/requests`, {
      headers: { 'Authorization': `Bearer ${adminToken}` },
      data: deletionRequestPayload
    });
    expect(deletionResponse.status()).toBe(201);
    const deletionRequest = await deletionResponse.json();
    const requestId = deletionRequest.id;
    expect(deletionRequest.status).toBe('pending');

    // Step 4-5: Query deletion request status and wait for completion
    let requestStatus = 'pending';
    let attempts = 0;
    while (requestStatus !== 'completed' && attempts < 10) {
      await page.waitForTimeout(3000);
      const statusResponse = await request.get(`${API_BASE_URL}/data/requests/${requestId}`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });
      const statusData = await statusResponse.json();
      requestStatus = statusData.status;
      attempts++;
    }
    expect(requestStatus).toBe('completed');

    // Step 6: Attempt to retrieve deleted employee data
    const deletedEmployeeResponse = await request.get(`${API_BASE_URL}/employees/${testEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    expect(deletedEmployeeResponse.status()).toBe(404);

    // Step 7: Verify deletion across timekeeping records
    const deletedTimekeepingResponse = await request.get(`${API_BASE_URL}/timekeeping/records?employeeId=${testEmployeeId}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    expect(deletedTimekeepingResponse.status()).toBe(200);
    const deletedRecords = await deletedTimekeepingResponse.json();
    expect(deletedRecords.length).toBe(0);

    // Step 9-10: Navigate to audit logs and verify deletion events
    await page.goto(`${BASE_URL}/compliance/audit-logs`);
    await page.fill('[data-testid="audit-log-search"]', testEmployeeId);
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-entry"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Data deletion');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('GDPR Article 17');
    
    const logEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(logEntry).toContainText('completed');
    await logEntry.click();
    await page.waitForSelector('[data-testid="audit-log-details"]');
    await expect(page.locator('[data-testid="legal-basis"]')).toContainText('GDPR Article 17');
    await expect(page.locator('[data-testid="deletion-timestamp"]')).toBeVisible();

    // Step 11-12: Access compliance dashboard and navigate to data subject requests
    await page.goto(`${BASE_URL}/compliance/dashboard`);
    await page.click('[data-testid="data-subject-requests-tab"]');
    await page.waitForSelector('[data-testid="data-subject-requests-list"]');
    await expect(page.locator('[data-testid="request-entry"]').filter({ hasText: testEmployeeId })).toBeVisible();

    // Step 13: Generate compliance report for data subject rights
    await page.click('[data-testid="generate-report-button"]');
    await page.selectOption('[data-testid="report-type-select"]', 'data-subject-rights');
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="report-date-from"]', today);
    await page.fill('[data-testid="report-date-to"]', today);
    await page.click('[data-testid="generate-button"]');
    await page.waitForSelector('[data-testid="report-generated"]', { timeout: 10000 });
    await expect(page.locator('[data-testid="report-status"]')).toContainText('Report generated successfully');

    // Step 14: Export compliance report in PDF and CSV formats
    await page.click('[data-testid="export-pdf-button"]');
    const pdfDownload = await page.waitForEvent('download');
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');

    await page.click('[data-testid="export-csv-button"]');
    const csvDownload = await page.waitForEvent('download');
    expect(csvDownload.suggestedFilename()).toContain('.csv');

    // Step 15: Review exported report for completeness
    await page.click('[data-testid="view-report-button"]');
    await page.waitForSelector('[data-testid="report-content"]');
    await expect(page.locator('[data-testid="report-content"]')).toContainText('deletion');
    await expect(page.locator('[data-testid="report-content"]')).toContainText(testEmployeeId);
    await expect(page.locator('[data-testid="report-content"]')).toContainText('GDPR Article 17');
    await expect(page.locator('[data-testid="report-content"]')).toContainText('completed');
    await expect(page.locator('[data-testid="report-submission-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-completion-date"]')).toBeVisible();
  });
});