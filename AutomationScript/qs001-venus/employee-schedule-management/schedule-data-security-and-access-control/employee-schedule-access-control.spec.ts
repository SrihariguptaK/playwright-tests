import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Access Control', () => {
  const testEmployee = {
    username: 'employee123',
    password: 'TestPassword123!',
    employeeId: '123',
    name: 'John Doe'
  };

  const otherEmployee = {
    employeeId: '456',
    name: 'Jane Smith'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Verify access granted only to authenticated employee\'s schedule', async ({ page }) => {
    // Step 1: Employee logs in
    await page.fill('[data-testid="username-input"]', testEmployee.username);
    await page.fill('[data-testid="password-input"]', testEmployee.password);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Authentication successful
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="employee-name"]')).toContainText(testEmployee.name);
    await expect(page.locator('[data-testid="employee-id"]')).toContainText(testEmployee.employeeId);

    // Step 2: Request own schedule
    await page.click('[data-testid="my-schedule-menu"]');
    await page.waitForLoadState('networkidle');

    // Expected Result: Schedule data returned
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-employee-id"]')).toContainText(testEmployee.employeeId);
    await expect(page.locator('[data-testid="schedule-employee-name"]')).toContainText(testEmployee.name);

    // Step 3: Attempt to access another employee's schedule by modifying URL
    const currentUrl = page.url();
    const unauthorizedUrl = currentUrl.replace(`employeeId=${testEmployee.employeeId}`, `employeeId=${otherEmployee.employeeId}`);
    await page.goto(unauthorizedUrl);

    // Expected Result: Access denied with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|permission denied/i);

    // Verify user is redirected back to their own schedule or dashboard
    await page.waitForTimeout(1000);
    const finalUrl = page.url();
    expect(finalUrl).toMatch(/dashboard|schedule.*employeeId=123/);

    // Step 4: Attempt API call to retrieve another employee's schedule
    const apiResponse = await page.request.get(`/api/schedule/${otherEmployee.employeeId}`);
    
    // Expected Result: API returns unauthorized status
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toMatch(/unauthorized|access denied|forbidden/i);
  });

  test('Verify audit logging of schedule access', async ({ page }) => {
    // Note current timestamp before starting
    const testStartTime = new Date();

    // Step 1: Login with valid employee credentials
    await page.fill('[data-testid="username-input"]', testEmployee.username);
    await page.fill('[data-testid="password-input"]', testEmployee.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to and access employee's own schedule
    await page.click('[data-testid="my-schedule-menu"]');
    await page.waitForLoadState('networkidle');
    const scheduleAccessTime = new Date();

    // Expected Result: Access logged with timestamp and user ID
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Step 3: Access audit logs (assuming admin panel or API endpoint)
    const auditLogsResponse = await page.request.get('/api/audit-logs', {
      params: {
        userId: testEmployee.employeeId,
        startTime: testStartTime.toISOString(),
        endTime: new Date().toISOString()
      }
    });

    expect(auditLogsResponse.ok()).toBeTruthy();
    const auditLogs = await auditLogsResponse.json();

    // Step 4: Verify log entry contains required information
    const scheduleAccessLog = auditLogs.find((log: any) => 
      log.userId === testEmployee.employeeId && 
      log.action === 'SCHEDULE_ACCESS' &&
      new Date(log.timestamp) >= testStartTime
    );

    expect(scheduleAccessLog).toBeDefined();
    expect(scheduleAccessLog.userId).toBe(testEmployee.employeeId);
    expect(scheduleAccessLog.timestamp).toBeDefined();
    expect(scheduleAccessLog.action).toBe('SCHEDULE_ACCESS');
    expect(scheduleAccessLog.resource).toMatch(/schedule/i);

    // Step 5: Attempt unauthorized access
    const unauthorizedAttemptTime = new Date();
    const unauthorizedResponse = await page.request.get(`/api/schedule/${otherEmployee.employeeId}`);
    
    // Expected Result: Attempt logged with details
    expect(unauthorizedResponse.status()).toBe(403);

    // Step 6: Check audit logs for unauthorized access attempt
    const updatedAuditLogsResponse = await page.request.get('/api/audit-logs', {
      params: {
        userId: testEmployee.employeeId,
        startTime: unauthorizedAttemptTime.toISOString(),
        endTime: new Date().toISOString()
      }
    });

    const updatedAuditLogs = await updatedAuditLogsResponse.json();

    // Step 7: Verify unauthorized attempt log includes denial details
    const unauthorizedAccessLog = updatedAuditLogs.find((log: any) => 
      log.userId === testEmployee.employeeId && 
      log.action === 'SCHEDULE_ACCESS_DENIED' &&
      new Date(log.timestamp) >= unauthorizedAttemptTime
    );

    expect(unauthorizedAccessLog).toBeDefined();
    expect(unauthorizedAccessLog.userId).toBe(testEmployee.employeeId);
    expect(unauthorizedAccessLog.timestamp).toBeDefined();
    expect(unauthorizedAccessLog.action).toMatch(/DENIED|UNAUTHORIZED|FORBIDDEN/i);
    expect(unauthorizedAccessLog.targetResource).toContain(otherEmployee.employeeId);
    expect(unauthorizedAccessLog.result).toMatch(/denied|failed|unauthorized/i);
  });

  test('Verify system denies access to schedules not belonging to authenticated employee', async ({ page }) => {
    // Login as test employee
    await page.fill('[data-testid="username-input"]', testEmployee.username);
    await page.fill('[data-testid="password-input"]', testEmployee.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt direct navigation to another employee's schedule
    await page.goto(`/schedule?employeeId=${otherEmployee.employeeId}`);

    // Expected Result: Access denied
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized/i);

    // Verify schedule data is not displayed
    const scheduleData = page.locator('[data-testid="schedule-container"]');
    if (await scheduleData.isVisible()) {
      await expect(page.locator('[data-testid="schedule-employee-id"]')).not.toContainText(otherEmployee.employeeId);
    }
  });

  test('Verify system responds to unauthorized access with appropriate error messages', async ({ page }) => {
    // Login as test employee
    await page.fill('[data-testid="username-input"]', testEmployee.username);
    await page.fill('[data-testid="password-input"]', testEmployee.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Make API request for unauthorized schedule
    const response = await page.request.get(`/api/schedule/${otherEmployee.employeeId}`);

    // Expected Result: Appropriate error response
    expect(response.status()).toBe(403);
    const errorResponse = await response.json();
    expect(errorResponse).toHaveProperty('error');
    expect(errorResponse.error).toMatch(/unauthorized|access denied|forbidden|permission denied/i);
    expect(errorResponse).toHaveProperty('message');
    expect(errorResponse.message).toBeTruthy();
  });

  test('Verify role-based access control enforced across all schedule endpoints', async ({ page }) => {
    // Login as test employee
    await page.fill('[data-testid="username-input"]', testEmployee.username);
    await page.fill('[data-testid="password-input"]', testEmployee.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Test multiple schedule endpoints
    const endpoints = [
      `/api/schedule/${otherEmployee.employeeId}`,
      `/api/schedule/${otherEmployee.employeeId}/details`,
      `/api/schedule/${otherEmployee.employeeId}/shifts`,
      `/api/schedules?employeeId=${otherEmployee.employeeId}`
    ];

    for (const endpoint of endpoints) {
      const response = await page.request.get(endpoint);
      
      // Expected Result: All endpoints enforce access control
      expect(response.status()).toBe(403);
      const errorData = await response.json();
      expect(errorData.error).toMatch(/unauthorized|access denied|forbidden/i);
    }

    // Verify own schedule endpoints work correctly
    const ownScheduleResponse = await page.request.get(`/api/schedule/${testEmployee.employeeId}`);
    expect(ownScheduleResponse.status()).toBe(200);
    const scheduleData = await ownScheduleResponse.json();
    expect(scheduleData.employeeId).toBe(testEmployee.employeeId);
  });
});