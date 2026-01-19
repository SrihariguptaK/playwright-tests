import { test, expect } from '@playwright/test';

test.describe('Manager Approval Failure Alerts', () => {
  const managerEmail = 'manager@example.com';
  const managerPassword = 'Manager123!';
  const unauthorizedEmail = 'employee@example.com';
  const unauthorizedPassword = 'Employee123!';
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';

  test('Detect and alert on approval workflow failure', async ({ page }) => {
    // Step 1: Navigate to the test environment and access the workflow simulation tool
    await page.goto(`${baseURL}/admin/workflow-simulation`);
    await expect(page.locator('[data-testid="workflow-simulation-page"]')).toBeVisible();

    // Step 2: Simulate a failure in the schedule change approval workflow
    await page.click('[data-testid="simulate-failure-btn"]');
    await page.selectOption('[data-testid="failure-type-select"]', 'invalid-approver');
    await page.fill('[data-testid="schedule-change-id"]', 'SCH-12345');
    await page.click('[data-testid="trigger-failure-btn"]');

    // Expected Result: System detects failure event
    await expect(page.locator('[data-testid="failure-detected-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="failure-detected-message"]')).toContainText('Failure event detected');

    // Step 3: Wait for the system to process the failure event and trigger the alert mechanism
    await page.waitForTimeout(3000);

    // Step 4: Check the manager's email inbox for the alert notification (simulated via API check)
    const emailResponse = await page.request.get(`${baseURL}/api/test/emails/latest`, {
      params: { recipient: managerEmail }
    });
    expect(emailResponse.ok()).toBeTruthy();
    const emailData = await emailResponse.json();
    expect(emailData.subject).toContain('Schedule Change Approval Failure');
    expect(emailData.body).toContain('SCH-12345');
    expect(emailData.body).toContain('invalid approver');

    // Step 5: Log in to the system as the manager and check the in-app notification center
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-btn"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 6: Check in-app notification
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toContainText('Schedule Change Approval Failure');
    await expect(notification).toContainText('SCH-12345');

    // Step 7: Navigate to the alert history section
    await page.click('[data-testid="alert-history-link"]');
    await expect(page.locator('[data-testid="alert-history-page"]')).toBeVisible();

    // Step 8: Search for the recently triggered alert
    await page.fill('[data-testid="alert-search-input"]', 'SCH-12345');
    await page.click('[data-testid="search-btn"]');

    // Step 9: Verify the alert details match the simulated failure event
    const alertRow = page.locator('[data-testid="alert-row"]').first();
    await expect(alertRow).toBeVisible();
    await expect(alertRow.locator('[data-testid="alert-schedule-id"]')).toContainText('SCH-12345');
    await expect(alertRow.locator('[data-testid="alert-failure-type"]')).toContainText('invalid approver');
    await expect(alertRow.locator('[data-testid="alert-recipient"]')).toContainText(managerEmail);
    await expect(alertRow.locator('[data-testid="alert-timestamp"]')).toBeVisible();
    await expect(alertRow.locator('[data-testid="alert-status"]')).toContainText('Delivered');
  });

  test('Verify alert delivery within SLA', async ({ page }) => {
    // Step 1: Prepare timing measurement tools and note the current system time
    const startTime = Date.now();

    // Step 2: Navigate to workflow simulation tool
    await page.goto(`${baseURL}/admin/workflow-simulation`);
    await expect(page.locator('[data-testid="workflow-simulation-page"]')).toBeVisible();

    // Step 3: Trigger a failure event and record the exact timestamp
    await page.click('[data-testid="simulate-failure-btn"]');
    await page.selectOption('[data-testid="failure-type-select"]', 'system-timeout');
    await page.fill('[data-testid="schedule-change-id"]', 'SCH-67890');
    const failureTimestamp = Date.now();
    await page.click('[data-testid="trigger-failure-btn"]');
    await expect(page.locator('[data-testid="failure-detected-message"]')).toBeVisible();

    // Step 4: Monitor the system logs and alert queue
    await page.goto(`${baseURL}/admin/alert-logs`);
    await page.fill('[data-testid="log-search-input"]', 'SCH-67890');
    await page.click('[data-testid="refresh-logs-btn"]');

    // Step 5: Wait for alert generation and check timestamps
    await page.waitForSelector('[data-testid="alert-log-entry"]', { timeout: 130000 });
    const alertLogEntry = page.locator('[data-testid="alert-log-entry"]').first();
    await expect(alertLogEntry).toBeVisible();

    // Step 6: Get the alert delivery timestamp from the log
    const deliveryTimestampText = await alertLogEntry.locator('[data-testid="delivery-timestamp"]').textContent();
    const deliveryTimestamp = new Date(deliveryTimestampText || '').getTime();

    // Step 7: Calculate time difference
    const timeDifference = deliveryTimestamp - failureTimestamp;
    const timeDifferenceInMinutes = timeDifference / (1000 * 60);

    // Step 8: Verify alert was sent within 2 minutes (120 seconds)
    expect(timeDifferenceInMinutes).toBeLessThanOrEqual(2);
    await expect(alertLogEntry.locator('[data-testid="alert-status"]')).toContainText('Sent');

    // Step 9: Login as manager and verify in-app notification delivery time
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-btn"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    await page.click('[data-testid="notifications-icon"]');
    const notification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'SCH-67890' }).first();
    await expect(notification).toBeVisible();

    // Step 10: Verify notification timestamp is within SLA
    const notificationTimestampText = await notification.locator('[data-testid="notification-timestamp"]').textContent();
    const notificationTimestamp = new Date(notificationTimestampText || '').getTime();
    const notificationTimeDifference = notificationTimestamp - failureTimestamp;
    const notificationTimeDifferenceInMinutes = notificationTimeDifference / (1000 * 60);
    expect(notificationTimeDifferenceInMinutes).toBeLessThanOrEqual(2);
  });

  test('Prevent unauthorized access to alert management', async ({ page }) => {
    // Step 1: Log in to the system using unauthorized user credentials
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', unauthorizedEmail);
    await page.fill('[data-testid="password-input"]', unauthorizedPassword);
    await page.click('[data-testid="login-btn"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Attempt to navigate to the alert configuration page by entering the URL directly
    await page.goto(`${baseURL}/admin/alert-configuration`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="error-code"]')).toContainText('403');

    // Step 3: Attempt to access the alert configuration API endpoint directly
    const apiResponse = await page.request.post(`${baseURL}/api/alerts`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      },
      data: {
        alertType: 'workflow-failure',
        recipients: ['test@example.com']
      }
    });
    expect(apiResponse.status()).toBe(403);
    const apiResponseData = await apiResponse.json();
    expect(apiResponseData.error).toContain('Unauthorized');

    // Step 4: Attempt to view the alert history page
    await page.goto(`${baseURL}/admin/alert-history`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Step 5: Attempt to modify alert settings by manipulating request parameters
    const modifyResponse = await page.request.put(`${baseURL}/api/alerts/settings`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      },
      data: {
        alertEnabled: false,
        recipients: ['unauthorized@example.com']
      }
    });
    expect(modifyResponse.status()).toBe(403);

    // Step 6: Verify that no alert configuration data or sensitive information is exposed
    const errorResponseData = await modifyResponse.json();
    expect(errorResponseData).not.toHaveProperty('alertSettings');
    expect(errorResponseData).not.toHaveProperty('recipients');
    expect(errorResponseData).not.toHaveProperty('configurationData');
    expect(errorResponseData.error).toBeDefined();
    expect(errorResponseData.error).toContain('Unauthorized');

    // Step 7: Check security audit logs for the unauthorized access attempts
    await page.goto(`${baseURL}/logout`);
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-btn"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    await page.goto(`${baseURL}/admin/security-audit-logs`);
    await page.fill('[data-testid="audit-search-input"]', unauthorizedEmail);
    await page.click('[data-testid="search-audit-btn"]');

    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText(unauthorizedEmail);
    await expect(auditLogEntry.locator('[data-testid="audit-action"]')).toContainText('Unauthorized Access Attempt');
    await expect(auditLogEntry.locator('[data-testid="audit-resource"]')).toContainText('alert-configuration');
    await expect(auditLogEntry.locator('[data-testid="audit-result"]')).toContainText('Denied');
  });
});