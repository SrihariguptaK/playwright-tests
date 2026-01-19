import { test, expect } from '@playwright/test';

test.describe('Administrator Override Scheduling Restrictions', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@example.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const NON_ADMIN_EMAIL = 'user@example.com';
  const NON_ADMIN_PASSWORD = 'UserPass123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Verify administrator can override scheduling restrictions', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to admin interface
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="override-interface-link"]');
    
    // Action: Administrator accesses override interface
    // Expected Result: Override UI is displayed
    await expect(page.locator('[data-testid="override-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-list"]')).toBeVisible();

    // Action: Administrator selects conflict and provides justification
    const firstConflict = page.locator('[data-testid="conflict-item"]').first();
    await firstConflict.click();
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
    
    await page.click('[data-testid="override-button"]');
    await expect(page.locator('[data-testid="justification-modal"]')).toBeVisible();
    
    const justificationText = 'Critical business requirement - CEO meeting needs this room';
    await page.fill('[data-testid="justification-input"]', justificationText);
    
    // Expected Result: Override action is accepted
    await page.click('[data-testid="confirm-override-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Override applied successfully');

    // Action: Override is applied and logged
    // Expected Result: Conflict restriction is lifted and audit log updated
    await page.click('[data-testid="audit-log-link"]');
    await expect(page.locator('[data-testid="audit-log-table"]')).toBeVisible();
    
    const latestLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestLogEntry).toContainText('Override');
    await expect(latestLogEntry).toContainText(justificationText);
    await expect(latestLogEntry).toContainText(ADMIN_EMAIL);
    
    // Verify conflict is resolved
    await page.click('[data-testid="scheduling-link"]');
    await expect(page.locator('[data-testid="conflict-resolved-badge"]')).toBeVisible();
  });

  test('Ensure affected users receive notifications after override', async ({ page, context }) => {
    // Login as administrator
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to admin interface and select conflict
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="override-interface-link"]');
    await expect(page.locator('[data-testid="override-interface"]')).toBeVisible();

    // Select a conflict that affects multiple users
    const conflictWithMultipleUsers = page.locator('[data-testid="conflict-item"]').filter({ hasText: 'Multiple users' }).first();
    await conflictWithMultipleUsers.click();
    
    // Get affected users count before override
    const affectedUsersText = await page.locator('[data-testid="affected-users-count"]').textContent();
    
    // Action: Administrator applies override
    await page.click('[data-testid="override-button"]');
    await expect(page.locator('[data-testid="justification-modal"]')).toBeVisible();
    
    const justificationText = 'Emergency maintenance required';
    await page.fill('[data-testid="justification-input"]', justificationText);
    await page.click('[data-testid="confirm-override-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const overrideTimestamp = new Date();

    // Wait for up to 5 minutes and check notifications
    await page.waitForTimeout(10000); // Wait 10 seconds for notification processing
    
    // Check notification queue/logs
    await page.click('[data-testid="notifications-link"]');
    await expect(page.locator('[data-testid="notification-queue"]')).toBeVisible();
    
    // Expected Result: Notification is sent to affected schedulers within 5 minutes
    const notificationEntry = page.locator('[data-testid="notification-entry"]').filter({ hasText: 'Override' }).first();
    await expect(notificationEntry).toBeVisible({ timeout: 300000 }); // 5 minutes timeout
    await expect(notificationEntry).toContainText('Emergency maintenance required');
    
    // Login as affected user in new page
    const affectedUserPage = await context.newPage();
    await affectedUserPage.goto(BASE_URL);
    await affectedUserPage.fill('[data-testid="email-input"]', 'affected.user@example.com');
    await affectedUserPage.fill('[data-testid="password-input"]', 'UserPass123!');
    await affectedUserPage.click('[data-testid="login-button"]');
    
    // Check notifications for affected user
    await affectedUserPage.click('[data-testid="notifications-icon"]');
    await expect(affectedUserPage.locator('[data-testid="notification-dropdown"]')).toBeVisible();
    
    const userNotification = affectedUserPage.locator('[data-testid="notification-item"]').first();
    await expect(userNotification).toContainText('Override');
    await expect(userNotification).toContainText(justificationText);
    await expect(userNotification).toContainText(/\d{1,2}:\d{2}/); // Timestamp format
    
    await affectedUserPage.close();
  });

  test('Test override access control enforcement', async ({ page, request }) => {
    // Login as non-admin user
    await page.fill('[data-testid="email-input"]', NON_ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Action: Non-admin user attempts to navigate to admin override interface URL directly
    await page.goto(`${BASE_URL}/admin/override`);
    
    // Expected Result: Access denied with error message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission');

    // Check if override controls are visible in regular scheduling interface
    await page.goto(`${BASE_URL}/scheduling`);
    await expect(page.locator('[data-testid="scheduling-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="override-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="admin-override-controls"]')).not.toBeVisible();

    // Get auth token from cookies/storage for API request
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token')?.value || '';

    // Action: Attempt to send direct API request to override endpoint
    const apiResponse = await request.post(`${BASE_URL}/api/admin/override`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        conflictId: 'conflict-123',
        justification: 'Unauthorized override attempt'
      }
    });

    // Expected Result: API returns 403 Forbidden
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Forbidden');
    expect(responseBody.message).toContain('Insufficient permissions');

    // Verify audit logs for unauthorized access attempt
    // Login as admin to check audit logs
    await page.goto(BASE_URL);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-log-link"]');
    await expect(page.locator('[data-testid="audit-log-table"]')).toBeVisible();
    
    // Check for unauthorized access attempt in logs
    const unauthorizedAttempt = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'Unauthorized' }).first();
    await expect(unauthorizedAttempt).toBeVisible();
    await expect(unauthorizedAttempt).toContainText(NON_ADMIN_EMAIL);
    await expect(unauthorizedAttempt).toContainText('Access denied');
    
    // Verify no changes were made to scheduling conflict
    await page.click('[data-testid="override-interface-link"]');
    const conflictStatus = page.locator('[data-testid="conflict-item"][data-conflict-id="conflict-123"]');
    await expect(conflictStatus).not.toContainText('Overridden');
    await expect(conflictStatus.locator('[data-testid="conflict-status"]')).toContainText('Active');
  });
});