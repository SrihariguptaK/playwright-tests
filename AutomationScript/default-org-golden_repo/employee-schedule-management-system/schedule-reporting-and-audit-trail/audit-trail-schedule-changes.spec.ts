import { test, expect } from '@playwright/test';

test.describe('Audit Trail - Schedule Changes Compliance', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const schedulerCredentials = {
    username: 'scheduler@company.com',
    password: 'Scheduler123!'
  };
  const managerCredentials = {
    username: 'manager@company.com',
    password: 'Manager123!'
  };
  const unauthorizedCredentials = {
    username: 'employee@company.com',
    password: 'Employee123!'
  };

  test('Verify audit logging of schedule changes (happy-path)', async ({ page }) => {
    // Step 1: Login as Scheduler user
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', schedulerCredentials.username);
    await page.fill('[data-testid="password-input"]', schedulerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Navigate to schedule management page
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();

    // Step 3: Select an existing employee schedule
    const employeeName = 'John Doe';
    await page.click(`[data-testid="employee-schedule-${employeeName.replace(' ', '-').toLowerCase()}"]`);
    await expect(page.locator('[data-testid="schedule-edit-modal"]')).toBeVisible();

    // Step 4: Modify shift time from 9:00 AM to 10:00 AM
    await page.fill('[data-testid="shift-start-time"]', '10:00');
    const changeTimestamp = new Date().toISOString();

    // Step 5: Save the schedule change
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Changes are saved successfully');

    // Step 6: Logout from Scheduler account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Login as Manager user
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 8: Navigate to audit trail module
    await page.click('[data-testid="audit-trail-link"]');
    await expect(page.locator('[data-testid="audit-trail-page"]')).toBeVisible();

    // Step 9: Query audit trail for the modified employee
    await page.fill('[data-testid="audit-search-input"]', employeeName);
    await page.click('[data-testid="search-button"]');

    // Step 10: Verify change entries with user and timestamp are displayed
    const auditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-user"]')).toContainText(schedulerCredentials.username);
    await expect(auditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(auditEntry.locator('[data-testid="audit-employee"]')).toContainText(employeeName);

    // Step 11: Click on audit entry to view detailed change information
    await auditEntry.click();
    await expect(page.locator('[data-testid="audit-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-detail-change"]')).toContainText('9:00 AM');
    await expect(page.locator('[data-testid="audit-detail-change"]')).toContainText('10:00 AM');
  });

  test('Search and filter audit logs (happy-path)', async ({ page }) => {
    // Login as Manager
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Navigate to audit trail module
    await page.click('[data-testid="audit-trail-link"]');
    await expect(page.locator('[data-testid="audit-trail-page"]')).toBeVisible();

    // Step 2: Note the total number of audit entries
    const initialEntries = await page.locator('[data-testid="audit-entry"]').count();
    const totalEntriesText = await page.locator('[data-testid="total-entries-count"]').textContent();
    expect(initialEntries).toBeGreaterThan(0);

    // Step 3: Select a specific employee from filter dropdown
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');

    // Step 4: Set date range filter for last 7 days
    const today = new Date();
    const sevenDaysAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    await page.fill('[data-testid="date-from-input"]', sevenDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="date-to-input"]', today.toISOString().split('T')[0]);

    // Step 5: Apply filters
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000); // Wait for filter application

    // Step 6: Verify all displayed entries match applied filters
    const filteredEntries = page.locator('[data-testid="audit-entry"]');
    const filteredCount = await filteredEntries.count();
    expect(filteredCount).toBeLessThanOrEqual(initialEntries);

    for (let i = 0; i < filteredCount; i++) {
      const entry = filteredEntries.nth(i);
      await expect(entry.locator('[data-testid="audit-employee"]')).toContainText('John Doe');
      const entryDate = await entry.locator('[data-testid="audit-timestamp"]').textContent();
      expect(entryDate).toBeTruthy();
    }

    // Step 7: Clear employee filter and add user filter
    await page.click('[data-testid="clear-employee-filter"]');
    await page.click('[data-testid="user-filter-dropdown"]');
    await page.click('[data-testid="user-option-scheduler"]');
    await page.click('[data-testid="apply-filters-button"]');

    // Verify user filter is applied
    const userFilteredEntries = page.locator('[data-testid="audit-entry"]');
    const userFilteredCount = await userFilteredEntries.count();
    for (let i = 0; i < userFilteredCount; i++) {
      const entry = userFilteredEntries.nth(i);
      await expect(entry.locator('[data-testid="audit-user"]')).toContainText('scheduler');
    }

    // Step 8: Clear all filters
    await page.click('[data-testid="clear-all-filters-button"]');
    await page.waitForTimeout(1000);
    const clearedEntriesCount = await page.locator('[data-testid="audit-entry"]').count();
    expect(clearedEntriesCount).toBe(initialEntries);
  });

  test('Restrict audit trail access to authorized users (error-case)', async ({ page, request }) => {
    // Login as unauthorized user (employee)
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', unauthorizedCredentials.username);
    await page.fill('[data-testid="password-input"]', unauthorizedCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Attempt to navigate to audit trail module by clicking link
    const auditTrailLink = page.locator('[data-testid="audit-trail-link"]');
    
    // Check if link is not visible or disabled for unauthorized user
    const isLinkVisible = await auditTrailLink.isVisible().catch(() => false);
    
    if (isLinkVisible) {
      await auditTrailLink.click();
      // Should be redirected or see access denied message
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access is denied with appropriate message');
    }

    // Step 2: Attempt direct URL navigation
    await page.goto(`${baseURL}/audit-trail`);
    
    // Step 3: Verify no audit log data is visible
    const auditData = page.locator('[data-testid="audit-entry"]');
    await expect(auditData).toHaveCount(0);
    
    // Verify access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/Access Denied|Unauthorized|403/');
    
    const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false);
    const isUnauthorizedShown = await unauthorizedMessage.isVisible().catch(() => false);
    
    expect(isAccessDenied || isUnauthorizedShown).toBeTruthy();

    // Step 4: Check if redirected to appropriate page
    const currentURL = page.url();
    const isRedirected = currentURL.includes('/dashboard') || currentURL.includes('/unauthorized') || currentURL.includes('/403');
    expect(isRedirected).toBeTruthy();

    // Step 5: Attempt API endpoint access directly
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token')?.value || '';

    const apiResponse = await request.get(`${baseURL}/api/auditlogs`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Step 6: Verify API returns 403 Forbidden or 401 Unauthorized
    expect([401, 403]).toContain(apiResponse.status());
    
    const responseBody = await apiResponse.json().catch(() => ({}));
    expect(responseBody.error || responseBody.message).toBeTruthy();

    // Step 7: Verify unauthorized access attempt is logged (check via manager account)
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as manager to verify logging
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="audit-trail-link"]');
    await page.fill('[data-testid="audit-search-input"]', 'unauthorized access');
    await page.click('[data-testid="search-button"]');
    
    // Verify unauthorized access attempt is logged
    const unauthorizedAccessLog = page.locator('[data-testid="audit-entry"]').filter({ hasText: unauthorizedCredentials.username });
    await expect(unauthorizedAccessLog.first()).toBeVisible({ timeout: 5000 });
  });
});