import { test, expect } from '@playwright/test';

test.describe('Manual Employee Data Synchronization', () => {
  const HR_ANALYST_EMAIL = 'hr.analyst@company.com';
  const HR_ANALYST_PASSWORD = 'HRAnalyst123!';
  const NON_HR_USER_EMAIL = 'regular.user@company.com';
  const NON_HR_USER_PASSWORD = 'RegularUser123!';
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SYNC_API_ENDPOINT = '/api/hr/sync/manual';

  test('Verify authorized user can trigger manual sync', async ({ page }) => {
    // Step 1: Login as authorized HR Analyst
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', HR_ANALYST_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_ANALYST_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to synchronization page
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="user-role"]')).toContainText('HR Analyst');

    // Navigate to synchronization page
    await page.click('[data-testid="nav-synchronization"]');
    await expect(page).toHaveURL(/.*synchronization/);
    await expect(page.locator('[data-testid="sync-page-title"]')).toBeVisible();

    // Step 2: Click 'Sync Now' button
    const syncButton = page.locator('[data-testid="sync-now-button"]');
    await expect(syncButton).toBeEnabled();
    await syncButton.click();

    // Expected Result: Synchronization starts and status is displayed
    await expect(page.locator('[data-testid="sync-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('In Progress');

    // Wait for synchronization to complete (max 30 minutes as per requirements)
    await page.waitForSelector('[data-testid="sync-status"]:has-text("Completed")', { 
      timeout: 1800000 
    });
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Completed');

    // Verify synchronization results are displayed
    await expect(page.locator('[data-testid="sync-results"]')).toBeVisible();
    await expect(page.locator('[data-testid="sync-results-summary"]')).toContainText(/Records processed/);

    // Step 3: Check logs for manual sync event
    await page.click('[data-testid="nav-logs"]');
    await expect(page).toHaveURL(/.*logs/);

    // Filter for manual sync events
    await page.selectOption('[data-testid="log-type-filter"]', 'manual_sync');
    await page.click('[data-testid="apply-filter-button"]');

    // Expected Result: Event logged with correct user and timestamp
    const latestLogEntry = page.locator('[data-testid="log-entry"]').first();
    await expect(latestLogEntry).toBeVisible();
    await expect(latestLogEntry.locator('[data-testid="log-user"]')).toContainText(HR_ANALYST_EMAIL);
    await expect(latestLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(latestLogEntry.locator('[data-testid="log-event-type"]')).toContainText('Manual Sync');

    // Verify employee records reflect latest data
    await page.click('[data-testid="nav-employees"]');
    await expect(page).toHaveURL(/.*employees/);
    await expect(page.locator('[data-testid="employee-list"]')).toBeVisible();
    const lastSyncIndicator = page.locator('[data-testid="last-sync-time"]');
    await expect(lastSyncIndicator).toBeVisible();
  });

  test('Verify unauthorized user cannot trigger manual sync', async ({ page, request }) => {
    // Step 1: Login as non-HR user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', NON_HR_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_HR_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Access denied to synchronization page
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Verify synchronization menu is not visible or disabled
    const syncNavItem = page.locator('[data-testid="nav-synchronization"]');
    const isVisible = await syncNavItem.isVisible().catch(() => false);
    
    if (isVisible) {
      // If visible, it should be disabled
      await expect(syncNavItem).toBeDisabled();
    }

    // Attempt to navigate directly via URL
    await page.goto(`${BASE_URL}/synchronization`);
    
    // Should be redirected to unauthorized page or dashboard
    await page.waitForURL(/.*(?:unauthorized|access-denied|dashboard)/);
    const currentUrl = page.url();
    expect(currentUrl).not.toContain('/synchronization');

    // Verify unauthorized message is displayed
    const unauthorizedMessage = page.locator('[data-testid="unauthorized-message"], [data-testid="access-denied-message"]');
    if (await unauthorizedMessage.isVisible().catch(() => false)) {
      await expect(unauthorizedMessage).toContainText(/unauthorized|access denied|permission/i);
    }

    // Step 2: Attempt to call manual sync API
    // Get authentication token from cookies or local storage
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token')?.value || 
                     await page.evaluate(() => localStorage.getItem('auth_token'));

    // Expected Result: Request rejected with authorization error
    const apiResponse = await request.post(`${BASE_URL}${SYNC_API_ENDPOINT}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      failOnStatusCode: false
    });

    // Verify API returns authorization error
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error || responseBody.message).toMatch(/unauthorized|forbidden|permission denied|access denied/i);

    // Check security logs for unauthorized access attempts
    // Login as admin or HR to check logs
    await page.goto(`${BASE_URL}/logout`);
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', HR_ANALYST_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_ANALYST_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard/);

    // Navigate to security logs
    await page.click('[data-testid="nav-logs"]');
    await page.selectOption('[data-testid="log-type-filter"]', 'security');
    await page.click('[data-testid="apply-filter-button"]');

    // Verify unauthorized access attempt is logged
    const securityLogEntry = page.locator('[data-testid="log-entry"]').filter({ 
      hasText: NON_HR_USER_EMAIL 
    }).first();
    await expect(securityLogEntry).toBeVisible();
    await expect(securityLogEntry).toContainText(/unauthorized|access denied/i);

    // Verify no synchronization process was initiated
    await page.selectOption('[data-testid="log-type-filter"]', 'manual_sync');
    await page.click('[data-testid="apply-filter-button"]');
    
    const unauthorizedSyncLog = page.locator('[data-testid="log-entry"]').filter({ 
      hasText: NON_HR_USER_EMAIL 
    });
    await expect(unauthorizedSyncLog).toHaveCount(0);

    // Confirm employee data remains unchanged
    await page.click('[data-testid="nav-employees"]');
    await expect(page.locator('[data-testid="employee-list"]')).toBeVisible();
    const lastSyncTime = await page.locator('[data-testid="last-sync-time"]').textContent();
    
    // Wait a moment and verify sync time hasn't changed
    await page.waitForTimeout(2000);
    await page.reload();
    const currentSyncTime = await page.locator('[data-testid="last-sync-time"]').textContent();
    expect(currentSyncTime).toBe(lastSyncTime);
  });
});