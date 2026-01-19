import { test, expect } from '@playwright/test';

test.describe('HR Manual Employee Data Synchronization', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const hrAnalystCredentials = {
    username: 'hr.analyst@company.com',
    password: 'HRAnalyst123!'
  };
  const nonHRUserCredentials = {
    username: 'regular.user@company.com',
    password: 'RegularUser123!'
  };

  test('Verify authorized user can trigger manual sync', async ({ page }) => {
    // Navigate to the application login page
    await page.goto(`${baseURL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Enter valid credentials for authorized HR Analyst user and click login button
    await page.fill('[data-testid="username-input"]', hrAnalystCredentials.username);
    await page.fill('[data-testid="password-input"]', hrAnalystCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Verify access to synchronization page by navigating to the HR synchronization section
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="hr-menu"]');
    await page.click('[data-testid="synchronization-link"]');
    await expect(page).toHaveURL(/.*synchronization/);

    // Review the synchronization page interface for current sync status
    await expect(page.locator('[data-testid="sync-status-panel"]')).toBeVisible();
    const currentStatus = await page.locator('[data-testid="current-sync-status"]').textContent();
    expect(currentStatus).toBeTruthy();

    // Click the 'Sync Now' button to trigger manual synchronization
    const syncButton = page.locator('[data-testid="sync-now-button"]');
    await expect(syncButton).toBeEnabled();
    await syncButton.click();

    // Monitor the synchronization status displayed on the page
    await expect(page.locator('[data-testid="sync-in-progress"]')).toBeVisible({ timeout: 5000 });
    const statusMessage = await page.locator('[data-testid="sync-status-message"]').textContent();
    expect(statusMessage).toContain('Synchronization');

    // Wait for synchronization to complete and observe the final status
    await expect(page.locator('[data-testid="sync-completed"]')).toBeVisible({ timeout: 60000 });

    // Verify synchronization results displayed to the user
    const syncResults = page.locator('[data-testid="sync-results-panel"]');
    await expect(syncResults).toBeVisible();
    const resultsText = await syncResults.textContent();
    expect(resultsText).toMatch(/success|completed/i);

    // Navigate to system logs or audit trail section
    await page.click('[data-testid="logs-menu"]');
    await page.click('[data-testid="audit-trail-link"]');
    await expect(page).toHaveURL(/.*logs|.*audit/);

    // Check logs for the manual sync event entry
    const logEntries = page.locator('[data-testid="log-entry"]');
    await expect(logEntries.first()).toBeVisible();
    const latestLogEntry = logEntries.first();
    const logText = await latestLogEntry.textContent();
    expect(logText).toContain('Manual sync');
    expect(logText).toContain(hrAnalystCredentials.username);

    // Verify the timestamp in the log matches the time when 'Sync Now' was clicked
    const logTimestamp = await latestLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    const logTime = new Date(logTimestamp!);
    const currentTime = new Date();
    const timeDifference = Math.abs(currentTime.getTime() - logTime.getTime()) / 1000 / 60;
    expect(timeDifference).toBeLessThan(5);
  });

  test('Verify unauthorized user cannot trigger manual sync', async ({ page, request }) => {
    // Navigate to the application login page
    await page.goto(`${baseURL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Enter valid credentials for non-HR user (unauthorized user) and click login button
    await page.fill('[data-testid="username-input"]', nonHRUserCredentials.username);
    await page.fill('[data-testid="password-input"]', nonHRUserCredentials.password);
    await page.click('[data-testid="login-button"]');

    // Verify successful login
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to the synchronization page through the application menu or direct URL
    const hrMenuExists = await page.locator('[data-testid="hr-menu"]').count();
    if (hrMenuExists > 0) {
      await page.click('[data-testid="hr-menu"]');
      const syncLinkExists = await page.locator('[data-testid="synchronization-link"]').count();
      expect(syncLinkExists).toBe(0);
    }

    // Attempt direct URL navigation
    await page.goto(`${baseURL}/hr/synchronization`);
    
    // Verify that synchronization page or 'Sync Now' button is not visible in the user interface
    const accessDeniedMessage = page.locator('[data-testid="access-denied"]');
    const unauthorizedMessage = page.locator('text=/access denied|unauthorized|forbidden/i');
    const syncButton = page.locator('[data-testid="sync-now-button"]');
    
    await expect(accessDeniedMessage.or(unauthorizedMessage)).toBeVisible({ timeout: 5000 });
    await expect(syncButton).not.toBeVisible();

    // Extract authentication token from browser storage
    const authToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    });
    expect(authToken).toBeTruthy();

    // Send POST request to /api/hr/sync/manual endpoint with unauthorized user's token
    const apiResponse = await request.post(`${baseURL}/api/hr/sync/manual`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Review the API response status code and message
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();

    // Verify the error response body contains appropriate authorization error details
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/unauthorized|forbidden|access denied/i);

    // Navigate to logs if accessible to verify no sync was triggered
    await page.goto(`${baseURL}/dashboard`);
    const logsMenuExists = await page.locator('[data-testid="logs-menu"]').count();
    if (logsMenuExists > 0) {
      await page.click('[data-testid="logs-menu"]');
      const auditLinkExists = await page.locator('[data-testid="audit-trail-link"]').count();
      if (auditLinkExists > 0) {
        await page.click('[data-testid="audit-trail-link"]');
        const recentLogs = await page.locator('[data-testid="log-entry"]').first().textContent();
        if (recentLogs) {
          expect(recentLogs).not.toContain(nonHRUserCredentials.username);
          expect(recentLogs).not.toContain('Manual sync');
        }
      }
    }
  });
});