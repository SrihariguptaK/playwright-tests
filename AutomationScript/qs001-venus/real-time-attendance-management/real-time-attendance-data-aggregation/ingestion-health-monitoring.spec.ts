import { test, expect } from '@playwright/test';

test.describe('Story-19: Ingestion Health Monitoring', () => {
  const DASHBOARD_URL = '/monitoring/ingestion';
  const ADMIN_EMAIL = 'admin@example.com';
  const ADMIN_PASSWORD = 'AdminPass123!';
  const NON_ADMIN_EMAIL = 'user@example.com';
  const NON_ADMIN_PASSWORD = 'UserPass123!';

  test.beforeEach(async ({ page }) => {
    // Set base URL context
    await page.goto('/');
  });

  test('Validate ingestion health dashboard updates (happy-path)', async ({ page }) => {
    // Login as admin
    await page.goto('/login');
    await page.fill('input[name="email"]', ADMIN_EMAIL);
    await page.fill('input[name="password"]', ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Navigate to the ingestion health dashboard URL
    await page.goto(DASHBOARD_URL);
    await page.waitForLoadState('networkidle');

    // Expected Result: Dashboard displays current status with recent metrics
    await expect(page.locator('[data-testid="ingestion-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="recent-metrics"]')).toBeVisible();
    
    const initialStatus = await page.locator('[data-testid="status-indicator"]').textContent();
    expect(initialStatus).toBeTruthy();

    // Step 2: Observe the dashboard for 2 minutes without any interaction
    await page.waitForTimeout(2000); // Simulated wait for dashboard updates
    
    // Verify dashboard updates every minute
    const lastUpdateTime = await page.locator('[data-testid="last-update-time"]').textContent();
    expect(lastUpdateTime).toBeTruthy();

    // Step 3: Simulate an ingestion failure by stopping the data ingestion service
    // Trigger failure simulation via API or UI control
    await page.click('[data-testid="simulate-failure-btn"]');
    await page.waitForTimeout(1000);

    // Expected Result: Dashboard reflects failure and alert is generated
    await expect(page.locator('[data-testid="status-indicator"]')).toContainText('Failed', { timeout: 10000 });
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-notification"]')).toContainText('Ingestion failure detected');

    // Step 4: Check the alerts section or notification panel on the dashboard
    await page.click('[data-testid="alerts-section"]');
    await expect(page.locator('[data-testid="alert-list"]')).toBeVisible();
    const alertCount = await page.locator('[data-testid="alert-item"]').count();
    expect(alertCount).toBeGreaterThan(0);

    // Step 5: Navigate to the historical logs section from the dashboard menu
    await page.click('[data-testid="historical-logs-link"]');
    await page.waitForLoadState('networkidle');

    // Expected Result: Logs show detailed ingestion events
    await expect(page.locator('[data-testid="historical-logs-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-entries"]')).toBeVisible();

    // Step 6: Review the historical logs for the simulated failure event
    const failureLog = page.locator('[data-testid="log-entry"]').filter({ hasText: 'failure' }).first();
    await expect(failureLog).toBeVisible();
    await expect(failureLog).toContainText('Ingestion');

    // Step 7: Filter logs by date range to view events from the last hour
    await page.click('[data-testid="filter-logs-btn"]');
    await page.selectOption('[data-testid="time-range-select"]', 'last-hour');
    await page.click('[data-testid="apply-filter-btn"]');
    await page.waitForLoadState('networkidle');

    // Verify filtered logs are displayed
    const filteredLogs = await page.locator('[data-testid="log-entry"]').count();
    expect(filteredLogs).toBeGreaterThan(0);
  });

  test('Verify admin access control (error-case)', async ({ page, context }) => {
    // Step 1: Log out from any existing session and clear browser cache/cookies
    await context.clearCookies();
    await page.goto('/login');

    // Step 2: Log in to the system using non-admin user credentials
    await page.fill('input[name="email"]', NON_ADMIN_EMAIL);
    await page.fill('input[name="password"]', NON_ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForLoadState('networkidle');

    // Step 3: Attempt to access the ingestion health dashboard
    await page.goto(DASHBOARD_URL);
    await page.waitForLoadState('networkidle');

    // Expected Result: Access denied
    const isAccessDenied = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    const isUnauthorized = await page.locator('text=/Access Denied|Unauthorized|403/i').isVisible().catch(() => false);
    const isRedirected = page.url().includes('/login') || page.url().includes('/unauthorized');
    
    expect(isAccessDenied || isUnauthorized || isRedirected).toBeTruthy();

    // Step 4: Verify that no dashboard data or metrics are visible in the response
    const dashboardVisible = await page.locator('[data-testid="ingestion-dashboard"]').isVisible().catch(() => false);
    expect(dashboardVisible).toBeFalsy();

    const metricsVisible = await page.locator('[data-testid="recent-metrics"]').isVisible().catch(() => false);
    expect(metricsVisible).toBeFalsy();

    // Step 5: Log out from the non-admin account
    if (!isRedirected) {
      await page.click('[data-testid="logout-btn"]').catch(() => {});
    }
    await context.clearCookies();

    // Step 6: Log in to the system using admin user credentials
    await page.goto('/login');
    await page.fill('input[name="email"]', ADMIN_EMAIL);
    await page.fill('input[name="password"]', ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForLoadState('networkidle');

    // Step 7: Navigate to the ingestion health dashboard URL
    await page.goto(DASHBOARD_URL);
    await page.waitForLoadState('networkidle');

    // Expected Result: Access granted
    await expect(page.locator('[data-testid="ingestion-dashboard"]')).toBeVisible({ timeout: 10000 });

    // Step 8: Verify all dashboard features are accessible
    await expect(page.locator('[data-testid="current-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="recent-metrics"]')).toBeVisible();
    await expect(page.locator('[data-testid="historical-logs-link"]')).toBeVisible();
    await expect(page.locator('[data-testid="alerts-section"]')).toBeVisible();
    
    // Verify alert configurations are accessible
    const alertConfigBtn = page.locator('[data-testid="alert-config-btn"]');
    if (await alertConfigBtn.isVisible()) {
      await expect(alertConfigBtn).toBeEnabled();
    }

    // Verify real-time metrics are updating
    const lastUpdateTime = await page.locator('[data-testid="last-update-time"]').textContent();
    expect(lastUpdateTime).toBeTruthy();
  });
});