import { test, expect } from '@playwright/test';

test.describe('Conflict Dashboard - View and Monitor Scheduling Issues', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify dashboard displays active conflict alerts (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the conflict dashboard by clicking on the dashboard menu or accessing the dashboard URL
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="conflict-dashboard-link"]');
    await expect(page).toHaveURL(/.*conflict-dashboard/);

    // Step 2: Verify that all active conflict alerts are displayed on the dashboard
    await page.waitForSelector('[data-testid="conflict-alerts-list"]', { timeout: 5000 });
    const alertsList = page.locator('[data-testid="conflict-alert-item"]');
    const alertsCount = await alertsList.count();
    expect(alertsCount).toBeGreaterThan(0);

    // Step 3: Check that each alert displays relevant details including resource, timestamp, and severity level
    const firstAlert = alertsList.first();
    await expect(firstAlert.locator('[data-testid="alert-resource"]')).toBeVisible();
    await expect(firstAlert.locator('[data-testid="alert-timestamp"]')).toBeVisible();
    await expect(firstAlert.locator('[data-testid="alert-severity"]')).toBeVisible();

    // Step 4: Locate the filter options on the dashboard (resource filter, time filter, severity filter)
    await expect(page.locator('[data-testid="resource-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="severity-filter"]')).toBeVisible();

    // Step 5: Apply a resource filter by selecting a specific resource from the filter dropdown
    await page.click('[data-testid="resource-filter"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    await page.waitForTimeout(500);
    const filteredByResource = await page.locator('[data-testid="conflict-alert-item"]').count();
    expect(filteredByResource).toBeGreaterThanOrEqual(0);
    const resourceText = await page.locator('[data-testid="conflict-alert-item"]').first().locator('[data-testid="alert-resource"]').textContent();
    expect(resourceText).toContain('Conference Room A');

    // Step 6: Clear the resource filter and apply a severity filter by selecting a specific severity level
    await page.click('[data-testid="clear-resource-filter"]');
    await page.waitForTimeout(500);
    await page.click('[data-testid="severity-filter"]');
    await page.click('[data-testid="severity-option-high"]');
    await page.waitForTimeout(500);
    const filteredBySeverity = await page.locator('[data-testid="conflict-alert-item"]').count();
    expect(filteredBySeverity).toBeGreaterThanOrEqual(0);
    const severityText = await page.locator('[data-testid="conflict-alert-item"]').first().locator('[data-testid="alert-severity"]').textContent();
    expect(severityText).toContain('High');

    // Step 7: Apply a time filter by selecting a specific time range or date
    await page.click('[data-testid="clear-severity-filter"]');
    await page.waitForTimeout(500);
    await page.click('[data-testid="time-filter"]');
    await page.click('[data-testid="time-option-today"]');
    await page.waitForTimeout(500);
    const filteredByTime = await page.locator('[data-testid="conflict-alert-item"]').count();
    expect(filteredByTime).toBeGreaterThanOrEqual(0);

    // Step 8: Apply multiple filters simultaneously (resource + severity + time)
    await page.click('[data-testid="resource-filter"]');
    await page.click('[data-testid="resource-option-conference-room-b"]');
    await page.click('[data-testid="severity-filter"]');
    await page.click('[data-testid="severity-option-medium"]');
    await page.click('[data-testid="time-filter"]');
    await page.click('[data-testid="time-option-this-week"]');
    await page.waitForTimeout(500);
    const multiFiltered = await page.locator('[data-testid="conflict-alert-item"]').count();
    expect(multiFiltered).toBeGreaterThanOrEqual(0);

    // Step 9: Clear all filters to return to the full list of active alerts
    await page.click('[data-testid="clear-all-filters"]');
    await page.waitForTimeout(500);
    const allAlertsAfterClear = await page.locator('[data-testid="conflict-alert-item"]').count();
    expect(allAlertsAfterClear).toBe(alertsCount);

    // Step 10: Select a specific conflict alert from the list by clicking on it
    await page.click('[data-testid="conflict-alert-item"]', { position: { x: 10, y: 10 } });
    await page.waitForSelector('[data-testid="conflict-detail-view"]', { timeout: 3000 });

    // Step 11: Verify the detailed view contains complete conflict information including affected resources, timeline, severity, and resolution options
    await expect(page.locator('[data-testid="detail-affected-resources"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-timeline"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-severity"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-resolution-options"]')).toBeVisible();

    // Step 12: Navigate back to the dashboard from the detailed view
    await page.click('[data-testid="back-to-dashboard-button"]');
    await expect(page).toHaveURL(/.*conflict-dashboard/);
    await expect(page.locator('[data-testid="conflict-alerts-list"]')).toBeVisible();
  });

  test('Ensure dashboard data refreshes within 2 seconds (happy-path)', async ({ page }) => {
    // Step 1: Open the conflict dashboard and note the current number of active alerts displayed
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="conflict-dashboard-link"]');
    await expect(page).toHaveURL(/.*conflict-dashboard/);
    await page.waitForSelector('[data-testid="conflict-alerts-list"]', { timeout: 5000 });
    const initialAlertsCount = await page.locator('[data-testid="conflict-alert-item"]').count();

    // Step 2: Prepare a timer or stopwatch to measure the refresh time
    const startTime = Date.now();

    // Step 3: Generate a new conflict alert in the system (through backend process, API call, or by creating a scheduling conflict)
    // Simulate API call to create a new conflict
    await page.evaluate(async () => {
      await fetch('/api/conflicts/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource: 'Conference Room C',
          timestamp: new Date().toISOString(),
          severity: 'High',
          description: 'Double booking detected'
        })
      });
    });

    // Step 4: Start the timer immediately after the new conflict alert is generated (already started above)
    // Step 5: Observe the dashboard without manually refreshing the page
    // Step 6: Stop the timer when the new alert appears on the dashboard
    await page.waitForFunction(
      (expectedCount) => {
        const alerts = document.querySelectorAll('[data-testid="conflict-alert-item"]');
        return alerts.length > expectedCount;
      },
      initialAlertsCount,
      { timeout: 3000 }
    );
    const endTime = Date.now();
    const elapsedTime = endTime - startTime;

    // Step 7: Verify that the elapsed time is 2 seconds or less
    expect(elapsedTime).toBeLessThanOrEqual(2000);

    // Step 8: Verify the new alert displays with correct information (resource, time, severity)
    const updatedAlertsCount = await page.locator('[data-testid="conflict-alert-item"]').count();
    expect(updatedAlertsCount).toBe(initialAlertsCount + 1);
    const newAlert = page.locator('[data-testid="conflict-alert-item"]').first();
    await expect(newAlert.locator('[data-testid="alert-resource"]')).toContainText('Conference Room C');
    await expect(newAlert.locator('[data-testid="alert-severity"]')).toContainText('High');

    // Step 9: Check that the alert count has increased by one
    const alertCountDisplay = await page.locator('[data-testid="alert-count"]').textContent();
    expect(parseInt(alertCountDisplay || '0')).toBe(updatedAlertsCount);

    // Step 10: Repeat the test by generating another new conflict alert and measuring refresh time again
    const secondStartTime = Date.now();
    await page.evaluate(async () => {
      await fetch('/api/conflicts/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource: 'Meeting Room D',
          timestamp: new Date().toISOString(),
          severity: 'Medium',
          description: 'Resource conflict detected'
        })
      });
    });

    await page.waitForFunction(
      (expectedCount) => {
        const alerts = document.querySelectorAll('[data-testid="conflict-alert-item"]');
        return alerts.length > expectedCount;
      },
      updatedAlertsCount,
      { timeout: 3000 }
    );
    const secondEndTime = Date.now();
    const secondElapsedTime = secondEndTime - secondStartTime;

    expect(secondElapsedTime).toBeLessThanOrEqual(2000);
    const finalAlertsCount = await page.locator('[data-testid="conflict-alert-item"]').count();
    expect(finalAlertsCount).toBe(updatedAlertsCount + 1);
  });
});