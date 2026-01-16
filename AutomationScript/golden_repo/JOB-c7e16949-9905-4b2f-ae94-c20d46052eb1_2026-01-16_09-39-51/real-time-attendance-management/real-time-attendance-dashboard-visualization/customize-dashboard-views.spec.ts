import { test, expect } from '@playwright/test';

test.describe('Customize Dashboard Views - Manager', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager and navigate to dashboard
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');
  });

  test('Validate adding and removing dashboard widgets', async ({ page }) => {
    // Step 1: Enter dashboard customization mode
    await page.click('[data-testid="customize-dashboard-button"]');
    await expect(page.locator('[data-testid="customization-ui"]')).toBeVisible();
    await expect(page.locator('[data-testid="add-widget-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-layout-button"]')).toBeVisible();

    // Verify existing widgets show edit controls
    const existingWidgets = page.locator('[data-testid^="widget-"]');
    const firstWidget = existingWidgets.first();
    await expect(firstWidget.locator('[data-testid="remove-widget-button"]')).toBeVisible();
    await expect(firstWidget.locator('[data-testid="drag-handle"]')).toBeVisible();

    // Step 2: Add a new widget to the dashboard
    await page.click('[data-testid="add-widget-button"]');
    await expect(page.locator('[data-testid="widget-selector-modal"]')).toBeVisible();
    
    // Select Attendance Summary widget
    await page.click('[data-testid="widget-option-attendance-summary"]');
    await page.click('[data-testid="confirm-add-widget-button"]');
    
    // Verify widget appears in dashboard layout
    await expect(page.locator('[data-testid="widget-attendance-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="widget-attendance-summary"]')).toContainText('Attendance Summary');

    // Step 3: Remove an existing widget
    const widgetToRemove = page.locator('[data-testid="widget-attendance-summary"]');
    await widgetToRemove.locator('[data-testid="remove-widget-button"]').click();
    
    // Confirm removal if confirmation dialog appears
    const confirmDialog = page.locator('[data-testid="confirm-remove-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="confirm-remove-button"]');
    }
    
    // Verify widget is removed from dashboard layout
    await expect(page.locator('[data-testid="widget-attendance-summary"]')).not.toBeVisible();
  });

  test('Validate saving and loading custom layouts', async ({ page }) => {
    // Enter customization mode
    await page.click('[data-testid="customize-dashboard-button"]');
    await expect(page.locator('[data-testid="customization-ui"]')).toBeVisible();

    // Add a widget to customize the layout
    await page.click('[data-testid="add-widget-button"]');
    await page.click('[data-testid="widget-option-attendance-summary"]');
    await page.click('[data-testid="confirm-add-widget-button"]');
    await expect(page.locator('[data-testid="widget-attendance-summary"]')).toBeVisible();

    // Step 1: Save current dashboard layout
    await page.click('[data-testid="save-layout-button"]');
    
    // Wait for save confirmation
    await expect(page.locator('[data-testid="save-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-success-message"]')).toContainText(/saved successfully/i);
    
    // Exit customization mode
    const exitButton = page.locator('[data-testid="exit-customization-button"]');
    if (await exitButton.isVisible()) {
      await exitButton.click();
    }

    // Note the widget arrangement for verification
    const widgetCount = await page.locator('[data-testid^="widget-"]').count();
    const hasAttendanceSummary = await page.locator('[data-testid="widget-attendance-summary"]').isVisible();

    // Step 2: Reload dashboard and verify saved layout loads automatically
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Verify customized layout persists after reload
    await expect(page.locator('[data-testid="widget-attendance-summary"]')).toBeVisible();
    const reloadedWidgetCount = await page.locator('[data-testid^="widget-"]').count();
    expect(reloadedWidgetCount).toBe(widgetCount);

    // Log out and log back in to verify persistence across sessions
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Log back in
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForLoadState('networkidle');

    // Verify layout persists across sessions
    await expect(page.locator('[data-testid="widget-attendance-summary"]')).toBeVisible();
    const sessionWidgetCount = await page.locator('[data-testid^="widget-"]').count();
    expect(sessionWidgetCount).toBe(widgetCount);
  });

  test('Test configuration of data refresh intervals', async ({ page }) => {
    // Navigate to dashboard settings
    await page.click('[data-testid="dashboard-settings-button"]');
    await expect(page.locator('[data-testid="dashboard-settings-modal"]')).toBeVisible();

    // Step 1: Set data refresh interval to 60 seconds
    await page.click('[data-testid="refresh-interval-dropdown"]');
    await page.click('[data-testid="refresh-interval-option-60"]');
    
    // Verify selection
    await expect(page.locator('[data-testid="refresh-interval-dropdown"]')).toContainText('60 seconds');

    // Save settings
    await page.click('[data-testid="save-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-message"]')).toBeVisible();
    
    // Close settings modal
    await page.click('[data-testid="close-settings-button"]');
    await expect(page.locator('[data-testid="dashboard-settings-modal"]')).not.toBeVisible();

    // Note current data values
    const initialTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    const initialDataValue = await page.locator('[data-testid="attendance-count"]').textContent();

    // Step 2: Wait for 60 seconds and verify dashboard refreshes data
    // Listen for API refresh calls
    const refreshPromise = page.waitForResponse(
      response => response.url().includes('/api/dashboard') && response.status() === 200,
      { timeout: 65000 }
    );

    // Wait for the refresh to occur (60 seconds + buffer)
    await page.waitForTimeout(61000);

    // Verify refresh occurred
    const refreshResponse = await refreshPromise;
    expect(refreshResponse.ok()).toBeTruthy();

    // Verify timestamp or data values have been updated
    const updatedTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(updatedTimestamp).not.toBe(initialTimestamp);

    // Verify auto-refresh indicator is active
    await expect(page.locator('[data-testid="auto-refresh-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="auto-refresh-indicator"]')).toContainText('60s');
  });
});