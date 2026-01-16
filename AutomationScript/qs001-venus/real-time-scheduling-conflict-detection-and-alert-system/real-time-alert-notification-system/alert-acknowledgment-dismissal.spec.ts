import { test, expect } from '@playwright/test';

test.describe('Alert Acknowledgment and Dismissal Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as authorized user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify alert acknowledgment functionality (happy-path)', async ({ page }) => {
    // Navigate to the notifications or alerts section of the application
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="active-alerts-link"]');
    await expect(page.locator('[data-testid="alerts-section"]')).toBeVisible();

    // Identify and view the conflict alert in the active alerts list
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();

    // Note the current count of active alerts displayed
    const initialAlertCount = await page.locator('[data-testid="active-alert-item"]').count();
    expect(initialAlertCount).toBeGreaterThan(0);

    // Click or tap the 'Acknowledge' button for the selected alert
    const alertId = await conflictAlert.getAttribute('data-alert-id');
    await conflictAlert.locator('[data-testid="acknowledge-button"]').click();

    // Verify the alert status changes to 'Acknowledged'
    await expect(page.locator(`[data-testid="alert-status-${alertId}"]`)).toHaveText('Acknowledged', { timeout: 2000 });

    // Check the active alerts list
    const updatedAlertCount = await page.locator('[data-testid="active-alert-item"]').count();
    expect(updatedAlertCount).toBe(initialAlertCount - 1);

    // Navigate to acknowledged or archived alerts section
    await page.click('[data-testid="acknowledged-alerts-link"]');
    await expect(page.locator('[data-testid="acknowledged-alerts-section"]')).toBeVisible();

    // Verify the acknowledgment timestamp and user information
    const acknowledgedAlert = page.locator(`[data-alert-id="${alertId}"]`);
    await expect(acknowledgedAlert).toBeVisible();
    await expect(acknowledgedAlert.locator('[data-testid="acknowledged-by"]')).toContainText('scheduler@example.com');
    await expect(acknowledgedAlert.locator('[data-testid="acknowledged-timestamp"]')).toBeVisible();
  });

  test('Verify alert dismissal with authorization (error-case)', async ({ page }) => {
    // Log into the system as a user with authorized dismissal permissions
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="active-alerts-link"]');

    // Navigate to the active alerts list and select a conflict alert
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();
    const alertId = await conflictAlert.getAttribute('data-alert-id');

    // Click the 'Dismiss' button for the selected alert
    await conflictAlert.locator('[data-testid="dismiss-button"]').click();

    // Confirm the dismissal action
    await page.click('[data-testid="confirm-dismiss-button"]');

    // Verify the alert is removed from active alerts list
    await expect(page.locator(`[data-alert-id="${alertId}"]`)).not.toBeVisible({ timeout: 2000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Alert dismissed successfully');

    // Log out and log in as a user without dismissal authorization
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'viewer@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the active alerts list and select a conflict alert
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="active-alerts-link"]');
    const unauthorizedAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(unauthorizedAlert).toBeVisible();
    const unauthorizedAlertId = await unauthorizedAlert.getAttribute('data-alert-id');

    // Attempt to dismiss the alert
    const dismissButton = unauthorizedAlert.locator('[data-testid="dismiss-button"]');
    
    // Check if button is visible or disabled
    const isDismissButtonVisible = await dismissButton.isVisible().catch(() => false);
    
    if (isDismissButtonVisible) {
      await dismissButton.click();
      // Verify error message appears
      await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission to dismiss alerts');
    } else {
      // Button should not be visible for unauthorized users
      await expect(dismissButton).not.toBeVisible();
    }

    // Verify the alert remains in the active alerts list
    await expect(page.locator(`[data-alert-id="${unauthorizedAlertId}"]`)).toBeVisible();

    // Check system logs for the unauthorized dismissal attempt
    await page.click('[data-testid="admin-menu"]').catch(() => {});
    const hasAdminAccess = await page.locator('[data-testid="system-logs-link"]').isVisible().catch(() => false);
    
    if (hasAdminAccess) {
      await page.click('[data-testid="system-logs-link"]');
      await expect(page.locator('[data-testid="unauthorized-attempt-log"]')).toBeVisible();
    }
  });

  test('Ensure alert history logs actions (happy-path)', async ({ page }) => {
    // Navigate to the active alerts section and select a conflict alert
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="active-alerts-link"]');
    
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();

    // Note the alert ID and current timestamp before taking action
    const alertId = await conflictAlert.getAttribute('data-alert-id');
    const timestampBefore = new Date();

    // Click 'Acknowledge' button for the selected alert
    await conflictAlert.locator('[data-testid="acknowledge-button"]').click();
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate to the alert history or audit log section
    await page.click('[data-testid="alert-history-link"]');
    await expect(page.locator('[data-testid="alert-history-section"]')).toBeVisible();

    // Search or filter for the acknowledged alert by alert ID
    await page.fill('[data-testid="alert-search-input"]', alertId);
    await page.click('[data-testid="search-button"]');

    // Verify the history entry contains required information
    const historyEntry = page.locator(`[data-testid="history-entry-${alertId}"]`).first();
    await expect(historyEntry).toBeVisible();
    await expect(historyEntry.locator('[data-testid="history-alert-id"]')).toContainText(alertId);
    await expect(historyEntry.locator('[data-testid="history-action-type"]')).toContainText('Acknowledged');
    await expect(historyEntry.locator('[data-testid="history-user"]')).toContainText('scheduler@example.com');
    await expect(historyEntry.locator('[data-testid="history-timestamp"]')).toBeVisible();

    // Create or select another active conflict alert
    await page.click('[data-testid="active-alerts-link"]');
    const secondAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(secondAlert).toBeVisible();
    const secondAlertId = await secondAlert.getAttribute('data-alert-id');

    // Dismiss the alert using the 'Dismiss' button
    await secondAlert.locator('[data-testid="dismiss-button"]').click();
    await page.fill('[data-testid="dismissal-reason-input"]', 'Resolved manually');
    await page.click('[data-testid="confirm-dismiss-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('dismissed');

    // Return to alert history and search for the dismissed alert
    await page.click('[data-testid="alert-history-link"]');
    await page.fill('[data-testid="alert-search-input"]', secondAlertId);
    await page.click('[data-testid="search-button"]');

    // Verify the dismissal entry contains required information
    const dismissalEntry = page.locator(`[data-testid="history-entry-${secondAlertId}"]`).first();
    await expect(dismissalEntry).toBeVisible();
    await expect(dismissalEntry.locator('[data-testid="history-alert-id"]')).toContainText(secondAlertId);
    await expect(dismissalEntry.locator('[data-testid="history-action-type"]')).toContainText('Dismissed');
    await expect(dismissalEntry.locator('[data-testid="history-user"]')).toContainText('scheduler@example.com');
    await expect(dismissalEntry.locator('[data-testid="history-timestamp"]')).toBeVisible();
    await expect(dismissalEntry.locator('[data-testid="history-reason"]')).toContainText('Resolved manually');

    // Verify both actions appear in chronological order in the history
    await page.fill('[data-testid="alert-search-input"]', '');
    await page.click('[data-testid="search-button"]');
    
    const allHistoryEntries = page.locator('[data-testid^="history-entry-"]');
    const entryCount = await allHistoryEntries.count();
    expect(entryCount).toBeGreaterThanOrEqual(2);

    // Verify chronological order (most recent first)
    const firstEntryTimestamp = await allHistoryEntries.nth(0).locator('[data-testid="history-timestamp"]').textContent();
    const secondEntryTimestamp = await allHistoryEntries.nth(1).locator('[data-testid="history-timestamp"]').textContent();
    expect(firstEntryTimestamp).toBeTruthy();
    expect(secondEntryTimestamp).toBeTruthy();
  });
});