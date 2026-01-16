import { test, expect } from '@playwright/test';

test.describe('Conflict Alert Management - Story 4', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify user can acknowledge conflict alerts (happy-path)', async ({ page }) => {
    // Navigate to the alerts or notifications section
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    
    // Verify that a conflict alert is displayed in the UI
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();
    await expect(conflictAlert).toContainText('Conflict');
    
    // Get alert ID for verification later
    const alertId = await conflictAlert.getAttribute('data-alert-id');
    
    // Locate and click the acknowledge button
    const acknowledgeButton = conflictAlert.locator('[data-testid="acknowledge-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();
    
    // Observe UI update after clicking acknowledge
    await page.waitForTimeout(500);
    const acknowledgedAlert = page.locator(`[data-alert-id="${alertId}"]`);
    await expect(acknowledgedAlert).toHaveAttribute('data-status', 'acknowledged');
    await expect(acknowledgedAlert.locator('[data-testid="alert-status-badge"]')).toContainText('Acknowledged');
    
    // Verify acknowledged alert remains visible but marked
    await expect(acknowledgedAlert).toBeVisible();
    
    // Refresh the browser or reload the alert list
    await page.reload();
    await page.waitForSelector('[data-testid="alerts-section"]');
    
    // Locate the previously acknowledged alert in the refreshed list
    const persistedAlert = page.locator(`[data-alert-id="${alertId}"]`);
    await expect(persistedAlert).toBeVisible();
    await expect(persistedAlert).toHaveAttribute('data-status', 'acknowledged');
    await expect(persistedAlert.locator('[data-testid="alert-status-badge"]')).toContainText('Acknowledged');
  });

  test('Verify user can dismiss conflict alerts (happy-path)', async ({ page }) => {
    // Navigate to the alerts or notifications section
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    
    // Verify that a conflict alert is displayed with full details
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();
    await expect(conflictAlert).toContainText('Conflict');
    
    // Get alert ID and count active alerts before dismissal
    const alertId = await conflictAlert.getAttribute('data-alert-id');
    const initialAlertCount = await page.locator('[data-testid="conflict-alert"]').count();
    
    // Locate and click the dismiss button
    const dismissButton = conflictAlert.locator('[data-testid="dismiss-button"]');
    await expect(dismissButton).toBeVisible();
    await dismissButton.click();
    
    // Observe UI update after clicking dismiss
    await page.waitForTimeout(500);
    
    // Verify dismissed alert is no longer visible in active alerts
    const dismissedAlert = page.locator(`[data-alert-id="${alertId}"]`);
    await expect(dismissedAlert).not.toBeVisible();
    
    // Verify alert count decreased
    const updatedAlertCount = await page.locator('[data-testid="conflict-alert"]').count();
    expect(updatedAlertCount).toBe(initialAlertCount - 1);
    
    // Refresh the browser or reload the alert list
    await page.reload();
    await page.waitForSelector('[data-testid="alerts-section"]');
    
    // Check that dismissed alert is not in active alerts list
    const activeAlerts = page.locator('[data-testid="conflict-alert"]');
    const alertIds = await activeAlerts.evaluateAll(alerts => 
      alerts.map(alert => alert.getAttribute('data-alert-id'))
    );
    expect(alertIds).not.toContain(alertId);
    
    // Navigate to alert history or archived alerts if available
    const historyLink = page.locator('[data-testid="alert-history-link"]');
    if (await historyLink.isVisible()) {
      await historyLink.click();
      await page.waitForSelector('[data-testid="alert-history-section"]');
      const archivedAlert = page.locator(`[data-alert-id="${alertId}"]`);
      await expect(archivedAlert).toBeVisible();
      await expect(archivedAlert).toHaveAttribute('data-status', 'dismissed');
    }
  });

  test('Ensure only authorized users can change alert status (error-case)', async ({ page }) => {
    // Logout from scheduler account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Log in with unauthorized user (read-only or viewer role)
    await page.fill('[data-testid="username-input"]', 'viewer@example.com');
    await page.fill('[data-testid="password-input"]', 'viewerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to alerts section
    await page.click('[data-testid="alerts-menu"]');
    await page.waitForSelector('[data-testid="alerts-section"]');
    
    // Locate a conflict alert
    const conflictAlert = page.locator('[data-testid="conflict-alert"]').first();
    await expect(conflictAlert).toBeVisible();
    const alertId = await conflictAlert.getAttribute('data-alert-id');
    
    // Check for acknowledge button and attempt to click if visible
    const acknowledgeButton = conflictAlert.locator('[data-testid="acknowledge-button"]');
    if (await acknowledgeButton.isVisible()) {
      await acknowledgeButton.click();
      
      // Verify error message is displayed
      const errorMessage = page.locator('[data-testid="error-message"]');
      await expect(errorMessage).toBeVisible();
      await expect(errorMessage).toContainText(/unauthorized|permission denied|not authorized/i);
    } else {
      // Verify buttons are not visible for unauthorized users
      await expect(acknowledgeButton).not.toBeVisible();
    }
    
    // Attempt to click dismiss button if visible
    const dismissButton = conflictAlert.locator('[data-testid="dismiss-button"]');
    if (await dismissButton.isVisible()) {
      await dismissButton.click();
      
      // Verify error message for dismiss action
      const errorMessage = page.locator('[data-testid="error-message"]');
      await expect(errorMessage).toBeVisible();
      await expect(errorMessage).toContainText(/unauthorized|permission denied|not authorized/i);
    } else {
      // Verify buttons are not visible for unauthorized users
      await expect(dismissButton).not.toBeVisible();
    }
    
    // Check alert status remains unchanged
    const alertStatus = await conflictAlert.getAttribute('data-status');
    expect(alertStatus).not.toBe('acknowledged');
    expect(alertStatus).not.toBe('dismissed');
    
    // Attempt direct API call with unauthorized credentials
    const response = await page.request.patch(`/api/alerts/${alertId}/status`, {
      headers: {
        'Authorization': 'Bearer viewer_token',
        'Content-Type': 'application/json'
      },
      data: {
        status: 'acknowledged'
      }
    });
    
    // Verify API returns unauthorized status
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toMatch(/unauthorized|forbidden|permission denied/i);
  });
});