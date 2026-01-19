import { test, expect } from '@playwright/test';

test.describe('Alert Preference Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'Test@1234');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify alert preference configuration and application (happy-path)', async ({ page }) => {
    const startTime = Date.now();

    // Step 1: Navigate to alert preference settings from main dashboard
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-settings-link"]');
    
    // Expected Result: Settings UI is displayed
    await expect(page.locator('[data-testid="alert-preferences-settings"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /alert preferences/i })).toBeVisible();

    // Step 2: Verify all alert channel options are visible and accessible
    await expect(page.locator('[data-testid="email-alert-toggle"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-notification-toggle"]')).toBeVisible();
    await expect(page.locator('[data-testid="popup-alert-toggle"]')).toBeVisible();

    // Step 3: Enable email alert channel
    const emailToggle = page.locator('[data-testid="email-alert-toggle"]');
    const isEmailEnabled = await emailToggle.isChecked();
    if (!isEmailEnabled) {
      await emailToggle.click();
    }
    await expect(emailToggle).toBeChecked();

    // Step 4: Enable dashboard notifications channel
    const dashboardToggle = page.locator('[data-testid="dashboard-notification-toggle"]');
    const isDashboardEnabled = await dashboardToggle.isChecked();
    if (!isDashboardEnabled) {
      await dashboardToggle.click();
    }
    await expect(dashboardToggle).toBeChecked();

    // Step 5: Disable pop-up alert channel
    const popupToggle = page.locator('[data-testid="popup-alert-toggle"]');
    const isPopupEnabled = await popupToggle.isChecked();
    if (isPopupEnabled) {
      await popupToggle.click();
    }
    await expect(popupToggle).not.toBeChecked();

    // Step 6: Save alert preferences
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences are saved successfully
    await expect(page.locator('[data-testid="success-message"]').filter({ hasText: /preferences saved/i })).toBeVisible({ timeout: 5000 });
    
    const saveTime = Date.now() - startTime;
    expect(saveTime).toBeLessThan(1000);

    // Step 7: Refresh the alert preference settings page
    await page.reload();
    await expect(page.locator('[data-testid="alert-preferences-settings"]')).toBeVisible();

    // Verify preferences persisted after refresh
    await expect(page.locator('[data-testid="email-alert-toggle"]')).toBeChecked();
    await expect(page.locator('[data-testid="dashboard-notification-toggle"]')).toBeChecked();
    await expect(page.locator('[data-testid="popup-alert-toggle"]')).not.toBeChecked();

    // Step 8: Navigate away and return to settings
    await page.click('[data-testid="dashboard-link"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-settings-link"]');

    // Verify preferences still persisted
    const retrievalStartTime = Date.now();
    await expect(page.locator('[data-testid="alert-preferences-settings"]')).toBeVisible();
    const retrievalTime = Date.now() - retrievalStartTime;
    expect(retrievalTime).toBeLessThan(1000);

    await expect(page.locator('[data-testid="email-alert-toggle"]')).toBeChecked();
    await expect(page.locator('[data-testid="dashboard-notification-toggle"]')).toBeChecked();
    await expect(page.locator('[data-testid="popup-alert-toggle"]')).not.toBeChecked();

    // Step 9: Trigger an alert event
    await page.goto('/dashboard');
    await page.click('[data-testid="trigger-test-alert-button"]');
    
    // Expected Result: No pop-up alert is displayed
    await page.waitForTimeout(2000);
    await expect(page.locator('[data-testid="popup-alert-modal"]')).not.toBeVisible();
    await expect(page.locator('.popup-alert')).not.toBeVisible();

    // Expected Result: Dashboard notification is displayed
    await expect(page.locator('[data-testid="dashboard-notifications-section"]')).toBeVisible();
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-item"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText(/alert/i);

    // Note: Email verification would require email service integration or mock
    // This is a placeholder for email verification logic
    // In real scenario, this would check email inbox via API or email testing service
  });

  test('Verify alert preference settings UI is displayed', async ({ page }) => {
    // Action: Navigate to alert preference settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-settings-link"]');
    
    // Expected Result: Settings UI is displayed
    await expect(page.locator('[data-testid="alert-preferences-settings"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-alert-toggle"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-notification-toggle"]')).toBeVisible();
    await expect(page.locator('[data-testid="popup-alert-toggle"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-preferences-button"]')).toBeVisible();
  });

  test('Verify enabling and disabling alert channels saves preferences', async ({ page }) => {
    // Navigate to alert preference settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-settings-link"]');
    
    // Action: Enable and disable alert channels
    await page.locator('[data-testid="email-alert-toggle"]').click();
    await page.locator('[data-testid="popup-alert-toggle"]').click();
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences are saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/saved/i);
  });

  test('Verify alerts are delivered according to configured preferences', async ({ page }) => {
    // Setup: Configure preferences to disable pop-ups
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-settings-link"]');
    
    const popupToggle = page.locator('[data-testid="popup-alert-toggle"]');
    if (await popupToggle.isChecked()) {
      await popupToggle.click();
    }
    
    const dashboardToggle = page.locator('[data-testid="dashboard-notification-toggle"]');
    if (!await dashboardToggle.isChecked()) {
      await dashboardToggle.click();
    }
    
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Action: Trigger alerts
    await page.goto('/dashboard');
    await page.click('[data-testid="trigger-test-alert-button"]');
    
    // Expected Result: Alerts are delivered according to preferences
    await page.waitForTimeout(1500);
    await expect(page.locator('[data-testid="popup-alert-modal"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="dashboard-notifications-section"]')).toBeVisible();
  });

  test('Verify preference operations complete within 1 second', async ({ page }) => {
    // Navigate to alert preference settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-settings-link"]');
    
    // Measure save operation time
    const saveStartTime = Date.now();
    await page.locator('[data-testid="email-alert-toggle"]').click();
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const saveTime = Date.now() - saveStartTime;
    
    expect(saveTime).toBeLessThan(1000);
    
    // Measure retrieval operation time
    const retrievalStartTime = Date.now();
    await page.reload();
    await expect(page.locator('[data-testid="alert-preferences-settings"]')).toBeVisible();
    const retrievalTime = Date.now() - retrievalStartTime;
    
    expect(retrievalTime).toBeLessThan(1000);
  });
});