import { test, expect } from '@playwright/test';

test.describe('Alert Preferences Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify alert preference modification and persistence', async ({ page }) => {
    // Step 1: Navigate to user profile or settings menu
    await page.click('[data-testid="user-profile-menu"]');
    await expect(page.locator('[data-testid="settings-dropdown"]')).toBeVisible();

    // Step 2: Click on 'Alert Preferences' or 'Notification Settings' option
    await page.click('[data-testid="alert-preferences-link"]');
    await expect(page.locator('[data-testid="alert-preferences-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Alert Preferences');

    // Step 3: Review current alert type settings
    const conflictsCheckbox = page.locator('[data-testid="alert-type-conflicts"]');
    const remindersCheckbox = page.locator('[data-testid="alert-type-reminders"]');
    await expect(conflictsCheckbox).toBeVisible();
    await expect(remindersCheckbox).toBeVisible();

    // Step 4: Select or deselect desired alert types
    await conflictsCheckbox.check();
    await expect(conflictsCheckbox).toBeChecked();
    await remindersCheckbox.uncheck();
    await expect(remindersCheckbox).not.toBeChecked();

    // Step 5: Change alert channel from current setting to a different option
    const inAppChannel = page.locator('[data-testid="channel-in-app"]');
    const emailChannel = page.locator('[data-testid="channel-email"]');
    await inAppChannel.check();
    await emailChannel.check();
    await expect(inAppChannel).toBeChecked();
    await expect(emailChannel).toBeChecked();

    // Step 6: Modify frequency setting
    await page.selectOption('[data-testid="frequency-select"]', 'daily-digest');
    await expect(page.locator('[data-testid="frequency-select"]')).toHaveValue('daily-digest');

    // Step 7: Click 'Save' or 'Apply' button to save preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Step 8: Navigate away from the alert preferences page and return to it
    await page.click('[data-testid="dashboard-link"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-preferences-link"]');

    // Verify preferences persisted
    await expect(page.locator('[data-testid="alert-type-conflicts"]')).toBeChecked();
    await expect(page.locator('[data-testid="alert-type-reminders"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="channel-in-app"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="frequency-select"]')).toHaveValue('daily-digest');

    // Step 9: Create or trigger a test alert condition
    await page.goto('/schedule');
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-title"]', 'Test Schedule Conflict');
    await page.fill('[data-testid="schedule-date"]', '2024-12-31');
    await page.fill('[data-testid="schedule-time"]', '10:00');
    await page.fill('[data-testid="schedule-resource"]', 'Room A');
    await page.click('[data-testid="save-schedule-button"]');

    // Create conflicting schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-title"]', 'Conflicting Schedule');
    await page.fill('[data-testid="schedule-date"]', '2024-12-31');
    await page.fill('[data-testid="schedule-time"]', '10:00');
    await page.fill('[data-testid="schedule-resource"]', 'Room A');
    await page.click('[data-testid="save-schedule-button"]');

    // Step 10: Verify alert delivery through the configured channels
    await page.click('[data-testid="alerts-icon"]');
    await expect(page.locator('[data-testid="alert-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-notification"]')).toContainText('conflict');

    // Step 11: Check alert delivery timing matches the configured frequency
    await expect(page.locator('[data-testid="alert-frequency-indicator"]')).toContainText('Daily Digest');

    // Step 12: Log out and log back in to the system
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');

    // Step 13: Access alert preferences settings again
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-preferences-link"]');

    // Verify preferences still persisted after logout/login
    await expect(page.locator('[data-testid="alert-type-conflicts"]')).toBeChecked();
    await expect(page.locator('[data-testid="alert-type-reminders"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="channel-in-app"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="frequency-select"]')).toHaveValue('daily-digest');
  });

  test('Validate preference input validation', async ({ page }) => {
    // Step 1: Navigate to alert preferences settings page
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="alert-preferences-link"]');
    await expect(page.locator('[data-testid="alert-preferences-page"]')).toBeVisible();

    // Step 2: Attempt to deselect all alert types
    await page.locator('[data-testid="alert-type-conflicts"]').uncheck();
    await page.locator('[data-testid="alert-type-reminders"]').uncheck();
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('At least one alert type must be selected');

    // Re-enable alert types for next test
    await page.locator('[data-testid="alert-type-conflicts"]').check();

    // Step 3: Attempt to deselect all alert channels
    await page.locator('[data-testid="channel-in-app"]').uncheck();
    await page.locator('[data-testid="channel-email"]').uncheck();
    await page.locator('[data-testid="channel-sms"]').uncheck();
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('At least one alert channel must be selected');

    // Re-enable a channel for next test
    await page.locator('[data-testid="channel-in-app"]').check();

    // Step 4: Select SMS channel and enter an invalid phone number format
    await page.locator('[data-testid="channel-sms"]').check();
    await expect(page.locator('[data-testid="sms-phone-input"]')).toBeVisible();
    await page.fill('[data-testid="sms-phone-input"]', 'abc123');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="phone-validation-error"]')).toContainText('Invalid phone number format');

    // Try incomplete number
    await page.fill('[data-testid="sms-phone-input"]', '123');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="phone-validation-error"]')).toContainText('Invalid phone number format');

    // Step 5: Select email channel and enter an invalid email address
    await page.locator('[data-testid="channel-email"]').check();
    await expect(page.locator('[data-testid="email-input"]')).toBeVisible();
    await page.fill('[data-testid="email-input"]', 'invalidemail');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="email-validation-error"]')).toContainText('Invalid email address');

    // Try another invalid format
    await page.fill('[data-testid="email-input"]', 'test@');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="email-validation-error"]')).toContainText('Invalid email address');

    // Step 6: Try to save preferences with validation errors present
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 7: Correct one validation error but leave others unresolved
    await page.fill('[data-testid="email-input"]', 'valid@example.com');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="phone-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 8: Correct all validation errors with valid inputs
    await page.fill('[data-testid="sms-phone-input"]', '+1234567890');
    await expect(page.locator('[data-testid="phone-validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="email-validation-error"]')).not.toBeVisible();

    // Step 9: Click 'Save' button with all valid inputs
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 10: Attempt to submit preferences using API with invalid JSON payload
    const response = await page.request.post('/api/user/preferences', {
      data: {
        alertTypes: null,
        channels: 'invalid_string_instead_of_array',
        frequency: 12345
      }
    });
    expect(response.status()).toBe(400);
    const responseBody = await response.json();
    expect(responseBody.error).toBeTruthy();

    // Attempt with missing required fields
    const response2 = await page.request.post('/api/user/preferences', {
      data: {
        alertTypes: ['conflicts']
      }
    });
    expect(response2.status()).toBe(400);
    const responseBody2 = await response2.json();
    expect(responseBody2.error).toContain('required');

    // Step 11: Verify that invalid preferences were not saved to the database
    await page.reload();
    await expect(page.locator('[data-testid="alert-type-conflicts"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-in-app"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-sms"]')).toBeChecked();
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue('valid@example.com');
    await expect(page.locator('[data-testid="sms-phone-input"]')).toHaveValue('+1234567890');
  });
});