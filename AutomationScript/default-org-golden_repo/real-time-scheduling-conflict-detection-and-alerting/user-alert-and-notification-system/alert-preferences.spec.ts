import { test, expect } from '@playwright/test';

test.describe('Alert Preference Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Save and apply alert preferences - happy path', async ({ page }) => {
    // Step 1: Navigate to alert preference settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-menu-item"]');
    await page.click('[data-testid="alert-preferences-tab"]');
    
    // Expected Result: Settings UI displayed
    await expect(page.locator('[data-testid="alert-preferences-form"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /alert preference/i })).toBeVisible();
    
    // Step 2: Select email and SMS as alert channels and set frequency to immediate
    await page.check('[data-testid="alert-channel-email"]');
    await page.check('[data-testid="alert-channel-sms"]');
    await page.selectOption('[data-testid="alert-frequency-dropdown"]', 'immediate');
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/preferences saved successfully/i);
    
    // Verify preferences are persisted
    await expect(page.locator('[data-testid="alert-channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="alert-channel-sms"]')).toBeChecked();
    await expect(page.locator('[data-testid="alert-frequency-dropdown"]')).toHaveValue('immediate');
    
    // Step 3: Trigger a scheduling conflict
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="create-schedule-button"]');
    
    // Create first schedule
    await page.fill('[data-testid="schedule-resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="schedule-start-time"]', '2024-02-01T10:00');
    await page.fill('[data-testid="schedule-end-time"]', '2024-02-01T12:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-created-message"]')).toBeVisible();
    
    // Create overlapping schedule to trigger conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="schedule-start-time"]', '2024-02-01T11:00');
    await page.fill('[data-testid="schedule-end-time"]', '2024-02-01T13:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Alerts received via email and SMS as configured
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText(/scheduling conflict/i);
    
    // Verify in-app notification
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText(/conflict/i);
    
    // Verify alert delivery channels indicator
    await expect(page.locator('[data-testid="alert-delivery-status"]')).toContainText(/email/i);
    await expect(page.locator('[data-testid="alert-delivery-status"]')).toContainText(/sms/i);
  });

  test('Validate input for alert preferences - error case', async ({ page }) => {
    // Navigate to alert preference settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-menu-item"]');
    await page.click('[data-testid="alert-preferences-tab"]');
    await expect(page.locator('[data-testid="alert-preferences-form"]')).toBeVisible();
    
    // Step 1: Enter invalid channel or frequency values
    // Attempt to manipulate form with invalid data
    await page.evaluate(() => {
      const frequencyInput = document.querySelector('[data-testid="alert-frequency-dropdown"]') as HTMLSelectElement;
      if (frequencyInput) {
        const option = document.createElement('option');
        option.value = '-5';
        option.text = 'Invalid Frequency';
        frequencyInput.appendChild(option);
        frequencyInput.value = '-5';
      }
    });
    
    // Uncheck all channels to create invalid state
    await page.uncheck('[data-testid="alert-channel-email"]');
    await page.uncheck('[data-testid="alert-channel-sms"]');
    await page.uncheck('[data-testid="alert-channel-inapp"]');
    
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Validation errors displayed preventing save
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText(/at least one channel/i);
    
    // Verify preferences were not saved
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Step 2: Correct inputs and save
    // Select valid channels
    await page.check('[data-testid="alert-channel-email"]');
    await page.check('[data-testid="alert-channel-inapp"]');
    
    // Select valid frequency
    await page.selectOption('[data-testid="alert-frequency-dropdown"]', 'immediate');
    
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/preferences saved successfully/i);
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Verify corrected preferences are persisted
    await expect(page.locator('[data-testid="alert-channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="alert-channel-inapp"]')).toBeChecked();
    await expect(page.locator('[data-testid="alert-frequency-dropdown"]')).toHaveValue('immediate');
  });

  test('Preference changes take effect immediately after saving', async ({ page }) => {
    // Navigate to alert preferences
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-menu-item"]');
    await page.click('[data-testid="alert-preferences-tab"]');
    
    // Set initial preferences
    await page.check('[data-testid="alert-channel-email"]');
    await page.selectOption('[data-testid="alert-frequency-dropdown"]', 'immediate');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Verify preferences are immediately active by checking API response
    const response = await page.request.get('/api/user/alert-preferences');
    expect(response.ok()).toBeTruthy();
    const preferences = await response.json();
    expect(preferences.channels).toContain('email');
    expect(preferences.frequency).toBe('immediate');
  });
});