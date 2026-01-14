import { test, expect } from '@playwright/test';

test.describe('Alert Channel Preferences Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate alert channel preference saving (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the alert preferences page from the user settings menu
    await page.click('[data-testid="user-settings-menu"]');
    await page.click('[data-testid="alert-preferences-link"]');
    
    // Expected Result: Preferences UI is displayed
    await expect(page.locator('[data-testid="alert-preferences-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Alert Preferences');

    // Step 2: Select the email checkbox and enter a valid email address
    const emailCheckbox = page.locator('[data-testid="email-channel-checkbox"]');
    await emailCheckbox.check();
    await expect(emailCheckbox).toBeChecked();
    
    await page.fill('[data-testid="email-input"]', 'scheduler@example.com');
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue('scheduler@example.com');

    // Step 3: Select the SMS checkbox and enter a valid phone number
    const smsCheckbox = page.locator('[data-testid="sms-channel-checkbox"]');
    await smsCheckbox.check();
    await expect(smsCheckbox).toBeChecked();
    
    await page.fill('[data-testid="sms-input"]', '+1234567890');
    await expect(page.locator('[data-testid="sms-input"]')).toHaveValue('+1234567890');

    // Expected Result: Inputs accepted without validation errors
    await expect(page.locator('[data-testid="email-validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="sms-validation-error"]')).not.toBeVisible();

    // Step 4: Click the 'Save Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: System confirms successful save
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Step 5: Refresh the alert preferences page
    await page.reload();
    
    // Verify preferences persisted after refresh
    await expect(page.locator('[data-testid="email-channel-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue('scheduler@example.com');
    await expect(page.locator('[data-testid="sms-channel-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="sms-input"]')).toHaveValue('+1234567890');
  });

  test('Verify alerts sent via configured channels (happy-path)', async ({ page }) => {
    // Pre-requisite: Configure email and SMS channels
    await page.click('[data-testid="user-settings-menu"]');
    await page.click('[data-testid="alert-preferences-link"]');
    await page.check('[data-testid="email-channel-checkbox"]');
    await page.fill('[data-testid="email-input"]', 'scheduler@example.com');
    await page.check('[data-testid="sms-channel-checkbox"]');
    await page.fill('[data-testid="sms-input"]', '+1234567890');
    await page.uncheck('[data-testid="inapp-channel-checkbox"]');
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 1: Create a scheduling conflict by double-booking a resource
    await page.goto('/schedule');
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-name-input"]', 'Conflict Schedule 1');
    await page.selectOption('[data-testid="resource-select"]', 'Resource-A');
    await page.fill('[data-testid="start-time-input"]', '2024-02-01T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-01T12:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-created-message"]')).toBeVisible();

    // Create overlapping schedule to trigger conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-name-input"]', 'Conflict Schedule 2');
    await page.selectOption('[data-testid="resource-select"]', 'Resource-A');
    await page.fill('[data-testid="start-time-input"]', '2024-02-01T11:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-01T13:00');
    await page.click('[data-testid="save-schedule-button"]');

    // Expected Result: Alert sent via email and SMS as configured
    // Wait for alert delivery (maximum 2 seconds as per success metrics)
    await page.waitForTimeout(2000);

    // Step 2: Check alert reception on email and SMS
    // Navigate to notifications/alerts page to verify delivery
    await page.goto('/alerts/history');
    
    const latestAlert = page.locator('[data-testid="alert-item"]').first();
    await expect(latestAlert).toBeVisible();
    await expect(latestAlert).toContainText('Scheduling conflict');
    
    // Verify alert was sent via email
    await expect(latestAlert.locator('[data-testid="email-channel-indicator"]')).toBeVisible();
    await expect(latestAlert.locator('[data-testid="email-channel-status"]')).toContainText('Sent');
    
    // Verify alert was sent via SMS
    await expect(latestAlert.locator('[data-testid="sms-channel-indicator"]')).toBeVisible();
    await expect(latestAlert.locator('[data-testid="sms-channel-status"]')).toContainText('Sent');
    
    // Verify that in-app notification was NOT received (since it was not configured)
    await expect(latestAlert.locator('[data-testid="inapp-channel-indicator"]')).not.toBeVisible();
  });

  test('Test validation of invalid contact info (error-case)', async ({ page }) => {
    // Step 1: Navigate to the alert preferences page
    await page.click('[data-testid="user-settings-menu"]');
    await page.click('[data-testid="alert-preferences-link"]');
    await expect(page.locator('[data-testid="alert-preferences-page"]')).toBeVisible();

    // Step 2: Select the email checkbox and enter an invalid email format
    await page.check('[data-testid="email-channel-checkbox"]');
    await page.fill('[data-testid="email-input"]', 'invalidemail@');

    // Step 3: Click the 'Save Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Validation error displayed preventing save
    await expect(page.locator('[data-testid="email-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-validation-error"]')).toContainText('Invalid email format');
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 4: Correct the email address to a valid format
    await page.fill('[data-testid="email-input"]', 'scheduler@example.com');
    
    // Verify validation error is cleared
    await expect(page.locator('[data-testid="email-validation-error"]')).not.toBeVisible();

    // Step 5: Select the SMS checkbox and enter an invalid phone number format
    await page.check('[data-testid="sms-channel-checkbox"]');
    await page.fill('[data-testid="sms-input"]', '123');

    // Step 6: Click the 'Save Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Validation error displayed preventing save
    await expect(page.locator('[data-testid="sms-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="sms-validation-error"]')).toContainText('Invalid phone number format');
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 7: Correct the phone number to a valid format
    await page.fill('[data-testid="sms-input"]', '+1234567890');
    
    // Verify validation error is cleared
    await expect(page.locator('[data-testid="sms-validation-error"]')).not.toBeVisible();

    // Step 8: Click the 'Save Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Verify no validation errors present
    await expect(page.locator('[data-testid="email-validation-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="sms-validation-error"]')).not.toBeVisible();
  });
});