import { test, expect } from '@playwright/test';

test.describe('Notification Preference Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate notification preference configuration UI (happy-path)', async ({ page }) => {
    // Step 1: Navigate to user profile menu and click on 'Notification Settings' option
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-settings-option"]');
    
    // Expected Result: Preference options are displayed
    await expect(page.locator('[data-testid="notification-preferences-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-channels-section"]')).toBeVisible();
    
    // Step 2: Review the notification preference options displayed on the page
    await expect(page.locator('[data-testid="email-notification-checkbox"]')).toBeVisible();
    await expect(page.locator('[data-testid="inapp-notification-checkbox"]')).toBeVisible();
    
    // Step 3: Select 'Email' notification channel by checking the checkbox
    await page.check('[data-testid="email-notification-checkbox"]');
    await expect(page.locator('[data-testid="email-notification-checkbox"]')).toBeChecked();
    
    // Step 4: Select 'In-app' notification channel by checking the checkbox
    await page.check('[data-testid="inapp-notification-checkbox"]');
    await expect(page.locator('[data-testid="inapp-notification-checkbox"]')).toBeChecked();
    
    // Step 5: Click 'Save' or 'Update Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Selections are accepted and saved
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Step 6: Create a scheduling conflict by attempting to book overlapping appointments
    await page.goto('/scheduling');
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time-input"]', '10:00');
    await page.fill('[data-testid="appointment-duration-input"]', '60');
    await page.fill('[data-testid="patient-name-input"]', 'John Doe');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Create overlapping appointment
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time-input"]', '10:30');
    await page.fill('[data-testid="appointment-duration-input"]', '60');
    await page.fill('[data-testid="patient-name-input"]', 'Jane Smith');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Step 7: Check in-app notifications panel or bell icon
    await page.click('[data-testid="notifications-bell-icon"]');
    
    // Expected Result: Alert delivered via selected channels
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'conflict' })).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'conflict' })).toContainText('Scheduling conflict detected');
  });

  test('Verify immediate application of preference changes (happy-path)', async ({ page }) => {
    // Step 1: Navigate to notification settings page
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-settings-option"]');
    await expect(page.locator('[data-testid="notification-preferences-page"]')).toBeVisible();
    
    // Step 2: Uncheck 'Email' notification channel
    await page.uncheck('[data-testid="email-notification-checkbox"]');
    await expect(page.locator('[data-testid="email-notification-checkbox"]')).not.toBeChecked();
    
    // Step 3: Check 'In-app' notification channel
    await page.check('[data-testid="inapp-notification-checkbox"]');
    await expect(page.locator('[data-testid="inapp-notification-checkbox"]')).toBeChecked();
    
    // Step 4: Click 'Save' or 'Update Preferences' button
    const saveTime = new Date();
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Changes saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Step 5: Note the current time and immediately create a scheduling conflict
    await page.goto('/scheduling');
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-16');
    await page.fill('[data-testid="appointment-time-input"]', '14:00');
    await page.fill('[data-testid="appointment-duration-input"]', '45');
    await page.fill('[data-testid="patient-name-input"]', 'Alice Johnson');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Create overlapping appointment
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-16');
    await page.fill('[data-testid="appointment-time-input"]', '14:20');
    await page.fill('[data-testid="appointment-duration-input"]', '45');
    await page.fill('[data-testid="patient-name-input"]', 'Bob Williams');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Step 6: Check in-app notifications panel
    await page.click('[data-testid="notifications-bell-icon"]');
    
    // Expected Result: Alert sent according to new preferences
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'conflict' })).toBeVisible();
    
    // Step 7: Access system logs or admin panel to review preference change events
    await page.goto('/admin/logs');
    await page.fill('[data-testid="log-search-input"]', 'notification preference');
    await page.click('[data-testid="search-logs-button"]');
    
    // Expected Result: Preferences applied without delay
    await expect(page.locator('[data-testid="log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="log-entry"]').first()).toContainText('Notification preferences updated');
    
    // Step 8: Verify log entries show alert delivery method matches updated preferences
    await page.fill('[data-testid="log-search-input"]', 'conflict alert delivery');
    await page.click('[data-testid="search-logs-button"]');
    await expect(page.locator('[data-testid="log-entry"]').filter({ hasText: 'in-app' })).toBeVisible();
    await expect(page.locator('[data-testid="log-entry"]').filter({ hasText: 'email' })).not.toBeVisible();
  });

  test('Ensure validation of user contact information (error-case)', async ({ page }) => {
    // Step 1: Navigate to notification settings page
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-settings-option"]');
    await expect(page.locator('[data-testid="notification-preferences-page"]')).toBeVisible();
    
    // Step 2: Click on 'Edit Contact Information' or email field to modify email address
    await page.click('[data-testid="edit-contact-info-button"]');
    await expect(page.locator('[data-testid="email-input"]')).toBeVisible();
    
    // Step 3: Enter invalid email address 'invalidemail@' in the email field
    await page.fill('[data-testid="email-input"]', 'invalidemail@');
    
    // Step 4: Select 'Email' notification channel checkbox
    await page.check('[data-testid="email-notification-checkbox"]');
    await expect(page.locator('[data-testid="email-notification-checkbox"]')).toBeChecked();
    
    // Step 5: Click 'Save' or 'Update Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: System displays validation error and rejects input
    await expect(page.locator('[data-testid="email-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-validation-error"]')).toContainText('Please enter a valid email address');
    
    // Step 6: Verify that the invalid email is highlighted or marked with error indicator
    await expect(page.locator('[data-testid="email-input"]')).toHaveClass(/error|invalid/);
    
    // Step 7: Clear the email field and enter valid email address 'scheduler@example.com'
    await page.fill('[data-testid="email-input"]', '');
    await page.fill('[data-testid="email-input"]', 'scheduler@example.com');
    
    // Step 8: Ensure 'Email' notification channel remains selected
    await expect(page.locator('[data-testid="email-notification-checkbox"]')).toBeChecked();
    
    // Step 9: Click 'Save' or 'Update Preferences' button
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences accepted and saved
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    await expect(page.locator('[data-testid="email-validation-error"]')).not.toBeVisible();
    
    // Step 10: Create a scheduling conflict to trigger an alert
    await page.goto('/scheduling');
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-17');
    await page.fill('[data-testid="appointment-time-input"]', '09:00');
    await page.fill('[data-testid="appointment-duration-input"]', '30');
    await page.fill('[data-testid="patient-name-input"]', 'Charlie Brown');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Create overlapping appointment
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', '2024-03-17');
    await page.fill('[data-testid="appointment-time-input"]', '09:15');
    await page.fill('[data-testid="appointment-duration-input"]', '30');
    await page.fill('[data-testid="patient-name-input"]', 'Diana Prince');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Expected Result: Alert delivered successfully
    await page.click('[data-testid="notifications-bell-icon"]');
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'conflict' })).toBeVisible();
  });
});