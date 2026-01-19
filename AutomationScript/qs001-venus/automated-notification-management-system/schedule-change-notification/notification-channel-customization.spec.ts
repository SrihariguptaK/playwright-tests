import { test, expect } from '@playwright/test';

test.describe('Story-28: Customize Notification Channels', () => {
  test.beforeEach(async ({ page }) => {
    // Login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate saving and updating notification preferences (happy-path)', async ({ page }) => {
    // Step 1: Navigate to user settings or profile section
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await expect(page).toHaveURL(/.*settings/);

    // Step 2: Click on notification preferences or notification settings option
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Step 3: Review the currently selected notification channels
    const emailCheckbox = page.locator('[data-testid="notification-channel-email"]');
    const smsCheckbox = page.locator('[data-testid="notification-channel-sms"]');
    const inAppCheckbox = page.locator('[data-testid="notification-channel-inapp"]');
    
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toContainText('Notification Preferences');
    const initialEmailState = await emailCheckbox.isChecked();
    const initialSmsState = await smsCheckbox.isChecked();

    // Step 4: Deselect one currently enabled channel (e.g., uncheck email notification)
    if (initialEmailState) {
      await emailCheckbox.uncheck();
      await expect(emailCheckbox).not.toBeChecked();
    }

    // Step 5: Select a previously disabled channel (e.g., enable SMS notification)
    if (!initialSmsState) {
      await smsCheckbox.check();
      await expect(smsCheckbox).toBeChecked();
      // Fill in phone number for SMS
      await page.fill('[data-testid="sms-phone-number"]', '+1234567890');
    }

    // Step 6: Click the Save or Update button to save the new preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Step 7: Navigate away from the preferences page and return to verify persistence
    await page.click('[data-testid="dashboard-link"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-preferences-tab"]');

    // Verify preferences persisted
    await expect(emailCheckbox).not.toBeChecked();
    await expect(smsCheckbox).toBeChecked();

    // Step 8: Trigger a notification event by updating a schedule entry
    await page.click('[data-testid="schedule-link"]');
    await page.click('[data-testid="schedule-entry-1"]');
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="schedule-time-input"]', '14:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-updated-message"]')).toBeVisible();

    // Step 9: Check only the selected notification channels for notification delivery
    await page.click('[data-testid="notifications-icon"]');
    const notifications = page.locator('[data-testid="notification-list"]');
    await expect(notifications).toContainText('Schedule updated');
    
    // Step 10: Verify the deselected channel did not receive notification
    // Check notification delivery log
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-history-tab"]');
    const latestNotification = page.locator('[data-testid="notification-history-item"]').first();
    await expect(latestNotification).toContainText('SMS');
    await expect(latestNotification).not.toContainText('Email');
  });

  test('Verify validation of invalid channel inputs (error-case)', async ({ page }) => {
    // Step 1: Navigate to notification preferences UI
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Step 2: Enable email notification channel and enter an invalid email address
    const emailCheckbox = page.locator('[data-testid="notification-channel-email"]');
    await emailCheckbox.check();
    await page.fill('[data-testid="email-address-input"]', 'invalidemail.com');

    // Step 3: Click Save or move focus away from the email field to trigger validation
    await page.click('[data-testid="save-preferences-button"]');
    
    // Step 4: Verify validation error is displayed
    await expect(page.locator('[data-testid="email-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-validation-error"]')).toContainText('Please enter a valid email address');

    // Step 5: Verify that preferences are not saved with invalid email
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 6: Enable SMS notification channel and enter an invalid phone number
    const smsCheckbox = page.locator('[data-testid="notification-channel-sms"]');
    await smsCheckbox.check();
    await page.fill('[data-testid="sms-phone-number"]', '123');

    // Step 7: Click Save or move focus away from the phone field to trigger validation
    await page.click('[data-testid="save-preferences-button"]');

    // Step 8: Verify validation error for phone number is displayed
    await expect(page.locator('[data-testid="phone-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="phone-validation-error"]')).toContainText('Please enter a valid phone number');

    // Step 9: Verify that preferences are not saved with invalid phone number
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();

    // Step 10: Correct the email address to a valid format
    await page.fill('[data-testid="email-address-input"]', 'scheduler@example.com');
    await expect(page.locator('[data-testid="email-validation-error"]')).not.toBeVisible();

    // Step 11: Correct the phone number to a valid format
    await page.fill('[data-testid="sms-phone-number"]', '+1234567890');
    await expect(page.locator('[data-testid="phone-validation-error"]')).not.toBeVisible();

    // Step 12: Click Save button with all valid inputs
    await page.click('[data-testid="save-preferences-button"]');

    // Step 13: Verify that the corrected contact information is saved
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Verify saved values
    await expect(page.locator('[data-testid="email-address-input"]')).toHaveValue('scheduler@example.com');
    await expect(page.locator('[data-testid="sms-phone-number"]')).toHaveValue('+1234567890');
  });

  test('Ensure immediate effect of preference changes (happy-path)', async ({ page }) => {
    // Step 1: Navigate to notification preferences UI
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Step 2: Note the currently enabled notification channels
    const emailCheckbox = page.locator('[data-testid="notification-channel-email"]');
    const smsCheckbox = page.locator('[data-testid="notification-channel-sms"]');
    const inAppCheckbox = page.locator('[data-testid="notification-channel-inapp"]');
    
    // Ensure email and in-app are enabled, SMS is disabled
    await emailCheckbox.check();
    await page.fill('[data-testid="email-address-input"]', 'scheduler@example.com');
    await inAppCheckbox.check();
    await smsCheckbox.uncheck();
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await page.waitForTimeout(500);

    // Step 3: Change notification preferences by disabling email and enabling SMS
    await emailCheckbox.uncheck();
    await smsCheckbox.check();
    await page.fill('[data-testid="sms-phone-number"]', '+1234567890');

    // Step 4: Click Save button to update preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Step 5: Record the exact timestamp when preferences were saved
    const saveTimestamp = new Date().toISOString();
    console.log('Preferences saved at:', saveTimestamp);

    // Step 6: Immediately navigate to the scheduling module without logging out or waiting
    await page.click('[data-testid="schedule-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Step 7: Trigger a notification event by updating a schedule entry within seconds of saving preferences
    await page.click('[data-testid="schedule-entry-1"]');
    await page.click('[data-testid="edit-schedule-button"]');
    await page.fill('[data-testid="schedule-time-input"]', '15:30');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-updated-message"]')).toBeVisible();

    const notificationTimestamp = new Date().toISOString();
    console.log('Notification triggered at:', notificationTimestamp);

    // Step 8: Monitor notification delivery across all channels
    // Step 9: Check SMS channel for notification delivery
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-history-tab"]');
    
    const latestNotification = page.locator('[data-testid="notification-history-item"]').first();
    await expect(latestNotification).toBeVisible();
    await expect(latestNotification).toContainText('SMS');
    await expect(latestNotification).toContainText('+1234567890');

    // Step 10: Check in-app notification center
    await page.click('[data-testid="notifications-icon"]');
    const inAppNotifications = page.locator('[data-testid="notification-list"]');
    await expect(inAppNotifications).toContainText('Schedule updated');

    // Step 11: Check email inbox to verify no notification was sent
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-history-tab"]');
    
    const emailNotifications = page.locator('[data-testid="notification-history-item"]').filter({ hasText: 'Email' });
    const emailCount = await emailNotifications.count();
    
    // Verify no new email notification was sent after preference change
    if (emailCount > 0) {
      const latestEmailNotification = emailNotifications.first();
      const emailTimestamp = await latestEmailNotification.getAttribute('data-timestamp');
      // Ensure email notification timestamp is before preference change
      expect(new Date(emailTimestamp!) < new Date(saveTimestamp)).toBeTruthy();
    }

    // Step 12: Review notification delivery logs
    const deliveryLog = page.locator('[data-testid="notification-history-item"]').first();
    await expect(deliveryLog).toContainText('Delivered');
    await expect(deliveryLog).toContainText('SMS');
    await expect(deliveryLog).not.toContainText('Email');
    
    // Verify the notification was sent according to updated preferences
    const logChannels = await deliveryLog.locator('[data-testid="delivery-channels"]').textContent();
    expect(logChannels).toContain('SMS');
    expect(logChannels).toContain('In-App');
    expect(logChannels).not.toContain('Email');
  });
});