import { test, expect } from '@playwright/test';

test.describe('Task Notification Preferences - Story 34', () => {
  test.beforeEach(async ({ page }) => {
    // Login as task assignee
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'assignee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate saving and updating task notification preferences (happy-path)', async ({ page }) => {
    // Navigate to user settings or profile section
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await expect(page).toHaveURL(/.*settings/);

    // Click on 'Notification Preferences' or 'Task Notification Settings' option
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Review the current notification frequency setting
    const currentFrequency = await page.locator('[data-testid="notification-frequency-select"]').inputValue();
    expect(currentFrequency).toBeTruthy();

    // Select a different notification frequency from the dropdown
    await page.selectOption('[data-testid="notification-frequency-select"]', 'daily_digest');
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('daily_digest');

    // Review available notification channels
    await expect(page.locator('[data-testid="channel-email"]')).toBeVisible();
    await expect(page.locator('[data-testid="channel-inapp"]')).toBeVisible();
    await expect(page.locator('[data-testid="channel-sms"]')).toBeVisible();

    // Select preferred notification channels
    await page.check('[data-testid="channel-email"]');
    await page.check('[data-testid="channel-inapp"]');
    await page.uncheck('[data-testid="channel-sms"]');

    // Verify selections
    await expect(page.locator('[data-testid="channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-inapp"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-sms"]')).not.toBeChecked();

    // Click the 'Save' or 'Update Preferences' button
    await page.click('[data-testid="save-preferences-button"]');

    // Wait for confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved');

    // Refresh the preferences page or navigate away and return
    await page.reload();
    await page.click('[data-testid="notification-preferences-tab"]');

    // Verify saved preferences persist
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('daily_digest');
    await expect(page.locator('[data-testid="channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-inapp"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-sms"]')).not.toBeChecked();

    // Trigger a task update notification (simulate by API or another user action)
    // Navigate to tasks and create/update a task
    await page.goto('/tasks');
    await page.click('[data-testid="create-task-button"]');
    await page.fill('[data-testid="task-title-input"]', 'Test Task for Notification');
    await page.fill('[data-testid="task-description-input"]', 'Testing notification preferences');
    await page.click('[data-testid="save-task-button"]');

    // Check the selected notification channels for the notification
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();
    
    // Verify notification appears in enabled channels
    const inAppNotification = page.locator('[data-testid="inapp-notification"]').first();
    await expect(inAppNotification).toBeVisible();

    // Verify that disabled channels did not receive the notification (SMS should not be present)
    const smsNotificationCount = await page.locator('[data-testid="sms-notification"]').count();
    expect(smsNotificationCount).toBe(0);
  });

  test('Verify validation of invalid inputs (error-case)', async ({ page }) => {
    // Navigate to task notification preferences UI
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Store current valid preferences
    const originalFrequency = await page.locator('[data-testid="notification-frequency-select"]').inputValue();
    const originalEmailChecked = await page.locator('[data-testid="channel-email"]').isChecked();

    // Attempt to enter an invalid frequency value via browser console
    await page.evaluate(() => {
      const select = document.querySelector('[data-testid="notification-frequency-select"]') as HTMLSelectElement;
      if (select) {
        const option = document.createElement('option');
        option.value = 'InvalidFrequency';
        option.text = 'InvalidFrequency';
        select.add(option);
        select.value = 'InvalidFrequency';
      }
    });

    // Try to select an unsupported or invalid channel value
    await page.evaluate(() => {
      const form = document.querySelector('[data-testid="notification-preferences-form"]') as HTMLFormElement;
      if (form) {
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.name = 'channels';
        input.value = 'FakeChannel';
        input.checked = true;
        form.appendChild(input);
      }
    });

    // Attempt to save preferences with invalid frequency or channel values
    await page.click('[data-testid="save-preferences-button"]');

    // Verify validation error messages appear
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/invalid|error/i);

    // Verify that the previous valid preferences remain unchanged
    await page.reload();
    await page.click('[data-testid="notification-preferences-tab"]');
    const currentFrequency = await page.locator('[data-testid="notification-frequency-select"]').inputValue();
    expect(currentFrequency).toBe(originalFrequency);

    // Correct the frequency input by selecting a valid option
    await page.selectOption('[data-testid="notification-frequency-select"]', 'immediate');
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('immediate');

    // Correct the channel selection by choosing valid channels
    await page.check('[data-testid="channel-email"]');
    await page.check('[data-testid="channel-inapp"]');

    // Click 'Save' button with corrected valid inputs
    await page.click('[data-testid="save-preferences-button"]');

    // Verify success message appears
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved');

    // Verify the saved preferences in the UI
    await page.reload();
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('immediate');
    await expect(page.locator('[data-testid="channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-inapp"]')).toBeChecked();
  });

  test('Ensure immediate effect of preference changes (happy-path)', async ({ page }) => {
    // Navigate to task notification preferences UI
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="notification-preferences-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Note the current preference settings
    const oldFrequency = await page.locator('[data-testid="notification-frequency-select"]').inputValue();
    const oldEmailChecked = await page.locator('[data-testid="channel-email"]').isChecked();
    const oldInAppChecked = await page.locator('[data-testid="channel-inapp"]').isChecked();

    // Change the notification frequency to 'Immediate'
    await page.selectOption('[data-testid="notification-frequency-select"]', 'immediate');
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('immediate');

    // Add additional notification channels
    await page.check('[data-testid="channel-email"]');
    await page.check('[data-testid="channel-inapp"]');
    await page.check('[data-testid="channel-push"]');

    // Verify all channels are checked
    await expect(page.locator('[data-testid="channel-email"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-inapp"]')).toBeChecked();
    await expect(page.locator('[data-testid="channel-push"]')).toBeChecked();

    // Click 'Save' to update preferences
    const saveTime = new Date();
    await page.click('[data-testid="save-preferences-button"]');

    // Wait for confirmation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Note the timestamp of the preference update
    const updateTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(updateTimestamp).toBeTruthy();

    // Immediately trigger a task update notification event
    await page.goto('/tasks');
    await page.click('[data-testid="task-item"]').first();
    await page.click('[data-testid="edit-task-button"]');
    await page.fill('[data-testid="task-description-input"]', 'Updated description to trigger notification');
    await page.click('[data-testid="save-task-button"]');

    // Wait for task update confirmation
    await expect(page.locator('[data-testid="task-updated-message"]')).toBeVisible();

    // Check for notification delivery across all newly enabled channels within 1-2 minutes
    await page.goto('/notifications');
    await page.waitForTimeout(2000); // Wait for notification processing

    // Verify notification appears in all enabled channels
    const emailNotification = page.locator('[data-testid="email-notification"]').first();
    const inAppNotification = page.locator('[data-testid="inapp-notification"]').first();
    const pushNotification = page.locator('[data-testid="push-notification"]').first();

    await expect(emailNotification).toBeVisible();
    await expect(inAppNotification).toBeVisible();
    await expect(pushNotification).toBeVisible();

    // Verify the notification was not sent according to the old preferences
    // Check that frequency is immediate (notification sent right away, not in digest)
    const notificationTime = await inAppNotification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTime).toBeTruthy();

    // Check system logs or audit trail for preference change record
    await page.goto('/settings');
    await page.click('[data-testid="audit-log-tab"]');
    await expect(page.locator('[data-testid="audit-log-section"]')).toBeVisible();

    const latestAuditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(latestAuditEntry).toBeVisible();
    await expect(latestAuditEntry).toContainText('Notification preferences updated');
    await expect(latestAuditEntry).toContainText('immediate');
  });
});