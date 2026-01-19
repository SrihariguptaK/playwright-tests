import { test, expect } from '@playwright/test';

test.describe('Email Notifications for Scheduling Conflicts', () => {
  let baseURL: string;
  let testUserEmail: string;

  test.beforeEach(async ({ page }) => {
    baseURL = process.env.BASE_URL || 'http://localhost:3000';
    testUserEmail = process.env.TEST_USER_EMAIL || 'scheduler@test.com';
    
    // Login as scheduler user
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', testUserEmail);
    await page.fill('[data-testid="password-input"]', 'Test123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify email notification sent on conflict detection', async ({ page }) => {
    // Note the current timestamp before triggering the conflict
    const conflictTriggerTime = new Date();
    
    // Navigate to scheduling page
    await page.goto(`${baseURL}/scheduling`);
    await expect(page.locator('[data-testid="scheduling-page"]')).toBeVisible();
    
    // Trigger a scheduling conflict by creating a conflicting schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-form"]')).toBeVisible();
    
    // Fill in schedule details that will conflict with existing entry
    await page.fill('[data-testid="schedule-resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-15');
    await page.fill('[data-testid="schedule-start-time-input"]', '10:00');
    await page.fill('[data-testid="schedule-end-time-input"]', '11:00');
    await page.fill('[data-testid="schedule-description-input"]', 'Team Meeting - Conflict Test');
    
    // Submit the conflicting schedule
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Verify conflict is detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('Scheduling conflict detected');
    
    // Wait and monitor for email notification delivery (within 30 seconds)
    await page.waitForTimeout(2000);
    
    // Navigate to email delivery logs
    await page.goto(`${baseURL}/admin/email-logs`);
    await expect(page.locator('[data-testid="email-logs-page"]')).toBeVisible();
    
    // Filter logs for recent emails
    await page.fill('[data-testid="log-search-input"]', testUserEmail);
    await page.click('[data-testid="search-button"]');
    
    // Verify email delivery status is logged as successful
    const emailLogEntry = page.locator('[data-testid="email-log-entry"]').first();
    await expect(emailLogEntry).toBeVisible({ timeout: 35000 });
    await expect(emailLogEntry.locator('[data-testid="email-status"]')).toContainText('Delivered');
    await expect(emailLogEntry.locator('[data-testid="email-subject"]')).toContainText('Scheduling Conflict');
    
    // Verify email was sent within 30 seconds
    const emailTimestamp = await emailLogEntry.locator('[data-testid="email-timestamp"]').textContent();
    const emailSentTime = new Date(emailTimestamp || '');
    const timeDifference = (emailSentTime.getTime() - conflictTriggerTime.getTime()) / 1000;
    expect(timeDifference).toBeLessThanOrEqual(30);
    
    // Verify email contains accurate conflict details
    await emailLogEntry.click();
    await expect(page.locator('[data-testid="email-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-body"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('2024-02-15');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('10:00');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('11:00');
  });

  test('Test email notification preference settings', async ({ page }) => {
    // Navigate to user settings or preferences page
    await page.goto(`${baseURL}/settings`);
    await expect(page.locator('[data-testid="settings-page"]')).toBeVisible();
    
    // Navigate to notifications tab
    await page.click('[data-testid="notifications-tab"]');
    await expect(page.locator('[data-testid="notification-preferences"]')).toBeVisible();
    
    // Locate the email notification configuration option
    const emailNotificationToggle = page.locator('[data-testid="email-notification-toggle"]');
    await expect(emailNotificationToggle).toBeVisible();
    
    // Disable email notifications by toggling off
    const isEnabled = await emailNotificationToggle.isChecked();
    if (isEnabled) {
      await emailNotificationToggle.uncheck();
    }
    
    // Save the preference changes
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Trigger a scheduling conflict in the system
    await page.goto(`${baseURL}/scheduling`);
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Conference Room B');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-16');
    await page.fill('[data-testid="schedule-start-time-input"]', '14:00');
    await page.fill('[data-testid="schedule-end-time-input"]', '15:00');
    await page.fill('[data-testid="schedule-description-input"]', 'Test Meeting - Disabled Notifications');
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Verify conflict is detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    
    // Wait 60 seconds and check email inbox via logs
    await page.waitForTimeout(60000);
    
    // Verify email delivery logs show no new emails sent
    await page.goto(`${baseURL}/admin/email-logs`);
    await page.fill('[data-testid="log-search-input"]', testUserEmail);
    await page.fill('[data-testid="log-date-filter"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="search-button"]');
    
    const noEmailsMessage = page.locator('[data-testid="no-emails-found"]');
    const emailCount = await page.locator('[data-testid="email-log-entry"]').count();
    
    // Verify no emails were sent (either no results or count is 0)
    if (await noEmailsMessage.isVisible()) {
      await expect(noEmailsMessage).toContainText('No emails found');
    } else {
      // If there are emails, verify none are for the recent conflict
      const recentEmailWithConflict = page.locator('[data-testid="email-log-entry"]').filter({ hasText: 'Conference Room B' });
      await expect(recentEmailWithConflict).toHaveCount(0);
    }
    
    // Return to user settings and enable email notifications
    await page.goto(`${baseURL}/settings`);
    await page.click('[data-testid="notifications-tab"]');
    await page.locator('[data-testid="email-notification-toggle"]').check();
    
    // Save the preference changes
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Trigger another scheduling conflict in the system
    await page.goto(`${baseURL}/scheduling`);
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-resource-input"]', 'Conference Room C');
    await page.fill('[data-testid="schedule-date-input"]', '2024-02-17');
    await page.fill('[data-testid="schedule-start-time-input"]', '09:00');
    await page.fill('[data-testid="schedule-end-time-input"]', '10:00');
    await page.fill('[data-testid="schedule-description-input"]', 'Test Meeting - Enabled Notifications');
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Verify conflict is detected
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    
    // Wait up to 30 seconds and check email inbox
    await page.waitForTimeout(5000);
    
    // Verify email delivery logs show email was sent
    await page.goto(`${baseURL}/admin/email-logs`);
    await page.fill('[data-testid="log-search-input"]', testUserEmail);
    await page.click('[data-testid="search-button"]');
    
    const enabledEmailLogEntry = page.locator('[data-testid="email-log-entry"]').first();
    await expect(enabledEmailLogEntry).toBeVisible({ timeout: 30000 });
    await expect(enabledEmailLogEntry.locator('[data-testid="email-status"]')).toContainText('Delivered');
    await expect(enabledEmailLogEntry.locator('[data-testid="email-subject"]')).toContainText('Scheduling Conflict');
    
    // Verify email contains conflict details for Conference Room C
    await enabledEmailLogEntry.click();
    await expect(page.locator('[data-testid="email-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-body"]')).toContainText('Conference Room C');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('2024-02-17');
  });
});