import { test, expect } from '@playwright/test';

test.describe('Email Notifications for Scheduling Conflicts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify email notification is sent upon conflict detection', async ({ page }) => {
    // Step 1: Configure user email notification preferences
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="profile-settings-link"]');
    await expect(page.locator('[data-testid="email-notification-section"]')).toBeVisible();
    
    // Enable email notifications for scheduling conflicts
    await page.check('[data-testid="enable-conflict-notifications-checkbox"]');
    await page.fill('[data-testid="notification-email-input"]', 'scheduler@example.com');
    await page.click('[data-testid="save-preferences-button"]');
    
    // Verify preferences saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Step 2: Navigate to scheduling module and create first schedule entry
    await page.click('[data-testid="scheduling-module-link"]');
    await page.click('[data-testid="create-schedule-button"]');
    
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    
    // Step 3: Create second conflicting schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:30');
    await page.fill('[data-testid="end-time-input"]', '11:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Trigger conflict detection
    await expect(page.locator('[data-testid="conflict-detected-message"]')).toBeVisible();
    
    // Verify email notification is sent
    await page.waitForTimeout(2000); // Wait for email processing
    
    // Navigate to notification logs to verify email was sent
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="notification-logs-link"]');
    
    const emailLogEntry = page.locator('[data-testid="email-log-entry"]').first();
    await expect(emailLogEntry).toBeVisible();
    await expect(emailLogEntry).toContainText('scheduler@example.com');
    await expect(emailLogEntry).toContainText('Scheduling Conflict Detected');
    
    // Verify email contains accurate conflict details
    await emailLogEntry.click();
    await expect(page.locator('[data-testid="email-details-panel"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="email-details-panel"]')).toContainText('2024-03-15');
    await expect(page.locator('[data-testid="email-details-panel"]')).toContainText('10:00');
    await expect(page.locator('[data-testid="email-details-panel"]')).toContainText('11:00');
  });

  test('Validate email delivery status tracking', async ({ page }) => {
    // Navigate to scheduling module
    await page.click('[data-testid="scheduling-module-link"]');
    
    // Create first schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Create conflicting schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-16');
    await page.fill('[data-testid="start-time-input"]', '14:30');
    await page.fill('[data-testid="end-time-input"]', '15:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for conflict detection and email processing
    await page.waitForTimeout(3000);
    
    // Navigate to system administration or notification logs
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs-link"]');
    
    // Locate the test email notification entry
    const emailLogEntry = page.locator('[data-testid="email-log-entry"]').first();
    await expect(emailLogEntry).toBeVisible();
    
    // Verify delivery status is logged
    await expect(emailLogEntry.locator('[data-testid="delivery-status"]')).toContainText(/Sent|Delivered/);
    
    // Verify timestamp is recorded
    const timestamp = await emailLogEntry.locator('[data-testid="email-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    expect(timestamp).toMatch(/\d{4}-\d{2}-\d{2}/);
    
    // Check for additional tracking information
    await emailLogEntry.click();
    await expect(page.locator('[data-testid="recipient-email"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-subject"]')).toContainText('Scheduling Conflict');
    await expect(page.locator('[data-testid="delivery-confirmation"]')).toBeVisible();
  });

  test('Ensure email is sent within 5 minutes of conflict detection', async ({ page }) => {
    // Navigate to scheduling module
    await page.click('[data-testid="scheduling-module-link"]');
    
    // Note current system time
    const testStartTime = new Date();
    
    // Create first schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Training Room C');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-17');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.fill('[data-testid="end-time-input"]', '10:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    await page.waitForSelector('[data-testid="schedule-success-message"]');
    
    // Create conflicting schedule entry and record conflict detection time
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Training Room C');
    await page.fill('[data-testid="schedule-date-input"]', '2024-03-17');
    await page.fill('[data-testid="start-time-input"]', '09:30');
    await page.fill('[data-testid="end-time-input"]', '10:30');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for conflict detection message
    await expect(page.locator('[data-testid="conflict-detected-message"]')).toBeVisible();
    const conflictDetectionTime = new Date();
    
    // Navigate to system logs to get exact conflict detection timestamp
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="system-logs-link"]');
    
    const conflictLogEntry = page.locator('[data-testid="conflict-log-entry"]').first();
    await expect(conflictLogEntry).toBeVisible();
    
    const conflictTimestampText = await conflictLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    
    // Navigate to notification logs
    await page.click('[data-testid="notification-logs-link"]');
    
    // Wait up to 5 minutes for email to be sent
    await page.waitForSelector('[data-testid="email-log-entry"]', { timeout: 300000 });
    
    const emailLogEntry = page.locator('[data-testid="email-log-entry"]').first();
    await expect(emailLogEntry).toBeVisible();
    
    // Get email sent timestamp
    const emailTimestampText = await emailLogEntry.locator('[data-testid="email-timestamp"]').textContent();
    
    // Calculate time difference
    const emailSentTime = new Date(emailTimestampText || '');
    const timeDifferenceMs = emailSentTime.getTime() - conflictDetectionTime.getTime();
    const timeDifferenceMinutes = timeDifferenceMs / (1000 * 60);
    
    // Verify time difference is less than or equal to 5 minutes
    expect(timeDifferenceMinutes).toBeLessThanOrEqual(5);
    
    // Additional verification from email details
    await emailLogEntry.click();
    await expect(page.locator('[data-testid="email-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="delivery-time-info"]')).toContainText(/within.*minutes/);
  });
});