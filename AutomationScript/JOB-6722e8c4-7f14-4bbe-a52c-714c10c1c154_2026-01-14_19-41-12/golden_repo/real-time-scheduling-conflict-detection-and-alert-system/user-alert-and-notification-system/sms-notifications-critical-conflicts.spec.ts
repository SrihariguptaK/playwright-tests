import { test, expect } from '@playwright/test';

test.describe('SMS Notifications for Critical Scheduling Conflicts', () => {
  const BASE_URL = process.env.BASE_URL || 'https://scheduling-app.example.com';
  const SCHEDULER_EMAIL = 'scheduler@example.com';
  const SCHEDULER_PASSWORD = 'SecurePass123!';
  const TEST_PHONE_NUMBER = '+1234567890';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
    
    // Login with scheduler credentials
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
  });

  test('Validate SMS notification sent for critical conflicts', async ({ page, request }) => {
    // Navigate to scheduling section
    await page.goto(`${BASE_URL}/scheduling`);
    
    // Create or trigger a critical scheduling conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'High-Priority Conference Room');
    await page.fill('[data-testid="schedule-date-input"]', '2024-12-15');
    await page.fill('[data-testid="schedule-time-input"]', '14:00');
    await page.selectOption('[data-testid="priority-select"]', 'critical');
    
    // Note timestamp before triggering conflict
    const conflictTriggerTime = Date.now();
    
    // Create conflicting schedule to trigger critical conflict
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify conflict is marked as critical in UI
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="conflict-severity"]')).toHaveText('Critical');
    
    // Wait for SMS to be sent (within 10 seconds)
    await page.waitForTimeout(2000);
    
    // Access SMS delivery logs
    await page.goto(`${BASE_URL}/admin/notifications/sms-logs`);
    
    // Verify SMS was generated and sent
    const smsLogEntry = page.locator('[data-testid="sms-log-entry"]').first();
    await expect(smsLogEntry).toBeVisible();
    
    // Verify SMS contains conflict summary
    await expect(smsLogEntry.locator('[data-testid="sms-recipient"]')).toContainText(TEST_PHONE_NUMBER);
    await expect(smsLogEntry.locator('[data-testid="sms-content"]')).toContainText('Critical conflict');
    await expect(smsLogEntry.locator('[data-testid="sms-content"]')).toContainText('High-Priority Conference Room');
    
    // Verify delivery status is successful
    await expect(smsLogEntry.locator('[data-testid="delivery-status"]')).toHaveText('Delivered');
    
    // Calculate and verify delivery time
    const deliveryTimestamp = await smsLogEntry.locator('[data-testid="delivery-timestamp"]').getAttribute('data-timestamp');
    const deliveryTime = parseInt(deliveryTimestamp || '0');
    const timeDifference = deliveryTime - conflictTriggerTime;
    
    // Verify SMS was sent within 10 seconds
    expect(timeDifference).toBeLessThanOrEqual(10000);
    
    // Verify SMS includes contact information
    await expect(smsLogEntry.locator('[data-testid="sms-content"]')).toContainText('Contact:');
  });

  test('Verify SMS opt-in and opt-out functionality', async ({ page }) => {
    // Navigate to user settings
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="settings-menu-item"]');
    
    // Navigate to notification preferences
    await page.click('[data-testid="notifications-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();
    
    // Locate SMS notification toggle
    const smsToggle = page.locator('[data-testid="sms-notifications-toggle"]');
    await expect(smsToggle).toBeVisible();
    
    // Disable SMS notifications
    const isEnabled = await smsToggle.isChecked();
    if (isEnabled) {
      await smsToggle.click();
    }
    
    // Save preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Verify opt-out preference persists
    await page.reload();
    await expect(page.locator('[data-testid="sms-notifications-toggle"]')).not.toBeChecked();
    
    // Trigger a critical conflict
    await page.goto(`${BASE_URL}/scheduling`);
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Test Resource Opt-Out');
    await page.fill('[data-testid="schedule-date-input"]', '2024-12-16');
    await page.fill('[data-testid="schedule-time-input"]', '15:00');
    await page.selectOption('[data-testid="priority-select"]', 'critical');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait 15 seconds
    await page.waitForTimeout(15000);
    
    // Check SMS delivery logs
    await page.goto(`${BASE_URL}/admin/notifications/sms-logs`);
    
    // Verify no SMS was sent
    const recentLogs = page.locator('[data-testid="sms-log-entry"]');
    const logCount = await recentLogs.count();
    
    if (logCount > 0) {
      const latestLog = recentLogs.first();
      const logContent = await latestLog.locator('[data-testid="sms-content"]').textContent();
      expect(logContent).not.toContain('Test Resource Opt-Out');
    }
    
    // Re-enable SMS notifications
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="settings-menu-item"]');
    await page.click('[data-testid="notifications-tab"]');
    
    const smsToggleReEnable = page.locator('[data-testid="sms-notifications-toggle"]');
    await smsToggleReEnable.check();
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Trigger another critical conflict
    await page.goto(`${BASE_URL}/scheduling`);
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Test Resource Opt-In');
    await page.fill('[data-testid="schedule-date-input"]', '2024-12-17');
    await page.fill('[data-testid="schedule-time-input"]', '16:00');
    await page.selectOption('[data-testid="priority-select"]', 'critical');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for SMS delivery
    await page.waitForTimeout(3000);
    
    // Verify SMS was sent
    await page.goto(`${BASE_URL}/admin/notifications/sms-logs`);
    const newSmsLog = page.locator('[data-testid="sms-log-entry"]').first();
    await expect(newSmsLog).toBeVisible();
    await expect(newSmsLog.locator('[data-testid="sms-content"]')).toContainText('Test Resource Opt-In');
    await expect(newSmsLog.locator('[data-testid="delivery-status"]')).toHaveText('Delivered');
  });

  test('Test SMS message content and formatting', async ({ page, context }) => {
    // Trigger a critical conflict with specific known details
    await page.goto(`${BASE_URL}/scheduling`);
    await page.click('[data-testid="create-schedule-button"]');
    
    const resourceName = 'Executive Meeting Room A';
    const scheduleDate = '2024-12-20';
    const scheduleTime = '10:30';
    
    await page.fill('[data-testid="resource-name-input"]', resourceName);
    await page.fill('[data-testid="schedule-date-input"]', scheduleDate);
    await page.fill('[data-testid="schedule-time-input"]', scheduleTime);
    await page.selectOption('[data-testid="priority-select"]', 'critical');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Wait for SMS to be sent
    await page.waitForTimeout(3000);
    
    // Access SMS delivery logs
    await page.goto(`${BASE_URL}/admin/notifications/sms-logs`);
    
    const smsLogEntry = page.locator('[data-testid="sms-log-entry"]').first();
    await expect(smsLogEntry).toBeVisible();
    
    // Verify SMS sender ID
    const senderId = await smsLogEntry.locator('[data-testid="sms-sender-id"]').textContent();
    expect(senderId).toMatch(/SCHEDULE|ALERT|[A-Z0-9]{3,11}/);
    
    // Get SMS content
    const smsContent = await smsLogEntry.locator('[data-testid="sms-content"]').textContent();
    
    // Verify message length (within SMS limits)
    expect(smsContent?.length || 0).toBeLessThanOrEqual(160);
    
    // Verify SMS contains accurate conflict summary
    expect(smsContent).toContain('Critical');
    expect(smsContent).toContain(resourceName);
    
    // Verify essential conflict details
    expect(smsContent).toContain(scheduleDate);
    expect(smsContent).toContain(scheduleTime);
    
    // Verify contact information is included
    const contactInfoRegex = /Contact:|Call:|Phone:|\+?\d{10,}/;
    expect(smsContent).toMatch(contactInfoRegex);
    
    // Check for shortened URLs or links
    const urlRegex = /(https?:\/\/[^\s]+)|(bit\.ly|tinyurl\.com)/gi;
    const urls = smsContent?.match(urlRegex);
    
    if (urls && urls.length > 0) {
      // Test first URL if present
      const testUrl = urls[0];
      await expect(smsLogEntry.locator('[data-testid="sms-link"]')).toHaveAttribute('href', testUrl);
      
      // Verify link is not broken by checking in new tab
      const [newPage] = await Promise.all([
        context.waitForEvent('page'),
        smsLogEntry.locator('[data-testid="sms-link"]').click()
      ]);
      
      await newPage.waitForLoadState('domcontentloaded');
      expect(newPage.url()).toBeTruthy();
      await newPage.close();
    }
    
    // Verify no formatting issues
    expect(smsContent).not.toMatch(/\s{2,}/);
    expect(smsContent).not.toMatch(/\n{2,}/);
    expect(smsContent?.trim()).toBe(smsContent);
    
    // Verify special characters and dates are formatted correctly
    const dateFormatRegex = /\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}\/\d{4}/;
    expect(smsContent).toMatch(dateFormatRegex);
    
    const timeFormatRegex = /\d{1,2}:\d{2}(\s?(AM|PM))?/i;
    expect(smsContent).toMatch(timeFormatRegex);
    
    // Verify phone numbers are formatted correctly if present
    const phoneRegex = /\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/;
    if (smsContent?.match(phoneRegex)) {
      const phoneMatch = smsContent.match(phoneRegex);
      expect(phoneMatch).toBeTruthy();
    }
    
    // Verify message readability - no truncated text
    expect(smsContent).not.toMatch(/\.\.\.$/);
    expect(smsContent).not.toContain('[truncated]');
    
    // Verify SMS display metadata
    await expect(smsLogEntry.locator('[data-testid="sms-character-count"]')).toBeVisible();
    const charCount = await smsLogEntry.locator('[data-testid="sms-character-count"]').textContent();
    expect(parseInt(charCount || '0')).toBeLessThanOrEqual(160);
  });
});