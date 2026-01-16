import { test, expect } from '@playwright/test';

test.describe('SMS Notifications for Critical Scheduling Conflicts', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const testPhoneNumber = '+1234567890';
  const testEmail = 'scheduler@test.com';
  const testPassword = 'Test123!';

  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', testEmail);
    await page.fill('[data-testid="password-input"]', testPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify SMS notification is sent for critical conflicts', async ({ page }) => {
    // Step 1: Configure user SMS preferences
    await page.goto(`${baseURL}/profile/settings`);
    await page.click('[data-testid="sms-notifications-tab"]');
    
    // Enable SMS notifications
    const smsToggle = page.locator('[data-testid="enable-sms-notifications"]');
    if (!(await smsToggle.isChecked())) {
      await smsToggle.check();
    }
    
    // Enter valid phone number in international format
    await page.fill('[data-testid="phone-number-input"]', testPhoneNumber);
    
    // Enable critical conflict notifications
    await page.check('[data-testid="critical-conflicts-checkbox"]');
    
    // Save preferences
    await page.click('[data-testid="save-preferences-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved');
    
    // Step 2: Trigger critical scheduling conflict
    await page.goto(`${baseURL}/scheduling`);
    
    // Create first schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-name-input"]', 'Resource Booking 1');
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-02-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-15T12:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-created-message"]')).toBeVisible();
    
    // Create conflicting schedule entry (double-booking)
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-name-input"]', 'Resource Booking 2');
    await page.fill('[data-testid="resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-02-15T11:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-15T13:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify conflict detection
    await expect(page.locator('[data-testid="critical-conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('Critical scheduling conflict detected');
    
    // Step 3: Check SMS notification was sent
    await page.goto(`${baseURL}/notifications/sms-log`);
    
    // Wait for SMS to be logged (within 3 minutes)
    await page.waitForSelector('[data-testid="sms-notification-entry"]', { timeout: 180000 });
    
    const smsEntry = page.locator('[data-testid="sms-notification-entry"]').first();
    await expect(smsEntry).toBeVisible();
    
    // Verify SMS contains accurate conflict details
    await smsEntry.click();
    const smsDetails = page.locator('[data-testid="sms-details-panel"]');
    await expect(smsDetails.locator('[data-testid="conflict-id"]')).toBeVisible();
    await expect(smsDetails.locator('[data-testid="schedule-names"]')).toContainText('Resource Booking 1');
    await expect(smsDetails.locator('[data-testid="schedule-names"]')).toContainText('Resource Booking 2');
    await expect(smsDetails.locator('[data-testid="time-overlap"]')).toContainText('11:00');
    await expect(smsDetails.locator('[data-testid="severity-level"]')).toContainText('Critical');
    await expect(smsDetails.locator('[data-testid="recipient-phone"]')).toContainText(testPhoneNumber);
  });

  test('Validate SMS delivery tracking', async ({ page }) => {
    // Step 1: Navigate to SMS notification settings
    await page.goto(`${baseURL}/profile/settings`);
    await page.click('[data-testid="sms-notifications-tab"]');
    
    // Ensure SMS notifications are enabled
    const smsToggle = page.locator('[data-testid="enable-sms-notifications"]');
    if (!(await smsToggle.isChecked())) {
      await smsToggle.check();
      await page.fill('[data-testid="phone-number-input"]', testPhoneNumber);
      await page.click('[data-testid="save-preferences-button"]');
      await page.waitForSelector('[data-testid="success-message"]');
    }
    
    // Initiate test SMS notification
    await page.click('[data-testid="send-test-sms-button"]');
    await page.selectOption('[data-testid="test-scenario-select"]', 'critical-conflict');
    await page.click('[data-testid="confirm-test-sms-button"]');
    
    // Capture the tracking ID
    const trackingIdElement = page.locator('[data-testid="sms-tracking-id"]');
    await expect(trackingIdElement).toBeVisible();
    const trackingId = await trackingIdElement.textContent();
    
    // Monitor SMS gateway response
    await expect(page.locator('[data-testid="gateway-response-status"]')).toContainText('Sent');
    
    // Step 2: Access SMS delivery logs
    await page.goto(`${baseURL}/admin/sms-delivery-logs`);
    
    // Search for test SMS using tracking ID
    await page.fill('[data-testid="search-tracking-id-input"]', trackingId || '');
    await page.click('[data-testid="search-button"]');
    
    // Wait for search results
    await page.waitForSelector('[data-testid="sms-log-entry"]');
    
    const logEntry = page.locator('[data-testid="sms-log-entry"]').first();
    await expect(logEntry).toBeVisible();
    
    // Verify delivery status is logged with complete metadata
    await logEntry.click();
    const logDetails = page.locator('[data-testid="sms-log-details"]');
    
    await expect(logDetails.locator('[data-testid="sent-time"]')).toBeVisible();
    await expect(logDetails.locator('[data-testid="delivered-time"]')).toBeVisible();
    await expect(logDetails.locator('[data-testid="status-code"]')).toBeVisible();
    await expect(logDetails.locator('[data-testid="delivery-status"]')).toContainText(/Delivered|Sent/);
    await expect(logDetails.locator('[data-testid="recipient-phone"]')).toContainText(testPhoneNumber);
    await expect(logDetails.locator('[data-testid="tracking-id-display"]')).toContainText(trackingId || '');
    
    // Verify metadata completeness
    await expect(logDetails.locator('[data-testid="gateway-provider"]')).toBeVisible();
    await expect(logDetails.locator('[data-testid="message-length"]')).toBeVisible();
    await expect(logDetails.locator('[data-testid="notification-type"]')).toContainText('Critical Conflict');
  });

  test('Ensure SMS sent within 3 minutes of conflict detection', async ({ page }) => {
    // Configure SMS preferences first
    await page.goto(`${baseURL}/profile/settings`);
    await page.click('[data-testid="sms-notifications-tab"]');
    
    const smsToggle = page.locator('[data-testid="enable-sms-notifications"]');
    if (!(await smsToggle.isChecked())) {
      await smsToggle.check();
      await page.fill('[data-testid="phone-number-input"]', testPhoneNumber);
      await page.check('[data-testid="critical-conflicts-checkbox"]');
      await page.click('[data-testid="save-preferences-button"]');
      await page.waitForSelector('[data-testid="success-message"]');
    }
    
    // Step 1: Record current system timestamp
    await page.goto(`${baseURL}/scheduling`);
    const conflictDetectionStartTime = Date.now();
    
    // Step 2: Create critical scheduling conflict
    // Create first schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-name-input"]', 'Personnel Assignment 1');
    await page.fill('[data-testid="personnel-select"]', 'John Doe');
    await page.fill('[data-testid="start-time-input"]', '2024-02-20T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-20T16:00');
    await page.click('[data-testid="save-schedule-button"]');
    await page.waitForSelector('[data-testid="schedule-created-message"]');
    
    // Create overlapping schedule entry for same personnel
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="schedule-name-input"]', 'Personnel Assignment 2');
    await page.fill('[data-testid="personnel-select"]', 'John Doe');
    await page.fill('[data-testid="start-time-input"]', '2024-02-20T15:00');
    await page.fill('[data-testid="end-time-input"]', '2024-02-20T17:00');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify conflict is detected
    await expect(page.locator('[data-testid="critical-conflict-alert"]')).toBeVisible();
    
    // Capture conflict detection timestamp from system
    const conflictTimestamp = await page.locator('[data-testid="conflict-detected-timestamp"]').textContent();
    
    // Step 3: Monitor SMS gateway logs
    await page.goto(`${baseURL}/admin/sms-gateway-logs`);
    
    // Wait for SMS processing entry (max 3 minutes)
    await page.waitForSelector('[data-testid="sms-processing-entry"]', { timeout: 180000 });
    
    const processingEntry = page.locator('[data-testid="sms-processing-entry"]').first();
    await expect(processingEntry).toBeVisible();
    
    // Step 4: Check notification queue and delivery time
    await processingEntry.click();
    const processingDetails = page.locator('[data-testid="sms-processing-details"]');
    
    const detectionTime = await processingDetails.locator('[data-testid="detection-time"]').textContent();
    const queueTime = await processingDetails.locator('[data-testid="queue-time"]').textContent();
    const gatewaySubmissionTime = await processingDetails.locator('[data-testid="gateway-submission-time"]').textContent();
    const deliveryTime = await processingDetails.locator('[data-testid="delivery-time"]').textContent();
    
    // Verify all timing stages are logged
    await expect(processingDetails.locator('[data-testid="detection-time"]')).toBeVisible();
    await expect(processingDetails.locator('[data-testid="queue-time"]')).toBeVisible();
    await expect(processingDetails.locator('[data-testid="gateway-submission-time"]')).toBeVisible();
    await expect(processingDetails.locator('[data-testid="delivery-time"]')).toBeVisible();
    
    // Step 5: Calculate elapsed time
    const smsReceivedTime = Date.now();
    const totalElapsedTimeMs = smsReceivedTime - conflictDetectionStartTime;
    const totalElapsedTimeMinutes = totalElapsedTimeMs / 1000 / 60;
    
    // Verify SMS was sent within 3 minutes
    expect(totalElapsedTimeMinutes).toBeLessThanOrEqual(3);
    
    // Verify in SMS delivery logs
    await page.goto(`${baseURL}/notifications/sms-log`);
    const latestSms = page.locator('[data-testid="sms-notification-entry"]').first();
    await latestSms.click();
    
    const smsDetails = page.locator('[data-testid="sms-details-panel"]');
    await expect(smsDetails.locator('[data-testid="delivery-status"]')).toContainText(/Delivered|Sent/);
    
    // Verify the SMS relates to the conflict we created
    await expect(smsDetails.locator('[data-testid="schedule-names"]')).toContainText('Personnel Assignment');
    await expect(smsDetails.locator('[data-testid="conflict-type"]')).toContainText('Overlapping');
    
    // Log timing information for verification
    console.log(`Total elapsed time: ${totalElapsedTimeMinutes.toFixed(2)} minutes`);
    console.log(`Detection time: ${detectionTime}`);
    console.log(`Queue time: ${queueTime}`);
    console.log(`Gateway submission time: ${gatewaySubmissionTime}`);
    console.log(`Delivery time: ${deliveryTime}`);
  });
});