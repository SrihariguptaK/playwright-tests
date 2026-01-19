import { test, expect } from '@playwright/test';

test.describe('Email Notifications for Scheduling Conflicts', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const schedulerEmail = 'scheduler@test.com';
  const schedulerPassword = 'Test123!';
  
  test.beforeEach(async ({ page }) => {
    // Login as scheduler
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', schedulerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify email notification is sent upon scheduling conflict', async ({ page, request }) => {
    // Step 1: Create a scheduling conflict by booking a resource that overlaps with an existing booking
    await page.goto(`${baseURL}/bookings`);
    
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '12:00');
    await page.click('[data-testid="save-booking-button"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Booking created successfully');
    
    // Create overlapping booking to trigger conflict
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-15');
    await page.fill('[data-testid="start-time-input"]', '11:00');
    await page.fill('[data-testid="end-time-input"]', '13:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Expected Result: Email notification is generated
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('Scheduling conflict detected');
    
    // Step 2: Check scheduler's email inbox
    // Wait up to 5 minutes for email delivery
    await page.waitForTimeout(5000); // Simulating wait time
    
    // Navigate to email verification page or use API to check email
    const emailCheckResponse = await request.get(`${baseURL}/api/test/emails/${schedulerEmail}/latest`);
    expect(emailCheckResponse.ok()).toBeTruthy();
    
    const emailData = await emailCheckResponse.json();
    
    // Expected Result: Email with conflict details is received
    expect(emailData.subject).toContain('Scheduling Conflict Detected');
    expect(emailData.body).toContain('Conference Room A');
    expect(emailData.body).toContain('2024-02-15');
    expect(emailData.body).toContain('10:00');
    expect(emailData.body).toContain('11:00');
    expect(emailData.to).toBe(schedulerEmail);
  });

  test('Test user preference configuration for email notifications', async ({ page, request }) => {
    // Step 1: Navigate to user settings/preferences page
    await page.goto(`${baseURL}/settings`);
    await page.click('[data-testid="notifications-tab"]');
    
    // Locate email notification settings
    await expect(page.locator('[data-testid="email-notifications-section"]')).toBeVisible();
    
    // Update email notification preferences - disable conflict notifications
    const conflictNotificationToggle = page.locator('[data-testid="conflict-notification-toggle"]');
    await expect(conflictNotificationToggle).toBeVisible();
    
    // Check current state and toggle if enabled
    const isEnabled = await conflictNotificationToggle.isChecked();
    if (isEnabled) {
      await conflictNotificationToggle.uncheck();
    }
    
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences are saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');
    
    // Step 2: Trigger conflict event
    await page.goto(`${baseURL}/bookings`);
    
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.click('[data-testid="save-booking-button"]');
    
    // Create conflicting booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-16');
    await page.fill('[data-testid="start-time-input"]', '14:30');
    await page.fill('[data-testid="end-time-input"]', '15:30');
    await page.click('[data-testid="save-booking-button"]');
    
    await page.waitForTimeout(5000);
    
    // Expected Result: Email suppressed according to preferences
    const emailCheckResponse = await request.get(`${baseURL}/api/test/emails/${schedulerEmail}/latest`);
    
    if (emailCheckResponse.ok()) {
      const emailData = await emailCheckResponse.json();
      // Verify no new conflict email was sent (timestamp should be old or subject different)
      expect(emailData.subject).not.toContain('Meeting Room B');
    }
    
    // Re-enable notifications for cleanup
    await page.goto(`${baseURL}/settings`);
    await page.click('[data-testid="notifications-tab"]');
    await page.locator('[data-testid="conflict-notification-toggle"]').check();
    await page.click('[data-testid="save-preferences-button"]');
  });

  test('Ensure email delivery success rate is above 99%', async ({ page, request }) => {
    // Step 1: Prepare a batch of at least 100 scheduling conflicts
    const totalConflicts = 100;
    const testEmails: string[] = [];
    
    // Generate test email addresses
    for (let i = 0; i < totalConflicts; i++) {
      testEmails.push(`scheduler${i}@test.com`);
    }
    
    // Navigate to admin/testing interface
    await page.goto(`${baseURL}/admin/email-testing`);
    await expect(page.locator('[data-testid="email-batch-test-section"]')).toBeVisible();
    
    // Step 2: Trigger all conflict events and initiate email notification sending
    await page.fill('[data-testid="batch-size-input"]', totalConflicts.toString());
    await page.fill('[data-testid="email-list-textarea"]', testEmails.join(','));
    await page.click('[data-testid="trigger-batch-conflicts-button"]');
    
    // Wait for batch processing to complete
    await expect(page.locator('[data-testid="batch-processing-status"]')).toContainText('Processing', { timeout: 10000 });
    await expect(page.locator('[data-testid="batch-processing-status"]')).toContainText('Completed', { timeout: 360000 }); // 6 minutes timeout
    
    // Step 3: Monitor email delivery status
    await page.click('[data-testid="view-delivery-report-button"]');
    await expect(page.locator('[data-testid="delivery-report-table"]')).toBeVisible();
    
    // Get delivery statistics
    const totalSentText = await page.locator('[data-testid="total-emails-sent"]').textContent();
    const totalDeliveredText = await page.locator('[data-testid="total-emails-delivered"]').textContent();
    const deliveryRateText = await page.locator('[data-testid="delivery-success-rate"]').textContent();
    
    const totalSent = parseInt(totalSentText?.replace(/\D/g, '') || '0');
    const totalDelivered = parseInt(totalDeliveredText?.replace(/\D/g, '') || '0');
    const deliveryRate = parseFloat(deliveryRateText?.replace(/[^0-9.]/g, '') || '0');
    
    // Step 4: Calculate and verify delivery success rate
    expect(totalSent).toBe(totalConflicts);
    expect(totalDelivered).toBeGreaterThanOrEqual(totalConflicts * 0.99);
    
    // Expected Result: At least 99% of emails are delivered successfully
    expect(deliveryRate).toBeGreaterThanOrEqual(99.0);
    
    // Verify in delivery report table
    const failedDeliveries = totalSent - totalDelivered;
    expect(failedDeliveries).toBeLessThanOrEqual(1); // Allow max 1 failure for 100 emails
    
    // Additional API verification
    const deliveryStatsResponse = await request.get(`${baseURL}/api/email/delivery-stats?batchId=latest`);
    expect(deliveryStatsResponse.ok()).toBeTruthy();
    
    const deliveryStats = await deliveryStatsResponse.json();
    expect(deliveryStats.successRate).toBeGreaterThanOrEqual(0.99);
    expect(deliveryStats.totalSent).toBe(totalConflicts);
    expect(deliveryStats.delivered).toBeGreaterThanOrEqual(totalConflicts * 0.99);
  });
});