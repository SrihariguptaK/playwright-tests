import { test, expect } from '@playwright/test';

test.describe('Email Notifications for Scheduling Conflicts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduling');
    // Login as scheduler user
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Receive email notification on conflict detection (happy-path)', async ({ page }) => {
    // Step 1: Create or modify a schedule entry that creates a scheduling conflict
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-02-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.fill('[data-testid="title-input"]', 'Team Meeting');
    
    // Create conflicting schedule entry
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Create another entry with same resource and overlapping time
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-02-15');
    await page.fill('[data-testid="start-time-input"]', '10:30');
    await page.fill('[data-testid="end-time-input"]', '11:30');
    await page.fill('[data-testid="title-input"]', 'Client Presentation');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Email notification is generated and sent
    await expect(page.locator('[data-testid="conflict-detected-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="email-notification-sent-indicator"]')).toBeVisible();
    
    // Step 2: User receives email - Navigate to email inbox (simulated)
    await page.goto('/email-inbox');
    await page.waitForTimeout(2000); // Wait for email delivery
    
    // Expected Result: Email contains detailed conflict information
    const emailNotification = page.locator('[data-testid="email-item"]').filter({ hasText: 'Scheduling Conflict Detected' }).first();
    await expect(emailNotification).toBeVisible();
    await emailNotification.click();
    
    // Verify email content
    await expect(page.locator('[data-testid="email-subject"]')).toContainText('Scheduling Conflict Detected');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('2024-02-15');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('10:00');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('Team Meeting');
    await expect(page.locator('[data-testid="email-body"]')).toContainText('Client Presentation');
    
    // Step 3: User reviews email and takes action
    // Expected Result: User is informed and able to resolve conflict
    await expect(page.locator('[data-testid="suggested-actions"]')).toBeVisible();
    await expect(page.locator('[data-testid="view-conflict-link"]')).toBeVisible();
    await expect(page.locator('[data-testid="resolve-now-link"]')).toBeVisible();
    
    // Click on action link
    await page.click('[data-testid="view-conflict-link"]');
    await expect(page.locator('[data-testid="conflict-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-resolution-options"]')).toBeVisible();
    
    // Verify email formatting and readability
    await page.goto('/email-inbox');
    await emailNotification.click();
    await expect(page.locator('[data-testid="email-body"]')).toHaveCSS('font-family', /Arial|Helvetica|sans-serif/);
    await expect(page.locator('[data-testid="email-body"]')).toHaveCSS('font-size', /14px|16px/);
  });

  test('Email delivery performance test (boundary)', async ({ page }) => {
    // Step 1: Prepare test environment and note the current timestamp
    const testStartTime = Date.now();
    
    // Step 2: Start performance monitoring to track email delivery timing
    await page.goto('/scheduling');
    
    // Step 3: Trigger a scheduling conflict by creating conflicting entries
    // Create first schedule entry
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Meeting Room B');
    await page.fill('[data-testid="date-input"]', '2024-02-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.fill('[data-testid="title-input"]', 'Project Review');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Step 4: Record the exact timestamp when the conflict was created/detected
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Meeting Room B');
    await page.fill('[data-testid="date-input"]', '2024-02-16');
    await page.fill('[data-testid="start-time-input"]', '14:30');
    await page.fill('[data-testid="end-time-input"]', '15:30');
    await page.fill('[data-testid="title-input"]', 'Budget Discussion');
    
    const conflictDetectionTime = Date.now();
    await page.click('[data-testid="save-schedule-button"]');
    
    // Expected Result: Email is sent within 5 seconds
    await expect(page.locator('[data-testid="conflict-detected-alert"]')).toBeVisible({ timeout: 5000 });
    
    // Step 5: Monitor the email service logs or system logs for email send confirmation
    await expect(page.locator('[data-testid="email-notification-sent-indicator"]')).toBeVisible({ timeout: 5000 });
    const emailSentTime = Date.now();
    
    // Step 6: Check the email inbox and record the timestamp when the email is received
    await page.goto('/email-inbox');
    const emailNotification = page.locator('[data-testid="email-item"]').filter({ hasText: 'Scheduling Conflict Detected' }).first();
    await expect(emailNotification).toBeVisible({ timeout: 5000 });
    const emailReceivedTime = Date.now();
    
    // Step 7: Calculate the time difference between conflict detection and email receipt
    const deliveryTime = emailReceivedTime - conflictDetectionTime;
    const deliveryTimeInSeconds = deliveryTime / 1000;
    
    // Expected Result: Email delivered within 5 seconds
    expect(deliveryTimeInSeconds).toBeLessThanOrEqual(5);
    
    // Step 8: Review system logs and email delivery tracking dashboard for delivery status
    await page.goto('/admin/email-tracking');
    await expect(page.locator('[data-testid="email-tracking-dashboard"]')).toBeVisible();
    
    const latestEmailLog = page.locator('[data-testid="email-log-entry"]').first();
    await expect(latestEmailLog).toBeVisible();
    await expect(latestEmailLog.locator('[data-testid="delivery-status"]')).toContainText('Delivered');
    await expect(latestEmailLog.locator('[data-testid="delivery-time"]')).toBeVisible();
    
    // Step 9: Verify no email bounces or delivery failures occurred
    await expect(latestEmailLog.locator('[data-testid="bounce-status"]')).toContainText('No Bounce');
    await expect(latestEmailLog.locator('[data-testid="failure-status"]')).toContainText('Success');
    
    // Verify bounce rate is less than 1%
    const bounceRateElement = page.locator('[data-testid="bounce-rate-metric"]');
    await expect(bounceRateElement).toBeVisible();
    const bounceRateText = await bounceRateElement.textContent();
    const bounceRate = parseFloat(bounceRateText?.replace('%', '') || '0');
    expect(bounceRate).toBeLessThan(1);
  });
});