import { test, expect } from '@playwright/test';

test.describe('Schedule Conflict Prevention and Override Authorization', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULING_PATH = '/scheduling';
  const AUDIT_LOG_PATH = '/audit-logs';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Block save on conflicting schedule without override', async ({ page }) => {
    // Login as non-authorized user
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(new RegExp(BASE_URL));

    // Navigate to scheduling interface
    await page.goto(`${BASE_URL}${SCHEDULING_PATH}`);
    await expect(page.locator('[data-testid="scheduling-interface"]')).toBeVisible();

    // Open booking form
    await page.click('[data-testid="new-booking-button"]');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    // Select resource with existing booking
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-room-a"]');

    // Enter conflicting booking details
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '10:00');
    await page.fill('[data-testid="end-time"]', '11:00');
    await page.fill('[data-testid="booking-title"]', 'Conflicting Meeting');

    // Attempt to save conflicting schedule
    await page.click('[data-testid="save-booking-button"]');

    // Verify save is blocked and conflict message is displayed
    await expect(page.locator('[data-testid="conflict-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-error-message"]')).toContainText('Schedule conflict detected');

    // Verify no override option is presented
    await expect(page.locator('[data-testid="override-button"]')).not.toBeVisible();

    // Attempt to bypass block by resubmitting
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="conflict-error-message"]')).toBeVisible();

    // Try browser refresh and resubmit
    await page.reload();
    await page.click('[data-testid="new-booking-button"]');
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-room-a"]');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '10:00');
    await page.fill('[data-testid="end-time"]', '11:00');
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="conflict-error-message"]')).toBeVisible();

    // Verify conflicting schedule was not saved
    await page.click('[data-testid="close-booking-form"]');
    await page.click('[data-testid="booking-list-view"]');
    const conflictingBooking = page.locator('[data-testid="booking-item"]', { hasText: 'Conflicting Meeting' });
    await expect(conflictingBooking).not.toBeVisible();

    // Verify original booking remains unchanged
    const originalBooking = page.locator('[data-testid="booking-item-room-a-10-00"]');
    await expect(originalBooking).toBeVisible();
    await expect(originalBooking).toContainText('10:00');
  });

  test('Allow override save for authorized user', async ({ page }) => {
    // Login as authorized user with override permissions
    await page.fill('[data-testid="username-input"]', 'admin_user');
    await page.fill('[data-testid="password-input"]', 'admin123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(new RegExp(BASE_URL));

    // Navigate to scheduling interface
    await page.goto(`${BASE_URL}${SCHEDULING_PATH}`);
    await expect(page.locator('[data-testid="scheduling-interface"]')).toBeVisible();

    // Create booking that conflicts with existing schedule
    await page.click('[data-testid="new-booking-button"]');
    await expect(page.locator('[data-testid="booking-form"]')).toBeVisible();

    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-room-a"]');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '10:00');
    await page.fill('[data-testid="end-time"]', '11:00');
    await page.fill('[data-testid="booking-title"]', 'Override Meeting');

    // Attempt to save conflicting schedule
    await page.click('[data-testid="save-booking-button"]');

    // Verify override option is presented with warning
    await expect(page.locator('[data-testid="override-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="override-warning-text"]')).toBeVisible();
    await expect(page.locator('[data-testid="override-warning-text"]')).toContainText('conflict');
    await expect(page.locator('[data-testid="override-button"]')).toBeVisible();

    // Click override button
    await page.click('[data-testid="override-button"]');

    // Enter authorization credentials
    await expect(page.locator('[data-testid="authorization-dialog"]')).toBeVisible();
    await page.fill('[data-testid="auth-username"]', 'admin_user');
    await page.fill('[data-testid="auth-password"]', 'admin123');

    // Confirm override action
    await page.click('[data-testid="confirm-override-button"]');

    // Verify schedule saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');

    // Navigate to audit log
    await page.goto(`${BASE_URL}${AUDIT_LOG_PATH}`);
    await expect(page.locator('[data-testid="audit-log-table"]')).toBeVisible();

    // Search for most recent override action
    await page.fill('[data-testid="audit-search"]', 'override');
    await page.click('[data-testid="search-button"]');

    // Verify logged entry contains required information
    const latestOverrideEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(latestOverrideEntry).toBeVisible();
    await expect(latestOverrideEntry).toContainText('admin_user');
    await expect(latestOverrideEntry).toContainText('override');
    await expect(latestOverrideEntry).toContainText('Override Meeting');

    // Verify timestamp is present and recent
    const timestamp = await latestOverrideEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();

    // Check scheduling view for both bookings
    await page.goto(`${BASE_URL}${SCHEDULING_PATH}`);
    await page.click('[data-testid="booking-list-view"]');

    // Verify original booking is visible
    const originalBooking = page.locator('[data-testid="booking-item"]').filter({ hasText: 'room-a' }).first();
    await expect(originalBooking).toBeVisible();

    // Verify new conflicting booking is visible
    const newBooking = page.locator('[data-testid="booking-item"]', { hasText: 'Override Meeting' });
    await expect(newBooking).toBeVisible();
    await expect(newBooking).toContainText('10:00');
    await expect(newBooking).toContainText('11:00');
  });

  test('Send notifications on override save', async ({ page }) => {
    // Login as authorized user
    await page.fill('[data-testid="username-input"]', 'admin_user');
    await page.fill('[data-testid="password-input"]', 'admin123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(new RegExp(BASE_URL));

    // Navigate to scheduling interface
    await page.goto(`${BASE_URL}${SCHEDULING_PATH}`);
    await expect(page.locator('[data-testid="scheduling-interface"]')).toBeVisible();

    // Create booking that conflicts with existing schedule
    await page.click('[data-testid="new-booking-button"]');
    await page.click('[data-testid="resource-select"]');
    await page.click('[data-testid="resource-option-room-a"]');
    await page.fill('[data-testid="booking-date"]', '2024-03-15');
    await page.fill('[data-testid="start-time"]', '10:00');
    await page.fill('[data-testid="end-time"]', '11:00');
    await page.fill('[data-testid="booking-title"]', 'Notification Test Meeting');

    // Attempt to save and click override option
    await page.click('[data-testid="save-booking-button"]');
    await expect(page.locator('[data-testid="override-dialog"]')).toBeVisible();
    await page.click('[data-testid="override-button"]');

    // Provide authorization credentials and confirm
    await page.fill('[data-testid="auth-username"]', 'admin_user');
    await page.fill('[data-testid="auth-password"]', 'admin123');
    await page.click('[data-testid="confirm-override-button"]');

    // Wait for notification processing
    await page.waitForTimeout(3000);

    // Check notification queue or logs
    await page.goto(`${BASE_URL}/notifications`);
    await expect(page.locator('[data-testid="notification-list"]')).toBeVisible();

    // Access stakeholder notification inbox
    await page.click('[data-testid="stakeholder-notifications-tab"]');
    await expect(page.locator('[data-testid="stakeholder-notification-inbox"]')).toBeVisible();

    // Find and open the override notification
    const overrideNotification = page.locator('[data-testid="notification-item"]', { hasText: 'override' }).first();
    await expect(overrideNotification).toBeVisible();
    await overrideNotification.click();

    // Verify notification content
    await expect(page.locator('[data-testid="notification-detail"]')).toBeVisible();

    // Verify subject line indicates override alert
    const notificationSubject = page.locator('[data-testid="notification-subject"]');
    await expect(notificationSubject).toBeVisible();
    await expect(notificationSubject).toContainText('Override Alert');

    // Verify notification includes override details and user info
    const notificationBody = page.locator('[data-testid="notification-body"]');
    await expect(notificationBody).toContainText('admin_user');
    await expect(notificationBody).toContainText('Notification Test Meeting');
    await expect(notificationBody).toContainText('room-a');
    await expect(notificationBody).toContainText('10:00');

    // Check timestamp of notification delivery
    const notificationTimestamp = await page.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTimestamp).toBeTruthy();

    // Verify all designated stakeholders received notification
    await page.click('[data-testid="notification-recipients"]');
    const recipientsList = page.locator('[data-testid="recipient-item"]');
    const recipientCount = await recipientsList.count();
    expect(recipientCount).toBeGreaterThan(0);

    // Verify delivery status
    for (let i = 0; i < recipientCount; i++) {
      const recipient = recipientsList.nth(i);
      const deliveryStatus = recipient.locator('[data-testid="delivery-status"]');
      await expect(deliveryStatus).toContainText('Delivered');
    }

    // Check notification logs for delivery confirmation
    await page.goto(`${BASE_URL}/notification-logs`);
    await page.fill('[data-testid="log-search"]', 'Notification Test Meeting');
    await page.click('[data-testid="search-logs-button"]');

    const notificationLog = page.locator('[data-testid="log-entry"]').first();
    await expect(notificationLog).toBeVisible();
    await expect(notificationLog).toContainText('override');
    await expect(notificationLog).toContainText('sent');
  });
});