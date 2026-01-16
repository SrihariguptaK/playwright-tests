import { test, expect } from '@playwright/test';

test.describe('Story-19: Scheduler Approval Decision Notifications', () => {
  let approverEmail: string;
  let schedulerEmail: string;
  let requestId: string;

  test.beforeEach(async ({ page }) => {
    // Setup test data
    approverEmail = 'approver@example.com';
    schedulerEmail = 'scheduler@example.com';
    requestId = `REQ-${Date.now()}`;
    
    // Navigate to application
    await page.goto('/login');
  });

  test('TC#1: Validate notification sent to scheduler on approval decision', async ({ page }) => {
    // Login as approver
    await page.fill('[data-testid="email-input"]', approverEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to pending approvals
    await page.click('[data-testid="approvals-menu"]');
    await page.click('[data-testid="pending-approvals-link"]');
    await expect(page.locator('[data-testid="pending-approvals-page"]')).toBeVisible();

    // Select a schedule change request
    await page.click(`[data-testid="request-row-${requestId}"]`);
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();

    // Action: Approver submits approval decision
    await page.fill('[data-testid="approval-comments"]', 'Approved - schedule change looks good');
    await page.click('[data-testid="approve-button"]');
    
    // Expected Result: Notification is triggered
    await expect(page.locator('[data-testid="notification-triggered-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="notification-triggered-message"]')).toContainText('Notification sent to scheduler');

    // Logout approver and login as scheduler
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');

    // Action: Scheduler receives email and in-app notification
    await page.waitForTimeout(2000); // Wait for notification processing
    
    // Check in-app notification
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    
    // Expected Result: Notification contains decision details and request reference
    await expect(notification).toContainText('Approved');
    await expect(notification).toContainText(requestId);
    await expect(notification).toContainText('Approved - schedule change looks good');
    
    // Verify notification timestamp is within 1 minute
    const notificationTime = await notification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(notificationTime).toBeTruthy();
    
    // Check email notification indicator
    await page.click(notification);
    await expect(page.locator('[data-testid="notification-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-sent-indicator"]')).toContainText('Email sent');
  });

  test('TC#2: Verify prevention of duplicate notifications', async ({ page }) => {
    // Login as system admin to access notification logs
    await page.fill('[data-testid="email-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'admin123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to notification management
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="notification-logs-link"]');
    await expect(page.locator('[data-testid="notification-logs-page"]')).toBeVisible();

    // Create a test approval decision
    const testDecisionId = `DEC-${Date.now()}`;
    await page.click('[data-testid="simulate-decision-button"]');
    await page.fill('[data-testid="decision-id-input"]', testDecisionId);
    await page.fill('[data-testid="scheduler-email-input"]', schedulerEmail);
    await page.selectOption('[data-testid="decision-type-select"]', 'approved');
    
    // Action: System processes multiple identical approval decisions
    await page.click('[data-testid="process-decision-button"]');
    await expect(page.locator('[data-testid="processing-message"]')).toContainText('Decision processed');
    
    // Attempt to process the same decision again
    await page.click('[data-testid="process-decision-button"]');
    await page.click('[data-testid="process-decision-button"]');
    
    await page.waitForTimeout(3000); // Wait for all processing attempts
    
    // Expected Result: Only one notification is sent to scheduler
    await page.fill('[data-testid="search-decision-input"]', testDecisionId);
    await page.click('[data-testid="search-button"]');
    
    const notificationCount = await page.locator(`[data-testid="notification-log-row"][data-decision-id="${testDecisionId}"]`).count();
    expect(notificationCount).toBe(1);
    
    // Verify duplicate prevention message
    await expect(page.locator('[data-testid="duplicate-prevention-log"]')).toBeVisible();
    await expect(page.locator('[data-testid="duplicate-prevention-log"]')).toContainText('Duplicate notifications prevented: 2');
  });

  test('TC#3: Test notification preference settings', async ({ page }) => {
    // Login as scheduler
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to notification preferences
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="settings-link"]');
    await expect(page.locator('[data-testid="settings-page"]')).toBeVisible();
    
    await page.click('[data-testid="notifications-tab"]');
    await expect(page.locator('[data-testid="notification-preferences-section"]')).toBeVisible();

    // Action: Scheduler updates notification preferences
    // Enable email notifications
    await page.check('[data-testid="email-notifications-checkbox"]');
    
    // Enable in-app notifications
    await page.check('[data-testid="inapp-notifications-checkbox"]');
    
    // Disable SMS notifications
    await page.uncheck('[data-testid="sms-notifications-checkbox"]');
    
    // Set notification frequency
    await page.selectOption('[data-testid="notification-frequency-select"]', 'immediate');
    
    // Enable specific notification types
    await page.check('[data-testid="approval-notifications-checkbox"]');
    await page.check('[data-testid="rejection-notifications-checkbox"]');
    await page.check('[data-testid="info-request-notifications-checkbox"]');
    
    // Save preferences
    await page.click('[data-testid="save-preferences-button"]');
    
    // Expected Result: Preferences are saved and applied
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toContainText('Notification preferences saved successfully');
    
    // Verify preferences are persisted
    await page.reload();
    await page.click('[data-testid="notifications-tab"]');
    
    await expect(page.locator('[data-testid="email-notifications-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="inapp-notifications-checkbox"]')).toBeChecked();
    await expect(page.locator('[data-testid="sms-notifications-checkbox"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="notification-frequency-select"]')).toHaveValue('immediate');

    // Action: System sends notifications according to preferences
    // Simulate an approval decision
    await page.goto('/admin/simulate-approval');
    await page.fill('[data-testid="target-scheduler-input"]', schedulerEmail);
    await page.fill('[data-testid="request-reference-input"]', `REQ-PREF-${Date.now()}`);
    await page.selectOption('[data-testid="decision-type-select"]', 'approved');
    await page.fill('[data-testid="decision-comments-input"]', 'Test notification with preferences');
    await page.click('[data-testid="trigger-notification-button"]');
    
    await page.waitForTimeout(2000); // Wait for notification processing
    
    // Login back as scheduler to verify notifications
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', schedulerEmail);
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Notifications are received as configured
    // Check in-app notification (enabled)
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    const latestNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toBeVisible();
    await expect(latestNotification).toContainText('Test notification with preferences');
    
    // Verify email was sent (check notification details)
    await page.click(latestNotification);
    await expect(page.locator('[data-testid="email-delivery-status"]')).toContainText('Sent');
    
    // Verify SMS was NOT sent (disabled in preferences)
    await expect(page.locator('[data-testid="sms-delivery-status"]')).toContainText('Not sent (disabled in preferences)');
    
    // Verify notification was immediate (as per frequency setting)
    const deliveryTime = await page.locator('[data-testid="notification-delivery-time"]').textContent();
    expect(deliveryTime).toContain('Immediate');
  });
});