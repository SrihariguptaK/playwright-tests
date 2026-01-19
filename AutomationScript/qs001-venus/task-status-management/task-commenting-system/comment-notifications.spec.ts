import { test, expect } from '@playwright/test';

test.describe('Comment Notifications - Story 9', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const COMMENTER_EMAIL = 'commenter@example.com';
  const COMMENTER_PASSWORD = 'Password123!';
  const RECIPIENT_EMAIL = 'recipient@example.com';
  const RECIPIENT_PASSWORD = 'Password123!';
  const UNAUTHORIZED_EMAIL = 'unauthorized@example.com';
  const UNAUTHORIZED_PASSWORD = 'Password123!';
  const NOTIFICATION_TIMEOUT = 5000;

  test('Validate notification delivery on new comment (happy-path)', async ({ page, context }) => {
    // Step 1: Login as commenter employee and add comment
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', COMMENTER_EMAIL);
    await page.fill('[data-testid="password-input"]', COMMENTER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to task details page
    await page.goto(`${BASE_URL}/tasks/task-123`);
    await expect(page.locator('[data-testid="task-details-container"]')).toBeVisible();

    // Enter and submit new comment
    const commentText = 'This is a test comment for notification';
    await page.fill('[data-testid="comment-text-field"]', commentText);
    await page.click('[data-testid="submit-comment-button"]');

    // Expected Result: Comment is saved successfully
    await expect(page.locator('[data-testid="comment-success-message"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator(`text=${commentText}`)).toBeVisible();

    // Step 2: Open new page as recipient employee
    const recipientPage = await context.newPage();
    await recipientPage.goto(`${BASE_URL}/login`);
    await recipientPage.fill('[data-testid="email-input"]', RECIPIENT_EMAIL);
    await recipientPage.fill('[data-testid="password-input"]', RECIPIENT_PASSWORD);
    await recipientPage.click('[data-testid="login-button"]');
    await expect(recipientPage).toHaveURL(/.*dashboard/);

    // Check in-app notification within 5 seconds
    await recipientPage.click('[data-testid="notification-center-icon"]');
    const notification = recipientPage.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible({ timeout: NOTIFICATION_TIMEOUT });

    // Expected Result: Notification appears with correct details
    await expect(notification).toContainText(commentText.substring(0, 50));
    await expect(notification.locator('[data-testid="notification-author"]')).toContainText('commenter');
    await expect(notification.locator('[data-testid="notification-task-details"]')).toBeVisible();

    // Step 3: Check email inbox for notification
    // Note: In real scenario, this would integrate with email testing service like MailHog or similar
    await recipientPage.goto(`${BASE_URL}/test/email-inbox`);
    const emailNotification = recipientPage.locator('[data-testid="email-notification"]').first();
    await expect(emailNotification).toBeVisible({ timeout: NOTIFICATION_TIMEOUT });

    // Expected Result: Email notification received with accurate content
    await expect(emailNotification.locator('[data-testid="email-subject"]')).toContainText('New Comment');
    await expect(emailNotification.locator('[data-testid="email-body"]')).toContainText(commentText);
    await expect(emailNotification.locator('[data-testid="email-author"]')).toContainText('commenter');

    await recipientPage.close();
  });

  test('Verify notification preference settings for comments (happy-path)', async ({ page, context }) => {
    // Step 1: Login as test employee
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', RECIPIENT_EMAIL);
    await page.fill('[data-testid="password-input"]', RECIPIENT_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to notification settings
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="notification-settings-link"]');

    // Expected Result: Settings UI is displayed
    await expect(page.locator('[data-testid="notification-settings-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-notification-section"]')).toBeVisible();

    // Step 2: Disable email notifications for comments
    const emailToggle = page.locator('[data-testid="email-notification-toggle-comments"]');
    await expect(emailToggle).toBeVisible();
    
    // Ensure in-app notifications remain enabled
    const inAppToggle = page.locator('[data-testid="inapp-notification-toggle-comments"]');
    const isInAppEnabled = await inAppToggle.isChecked();
    if (!isInAppEnabled) {
      await inAppToggle.check();
    }

    // Disable email notifications
    const isEmailEnabled = await emailToggle.isChecked();
    if (isEmailEnabled) {
      await emailToggle.uncheck();
    }

    await page.click('[data-testid="save-preferences-button"]');

    // Expected Result: Preference is saved successfully
    await expect(page.locator('[data-testid="preferences-saved-message"]')).toBeVisible({ timeout: 3000 });

    // Refresh page to verify persistence
    await page.reload();
    await expect(page.locator('[data-testid="email-notification-toggle-comments"]')).not.toBeChecked();
    await expect(page.locator('[data-testid="inapp-notification-toggle-comments"]')).toBeChecked();

    // Step 3: Add new comment as another employee
    const commenterPage = await context.newPage();
    await commenterPage.goto(`${BASE_URL}/login`);
    await commenterPage.fill('[data-testid="email-input"]', COMMENTER_EMAIL);
    await commenterPage.fill('[data-testid="password-input"]', COMMENTER_PASSWORD);
    await commenterPage.click('[data-testid="login-button"]');

    await commenterPage.goto(`${BASE_URL}/tasks/task-123`);
    const testCommentText = 'Testing notification preferences';
    await commenterPage.fill('[data-testid="comment-text-field"]', testCommentText);
    await commenterPage.click('[data-testid="submit-comment-button"]');
    await expect(commenterPage.locator('[data-testid="comment-success-message"]')).toBeVisible();

    // Step 4: Check in-app notification for test employee
    await page.goto(`${BASE_URL}/dashboard`);
    await page.click('[data-testid="notification-center-icon"]');
    const inAppNotification = page.locator('[data-testid="notification-item"]').first();

    // Expected Result: Notification sent only via in-app
    await expect(inAppNotification).toBeVisible({ timeout: NOTIFICATION_TIMEOUT });
    await expect(inAppNotification).toContainText(testCommentText.substring(0, 50));

    // Check email inbox - no email should be received
    await page.goto(`${BASE_URL}/test/email-inbox`);
    await page.waitForTimeout(10000);
    const emailCount = await page.locator('[data-testid="email-notification"]').count();
    const latestEmail = page.locator('[data-testid="email-notification"]').first();
    
    // Expected Result: No email received
    if (emailCount > 0) {
      await expect(latestEmail.locator('[data-testid="email-body"]')).not.toContainText(testCommentText);
    }

    await commenterPage.close();
  });

  test('Ensure unauthorized users do not receive comment notifications (error-case)', async ({ page, context }) => {
    // Step 1: Verify task assignment and permissions
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', COMMENTER_EMAIL);
    await page.fill('[data-testid="password-input"]', COMMENTER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    await page.goto(`${BASE_URL}/tasks/task-123`);
    await expect(page.locator('[data-testid="task-details-container"]')).toBeVisible();

    // Verify Employee A and B are assigned, Employee C is not
    const assignedUsers = page.locator('[data-testid="assigned-users-list"]');
    await expect(assignedUsers).toContainText('Employee A');
    await expect(assignedUsers).toContainText('Employee B');
    await expect(assignedUsers).not.toContainText('Employee C');

    // Step 2: Add new comment as Employee A
    const commentText = 'Comment for authorized users only';
    await page.fill('[data-testid="comment-text-field"]', commentText);
    await page.click('[data-testid="submit-comment-button"]');

    // Expected Result: Comment is saved
    await expect(page.locator('[data-testid="comment-success-message"]')).toBeVisible();
    await expect(page.locator(`text=${commentText}`)).toBeVisible();

    // Step 3: Check notifications for Employee C (unauthorized user)
    const unauthorizedPage = await context.newPage();
    await unauthorizedPage.goto(`${BASE_URL}/login`);
    await unauthorizedPage.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await unauthorizedPage.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await unauthorizedPage.click('[data-testid="login-button"]');
    await expect(unauthorizedPage).toHaveURL(/.*dashboard/);

    // Check in-app notification center immediately
    await unauthorizedPage.click('[data-testid="notification-center-icon"]');
    const notificationsList = unauthorizedPage.locator('[data-testid="notification-item"]');
    const notificationCount = await notificationsList.count();

    // Expected Result: No notification received
    if (notificationCount > 0) {
      const notifications = await notificationsList.allTextContents();
      for (const notification of notifications) {
        expect(notification).not.toContain(commentText);
      }
    }

    // Wait and check email inbox
    await unauthorizedPage.goto(`${BASE_URL}/test/email-inbox`);
    await unauthorizedPage.waitForTimeout(10000);
    const emailNotifications = unauthorizedPage.locator('[data-testid="email-notification"]');
    const emailCount = await emailNotifications.count();

    if (emailCount > 0) {
      const emails = await emailNotifications.allTextContents();
      for (const email of emails) {
        expect(email).not.toContain(commentText);
      }
    }

    // Step 4: Verify Employee B (authorized) receives notification
    const authorizedPage = await context.newPage();
    await authorizedPage.goto(`${BASE_URL}/login`);
    await authorizedPage.fill('[data-testid="email-input"]', RECIPIENT_EMAIL);
    await authorizedPage.fill('[data-testid="password-input"]', RECIPIENT_PASSWORD);
    await authorizedPage.click('[data-testid="login-button"]');

    await authorizedPage.click('[data-testid="notification-center-icon"]');
    const authorizedNotification = authorizedPage.locator('[data-testid="notification-item"]').first();
    await expect(authorizedNotification).toBeVisible({ timeout: NOTIFICATION_TIMEOUT });
    await expect(authorizedNotification).toContainText(commentText.substring(0, 50));

    // Step 5: Access audit logs and verify authorization
    await page.goto(`${BASE_URL}/admin/audit-logs`);
    await page.fill('[data-testid="audit-log-filter-event"]', 'notification');
    await page.click('[data-testid="apply-filter-button"]');

    const auditLogEntries = page.locator('[data-testid="audit-log-entry"]');
    await expect(auditLogEntries.first()).toBeVisible();

    // Expected Result: Notifications sent only to authorized users
    const logCount = await auditLogEntries.count();
    for (let i = 0; i < logCount; i++) {
      const logEntry = auditLogEntries.nth(i);
      const logText = await logEntry.textContent();
      if (logText?.includes(commentText)) {
        expect(logText).not.toContain(UNAUTHORIZED_EMAIL);
        expect(logText).not.toContain('Employee C');
      }
    }

    // Step 6: Verify Employee C cannot access task directly
    await unauthorizedPage.goto(`${BASE_URL}/tasks/task-123`);
    await expect(unauthorizedPage.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(unauthorizedPage.locator('[data-testid="task-details-container"]')).not.toBeVisible();

    await unauthorizedPage.close();
    await authorizedPage.close();
  });
});