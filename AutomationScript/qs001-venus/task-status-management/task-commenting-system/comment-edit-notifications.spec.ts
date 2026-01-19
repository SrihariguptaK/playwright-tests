import { test, expect } from '@playwright/test';

test.describe('Comment Edit Notifications', () => {
  test.beforeEach(async ({ page }) => {
    // Login as authorized user before each test
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate notification delivery on comment edit (happy-path)', async ({ page }) => {
    // Navigate to the task detail page containing the comment to be edited
    await page.goto('/tasks/task-123');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Locate an existing comment and click on the edit button/icon for that comment
    const commentSection = page.locator('[data-testid="comment-section"]');
    await expect(commentSection).toBeVisible();
    const firstComment = commentSection.locator('[data-testid="comment-item"]').first();
    const originalCommentText = await firstComment.locator('[data-testid="comment-text"]').textContent();
    await firstComment.locator('[data-testid="edit-comment-button"]').click();

    // Modify the comment text by adding or changing content
    const commentEditor = firstComment.locator('[data-testid="comment-editor"]');
    await expect(commentEditor).toBeVisible();
    await commentEditor.fill('Updated comment with new information');

    // Click the Save or Update button to save the edited comment
    await firstComment.locator('[data-testid="save-comment-button"]').click();
    
    // Expected Result: Comment is updated successfully
    await expect(firstComment.locator('[data-testid="comment-text"]')).toHaveText('Updated comment with new information');
    await expect(page.locator('[data-testid="success-toast"]')).toContainText('Comment updated successfully');

    // Wait for up to 5 seconds and check the in-app notification icon/bell in the application header
    await page.waitForTimeout(2000);
    const notificationBell = page.locator('[data-testid="notification-bell"]');
    await expect(notificationBell).toBeVisible();
    
    // Expected Result: Notification appears with correct details
    const notificationBadge = notificationBell.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible();
    await expect(notificationBadge).toHaveText('1');

    // Click on the in-app notification to view details
    await notificationBell.click();
    const notificationDropdown = page.locator('[data-testid="notification-dropdown"]');
    await expect(notificationDropdown).toBeVisible();
    
    // Verify the content of the notification matches the actual edit made
    const latestNotification = notificationDropdown.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('comment was edited');
    await expect(latestNotification).toContainText('Updated comment with new information');
    await expect(latestNotification.locator('[data-testid="editor-name"]')).toBeVisible();

    // Open the email client associated with the user's registered email address
    // Note: In real automation, this would integrate with email testing service like MailHog or similar
    await page.goto('/test-email-inbox');
    
    // Check the inbox for a notification email regarding the comment edit
    await page.waitForTimeout(3000);
    const emailList = page.locator('[data-testid="email-list"]');
    await expect(emailList).toBeVisible();
    
    // Expected Result: Email notification received with accurate content
    const commentEditEmail = emailList.locator('[data-testid="email-item"]').filter({ hasText: 'Comment Edited' }).first();
    await expect(commentEditEmail).toBeVisible();
    
    // Open the email notification and review its content
    await commentEditEmail.click();
    const emailContent = page.locator('[data-testid="email-content"]');
    await expect(emailContent).toContainText('Updated comment with new information');
    await expect(emailContent).toContainText('edited a comment');
    
    // Click on the task link in the email notification
    const taskLink = emailContent.locator('[data-testid="task-link"]');
    await expect(taskLink).toBeVisible();
    await taskLink.click();
    await expect(page).toHaveURL(/.*tasks\/task-123/);
  });

  test('Verify notification preference settings for comment edits (happy-path)', async ({ page }) => {
    // Navigate to the user profile or settings menu by clicking on the user avatar or settings icon
    await page.goto('/dashboard');
    const userAvatar = page.locator('[data-testid="user-avatar"]');
    await userAvatar.click();
    
    // Click on 'Notification Settings' or 'Preferences' option from the menu
    const userMenu = page.locator('[data-testid="user-menu"]');
    await expect(userMenu).toBeVisible();
    await userMenu.locator('[data-testid="notification-settings-link"]').click();
    
    // Expected Result: Settings UI is displayed
    await expect(page).toHaveURL(/.*settings\/notifications/);
    await expect(page.locator('[data-testid="notification-settings-page"]')).toBeVisible();

    // Locate the notification preferences section specifically for 'Comment Edits' or 'Comment Updates'
    const commentEditSection = page.locator('[data-testid="comment-edit-notifications-section"]');
    await expect(commentEditSection).toBeVisible();
    
    // Verify the current state of notification preferences (both in-app and email should be enabled by default)
    const inAppToggle = commentEditSection.locator('[data-testid="in-app-notification-toggle"]');
    const emailToggle = commentEditSection.locator('[data-testid="email-notification-toggle"]');
    await expect(inAppToggle).toBeChecked();
    await expect(emailToggle).toBeChecked();

    // Click on the email notification toggle to disable email notifications for comment edits
    await emailToggle.click();
    await expect(emailToggle).not.toBeChecked();
    await expect(inAppToggle).toBeChecked();

    // Click the Save or Update button to save the notification preferences
    await page.locator('[data-testid="save-preferences-button"]').click();
    
    // Expected Result: Preference is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Preferences saved successfully');

    // Navigate away from the settings page and then return to verify persistence
    await page.goto('/dashboard');
    await page.goto('/settings/notifications');
    const emailToggleAfterReload = page.locator('[data-testid="comment-edit-notifications-section"] [data-testid="email-notification-toggle"]');
    await expect(emailToggleAfterReload).not.toBeChecked();

    // Navigate to a task detail page with an existing comment
    await page.goto('/tasks/task-456');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // Edit an existing comment by modifying its text and saving the changes
    const commentItem = page.locator('[data-testid="comment-item"]').first();
    await commentItem.locator('[data-testid="edit-comment-button"]').click();
    await commentItem.locator('[data-testid="comment-editor"]').fill('Modified comment for preference testing');
    await commentItem.locator('[data-testid="save-comment-button"]').click();
    
    // Expected Result: Notification sent only via in-app, no email received
    await expect(commentItem.locator('[data-testid="comment-text"]')).toHaveText('Modified comment for preference testing');

    // Wait for up to 5 seconds and check the in-app notification icon
    await page.waitForTimeout(3000);
    const notificationBell = page.locator('[data-testid="notification-bell"]');
    await notificationBell.click();
    
    // Verify the in-app notification contains correct details about the comment edit
    const notificationDropdown = page.locator('[data-testid="notification-dropdown"]');
    const latestNotification = notificationDropdown.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toContainText('comment was edited');
    await expect(latestNotification).toContainText('Modified comment for preference testing');

    // Check the email inbox for any notification email regarding the comment edit
    await page.goto('/test-email-inbox');
    await page.waitForTimeout(5000);
    
    // Verify spam/junk folder to ensure email was not misdirected
    const emailList = page.locator('[data-testid="email-list"]');
    const commentEditEmails = emailList.locator('[data-testid="email-item"]').filter({ hasText: 'Modified comment for preference testing' });
    
    // Expected Result: No email received
    await expect(commentEditEmails).toHaveCount(0);
  });

  test('Ensure unauthorized users do not receive comment edit notifications (error-case)', async ({ page, context }) => {
    // Log in as User A (authorized user) and navigate to the task detail page
    await page.goto('/tasks/task-789');
    await expect(page.locator('[data-testid="task-detail-page"]')).toBeVisible();

    // As User A, locate an existing comment and click the edit button
    const commentItem = page.locator('[data-testid="comment-item"]').first();
    await commentItem.locator('[data-testid="edit-comment-button"]').click();

    // Modify the comment text with new content
    const commentEditor = commentItem.locator('[data-testid="comment-editor"]');
    await commentEditor.fill('This is an updated comment for testing');

    // Save the edited comment by clicking the Save or Update button
    await commentItem.locator('[data-testid="save-comment-button"]').click();
    
    // Expected Result: Comment is updated
    await expect(commentItem.locator('[data-testid="comment-text"]')).toHaveText('This is an updated comment for testing');
    await expect(page.locator('[data-testid="success-toast"]')).toContainText('Comment updated successfully');

    // Note the exact timestamp of the comment edit for audit verification
    const editTimestamp = await commentItem.locator('[data-testid="comment-timestamp"]').textContent();

    // Switch to User B's session (unauthorized user) or log in as User B in a different browser/incognito window
    const userBPage = await context.newPage();
    await userBPage.goto('/login');
    await userBPage.fill('[data-testid="email-input"]', 'unauthorized@company.com');
    await userBPage.fill('[data-testid="password-input"]', 'Password123!');
    await userBPage.click('[data-testid="login-button"]');
    await expect(userBPage).toHaveURL(/.*dashboard/);

    // As User B, check the in-app notification icon/bell for any new notifications
    await userBPage.waitForTimeout(3000);
    const userBNotificationBell = userBPage.locator('[data-testid="notification-bell"]');
    await userBNotificationBell.click();

    // As User B, navigate to the notifications page or notification center to view all notifications
    const userBNotificationDropdown = userBPage.locator('[data-testid="notification-dropdown"]');
    await expect(userBNotificationDropdown).toBeVisible();
    
    // Expected Result: No notification received
    const unauthorizedNotifications = userBNotificationDropdown.locator('[data-testid="notification-item"]').filter({ hasText: 'This is an updated comment for testing' });
    await expect(unauthorizedNotifications).toHaveCount(0);

    // Check User B's email inbox for any notification emails about the comment edit
    await userBPage.goto('/test-email-inbox');
    await userBPage.waitForTimeout(5000);
    const userBEmailList = userBPage.locator('[data-testid="email-list"]');
    const userBCommentEmails = userBEmailList.locator('[data-testid="email-item"]').filter({ hasText: 'This is an updated comment for testing' });
    await expect(userBCommentEmails).toHaveCount(0);

    // As User B, attempt to directly access the task URL to verify access control
    await userBPage.goto('/tasks/task-789');
    const accessDeniedMessage = userBPage.locator('[data-testid="access-denied-message"]');
    await expect(accessDeniedMessage).toBeVisible();
    await expect(accessDeniedMessage).toContainText('You do not have access to this task');

    // As User A or system administrator, access the audit logs or notification logs for the comment edit event
    await page.goto('/admin/audit-logs');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Review the audit logs to verify which users received notifications for the comment edit
    const searchInput = page.locator('[data-testid="audit-log-search"]');
    await searchInput.fill('task-789 comment edit');
    await page.locator('[data-testid="search-button"]').click();

    // Verify the audit log entry contains details such as: task ID, comment ID, editor name, timestamp, and list of notified users
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'This is an updated comment for testing' }).first();
    await expect(auditLogEntry).toBeVisible();
    await auditLogEntry.click();
    
    const auditDetails = page.locator('[data-testid="audit-log-details"]');
    await expect(auditDetails).toContainText('task-789');
    await expect(auditDetails).toContainText('Comment Edit');
    await expect(auditDetails.locator('[data-testid="editor-name"]')).toContainText('employee@company.com');
    
    // Expected Result: Notifications sent only to authorized users
    const notifiedUsers = auditDetails.locator('[data-testid="notified-users-list"]');
    await expect(notifiedUsers).toBeVisible();
    await expect(notifiedUsers).toContainText('employee@company.com');
    await expect(notifiedUsers).not.toContainText('unauthorized@company.com');

    await userBPage.close();
  });
});