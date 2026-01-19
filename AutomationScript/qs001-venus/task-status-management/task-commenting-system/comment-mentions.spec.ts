import { test, expect } from '@playwright/test';

test.describe('Comment Mentions Functionality', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to task detail page where comments can be added
    await page.goto('/tasks/123');
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate autocomplete suggestions for mentions - happy path', async ({ page }) => {
    // Step 1: Type '@' followed by characters in comment input
    const commentInput = page.locator('[data-testid="comment-input"]').or(page.locator('textarea[placeholder*="comment" i]')).or(page.locator('#comment-input'));
    await commentInput.click();
    
    const startTime = Date.now();
    await commentInput.fill('@joh');
    
    // Expected Result: Autocomplete list of matching users appears within 1 second
    const autocompleteList = page.locator('[data-testid="mention-autocomplete"]').or(page.locator('.mention-suggestions')).or(page.locator('[role="listbox"]'));
    await expect(autocompleteList).toBeVisible({ timeout: 1000 });
    
    const responseTime = Date.now() - startTime;
    expect(responseTime).toBeLessThan(1000);
    
    // Verify matching users are displayed
    const userOption = page.locator('[data-testid="mention-option"]').or(page.locator('.mention-option')).filter({ hasText: 'John Smith' });
    await expect(userOption).toBeVisible();
    
    // Step 2: Select a user from autocomplete list
    await userOption.click();
    
    // Expected Result: Mention is inserted into comment input correctly
    await expect(commentInput).toHaveValue(/@John Smith/);
    
    // Step 3: Submit the comment
    await commentInput.fill('@John Smith please review this task');
    const submitButton = page.locator('[data-testid="submit-comment"]').or(page.locator('button:has-text("Submit")')).or(page.locator('button:has-text("Post")')).first();
    await submitButton.click();
    
    // Expected Result: Comment is saved and displayed with mention highlighted
    await expect(page.locator('[data-testid="comment-list"]').or(page.locator('.comments-section'))).toContainText('@John Smith please review this task');
    
    const mentionHighlight = page.locator('[data-testid="mention-highlight"]').or(page.locator('.mention')).or(page.locator('.highlighted-mention')).filter({ hasText: 'John Smith' });
    await expect(mentionHighlight).toBeVisible();
  });

  test('Verify notifications sent to mentioned users - happy path', async ({ page, context }) => {
    // Step 1: Submit a comment with @mention
    const commentInput = page.locator('[data-testid="comment-input"]').or(page.locator('textarea[placeholder*="comment" i]')).or(page.locator('#comment-input'));
    await commentInput.click();
    await commentInput.fill('@jan');
    
    // Wait for autocomplete and select user
    const autocompleteList = page.locator('[data-testid="mention-autocomplete"]').or(page.locator('.mention-suggestions')).or(page.locator('[role="listbox"]'));
    await expect(autocompleteList).toBeVisible({ timeout: 1000 });
    
    const userOption = page.locator('[data-testid="mention-option"]').or(page.locator('.mention-option')).filter({ hasText: 'Jane Doe' });
    await userOption.click();
    
    await commentInput.fill('@Jane Doe can you help with this?');
    const submitButton = page.locator('[data-testid="submit-comment"]').or(page.locator('button:has-text("Submit")')).or(page.locator('button:has-text("Post")')).first();
    await submitButton.click();
    
    // Expected Result: Comment is saved successfully
    await expect(page.locator('[data-testid="comment-list"]').or(page.locator('.comments-section'))).toContainText('@Jane Doe can you help with this?');
    
    // Step 2: Check notification system for mentioned user
    // Open new page/tab as the mentioned user (Jane Doe)
    const janePage = await context.newPage();
    await janePage.goto('/login');
    await janePage.locator('[data-testid="username-input"]').or(janePage.locator('input[name="username"]')).fill('jane.doe');
    await janePage.locator('[data-testid="password-input"]').or(janePage.locator('input[name="password"]')).fill('password123');
    await janePage.locator('[data-testid="login-button"]').or(janePage.locator('button[type="submit"]')).click();
    
    // Navigate to notifications
    await janePage.waitForLoadState('networkidle');
    const notificationIcon = janePage.locator('[data-testid="notifications-icon"]').or(janePage.locator('.notification-bell')).or(janePage.locator('a[href*="notifications"]'));
    await notificationIcon.click();
    
    // Expected Result: User receives notification with comment details
    const notification = janePage.locator('[data-testid="notification-item"]').or(janePage.locator('.notification')).first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('mentioned you');
    
    // Step 3: Verify notification content accuracy
    await notification.click();
    
    // Expected Result: Notification includes task and comment context
    await expect(janePage.locator('[data-testid="notification-details"]').or(janePage.locator('.notification-content'))).toContainText('can you help with this?');
    await expect(janePage.locator('[data-testid="task-name"]').or(janePage.locator('.task-title'))).toBeVisible();
    await expect(janePage.locator('[data-testid="commenter-name"]').or(janePage.locator('.comment-author'))).toBeVisible();
    await expect(janePage.locator('[data-testid="comment-timestamp"]').or(janePage.locator('.timestamp'))).toBeVisible();
    
    await janePage.close();
  });

  test('Ensure input sanitization prevents injection via mentions - error case', async ({ page }) => {
    // Step 1: Enter mention input with special characters or scripts
    const commentInput = page.locator('[data-testid="comment-input"]').or(page.locator('textarea[placeholder*="comment" i]')).or(page.locator('#comment-input'));
    await commentInput.click();
    
    // Test XSS attempt with script tag
    await commentInput.fill('@<script>alert("XSS")</script>');
    
    // Expected Result: System sanitizes input and prevents execution
    // Check that no alert is triggered (Playwright would fail if alert appears unexpectedly)
    
    // Step 2: Submit the comment
    const submitButton = page.locator('[data-testid="submit-comment"]').or(page.locator('button:has-text("Submit")')).or(page.locator('button:has-text("Post")')).first();
    await submitButton.click();
    
    // Expected Result: Comment is saved as plain text without security issues
    const savedComment = page.locator('[data-testid="comment-list"]').or(page.locator('.comments-section')).last();
    await expect(savedComment).toBeVisible();
    
    // Verify the script tag is rendered as plain text, not executed
    const commentText = await savedComment.textContent();
    expect(commentText).toContain('<script>');
    expect(commentText).toContain('</script>');
    
    // Verify no script elements were injected into DOM
    const injectedScripts = page.locator('script:has-text("alert")');
    await expect(injectedScripts).toHaveCount(0);
    
    // Test SQL injection attempt
    await commentInput.clear();
    await commentInput.fill("@user'; DROP TABLE users;--");
    await submitButton.click();
    
    // Verify comment is saved safely
    await expect(page.locator('[data-testid="comment-list"]').or(page.locator('.comments-section'))).toContainText("DROP TABLE users");
    
    // Test another XSS variant
    await commentInput.clear();
    await commentInput.fill('@user"><script>alert("XSS")</script>');
    await submitButton.click();
    
    // Step 3: Verify system stability and security logs
    // Expected Result: No errors or security alerts are generated
    
    // Check browser console for errors
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    // Refresh page to verify data integrity
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Verify comments are still displayed correctly
    await expect(page.locator('[data-testid="comment-list"]').or(page.locator('.comments-section'))).toBeVisible();
    
    // Verify no JavaScript errors occurred
    expect(consoleErrors.filter(err => err.includes('script') || err.includes('injection'))).toHaveLength(0);
    
    // Verify page is still functional
    await expect(commentInput).toBeVisible();
    await expect(submitButton).toBeEnabled();
  });
});