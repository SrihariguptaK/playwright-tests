import { test, expect } from '@playwright/test';

test.describe('Employee Dashboard - Task Summary and Comments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Perform employee login
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await page.waitForURL('/dashboard');
  });

  test('Verify dashboard displays task status counts', async ({ page }) => {
    // Action: Employee logs into system and opens dashboard
    await page.goto('/dashboard');
    
    // Wait for dashboard to fully load
    await page.waitForSelector('[data-testid="dashboard-container"]', { timeout: 3000 });
    
    // Expected Result: Task counts by status are displayed correctly
    const taskStatusSection = page.locator('[data-testid="task-status-summary"]');
    await expect(taskStatusSection).toBeVisible();
    
    // Verify different status counts are displayed
    const pendingCount = page.locator('[data-testid="status-pending-count"]');
    await expect(pendingCount).toBeVisible();
    await expect(pendingCount).toContainText(/\d+/);
    
    const inProgressCount = page.locator('[data-testid="status-inprogress-count"]');
    await expect(inProgressCount).toBeVisible();
    await expect(inProgressCount).toContainText(/\d+/);
    
    const completedCount = page.locator('[data-testid="status-completed-count"]');
    await expect(completedCount).toBeVisible();
    await expect(completedCount).toContainText(/\d+/);
    
    // Verify status labels are present
    await expect(page.locator('text=Pending')).toBeVisible();
    await expect(page.locator('text=In Progress')).toBeVisible();
    await expect(page.locator('text=Completed')).toBeVisible();
  });

  test('Verify recent comments are shown on dashboard', async ({ page }) => {
    // Action: Employee views dashboard comments section
    await page.goto('/dashboard');
    
    // Wait for comments section to load
    await page.waitForSelector('[data-testid="recent-comments-section"]', { timeout: 3000 });
    
    // Expected Result: Recent comments related to tasks are displayed
    const commentsSection = page.locator('[data-testid="recent-comments-section"]');
    await expect(commentsSection).toBeVisible();
    
    // Verify comments section header
    await expect(page.locator('[data-testid="comments-section-header"]')).toContainText(/Recent Comments/i);
    
    // Verify at least one comment is displayed
    const commentItems = page.locator('[data-testid="comment-item"]');
    await expect(commentItems.first()).toBeVisible();
    
    // Verify comment structure contains expected elements
    const firstComment = commentItems.first();
    await expect(firstComment.locator('[data-testid="comment-text"]')).toBeVisible();
    await expect(firstComment.locator('[data-testid="comment-author"]')).toBeVisible();
    await expect(firstComment.locator('[data-testid="comment-timestamp"]')).toBeVisible();
    await expect(firstComment.locator('[data-testid="comment-task-reference"]')).toBeVisible();
    
    // Verify comments are related to employee's tasks
    const taskReference = firstComment.locator('[data-testid="comment-task-reference"]');
    await expect(taskReference).toContainText(/Task/i);
  });

  test('Test navigation from dashboard to task details', async ({ page }) => {
    // Action: Employee clicks on task link in dashboard
    await page.goto('/dashboard');
    
    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="dashboard-container"]', { timeout: 3000 });
    
    // Locate and click on first task link
    const taskLink = page.locator('[data-testid="task-link"]').first();
    await expect(taskLink).toBeVisible();
    
    // Get task ID or name for verification
    const taskText = await taskLink.textContent();
    
    // Click on task link
    await taskLink.click();
    
    // Expected Result: Task details page opens correctly
    await page.waitForURL(/\/tasks\/\d+/, { timeout: 5000 });
    
    // Verify task details page is loaded
    const taskDetailsContainer = page.locator('[data-testid="task-details-container"]');
    await expect(taskDetailsContainer).toBeVisible();
    
    // Verify task details elements are present
    await expect(page.locator('[data-testid="task-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-description"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="task-assignee"]')).toBeVisible();
    
    // Verify URL contains task identifier
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/\/tasks\/\d+/);
  });

  test('Verify dashboard loads within 3 seconds', async ({ page }) => {
    const startTime = Date.now();
    
    // Navigate to dashboard
    await page.goto('/dashboard');
    
    // Wait for dashboard to be fully loaded
    await page.waitForSelector('[data-testid="dashboard-container"]', { timeout: 3000 });
    await page.waitForSelector('[data-testid="task-status-summary"]', { timeout: 3000 });
    await page.waitForSelector('[data-testid="recent-comments-section"]', { timeout: 3000 });
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Verify dashboard loaded within 3 seconds (3000ms)
    expect(loadTime).toBeLessThan(3000);
  });

  test('Verify access restricted to authenticated employees', async ({ page, context }) => {
    // Clear authentication by creating new context
    await context.clearCookies();
    
    // Attempt to access dashboard without authentication
    await page.goto('/dashboard');
    
    // Verify redirect to login page or access denied
    await page.waitForURL(/\/login/, { timeout: 5000 });
    
    // Verify login page is displayed
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Verify dashboard is not accessible
    const dashboardContainer = page.locator('[data-testid="dashboard-container"]');
    await expect(dashboardContainer).not.toBeVisible();
  });
});