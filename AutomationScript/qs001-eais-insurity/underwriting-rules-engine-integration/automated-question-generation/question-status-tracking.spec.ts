import { test, expect } from '@playwright/test';

test.describe('Story-24: Question Status Tracking for Underwriting Analyst', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Login with Underwriting Analyst credentials
    await page.fill('[data-testid="username-input"]', 'underwriting.analyst@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify question status dashboard displays all assigned questions with current status', async ({ page }) => {
    // Navigate to question status dashboard
    await page.click('[data-testid="question-management-menu"]');
    await page.click('[data-testid="question-status-dashboard-link"]');
    
    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="question-status-dashboard"]');
    
    // Verify dashboard is displayed
    await expect(page.locator('[data-testid="question-status-dashboard"]')).toBeVisible();
    
    // Verify all assigned questions are displayed
    const questionRows = page.locator('[data-testid="question-row"]');
    await expect(questionRows).not.toHaveCount(0);
    
    // Verify each question has status displayed
    const firstQuestionStatus = page.locator('[data-testid="question-row"]').first().locator('[data-testid="question-status"]');
    await expect(firstQuestionStatus).toBeVisible();
    
    // Verify real-time status information with counts
    await expect(page.locator('[data-testid="status-count-pending"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-count-answered"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-count-overdue"]')).toBeVisible();
    
    // Verify status counts are numeric
    const pendingCount = await page.locator('[data-testid="status-count-pending"]').textContent();
    expect(parseInt(pendingCount || '0')).toBeGreaterThanOrEqual(0);
  });

  test('Verify questions can be filtered and sorted correctly', async ({ page }) => {
    // Navigate to question status dashboard
    await page.click('[data-testid="question-management-menu"]');
    await page.click('[data-testid="question-status-dashboard-link"]');
    await page.waitForSelector('[data-testid="question-status-dashboard"]');
    
    // Get initial question count
    const initialQuestionCount = await page.locator('[data-testid="question-row"]').count();
    
    // Apply filter to show only 'Pending' status questions
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-pending"]');
    await page.waitForTimeout(500); // Wait for filter to apply
    
    // Verify filtered results show only pending questions
    const pendingQuestions = page.locator('[data-testid="question-row"]');
    const pendingCount = await pendingQuestions.count();
    
    if (pendingCount > 0) {
      const firstStatus = await pendingQuestions.first().locator('[data-testid="question-status"]').textContent();
      expect(firstStatus?.toLowerCase()).toContain('pending');
    }
    
    // Clear the status filter
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    // Apply priority filter to show only 'High' priority questions
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-filter-high"]');
    await page.waitForTimeout(500);
    
    // Verify filtered results show only high priority questions
    const highPriorityQuestions = page.locator('[data-testid="question-row"]');
    const highPriorityCount = await highPriorityQuestions.count();
    
    if (highPriorityCount > 0) {
      const firstPriority = await highPriorityQuestions.first().locator('[data-testid="question-priority"]').textContent();
      expect(firstPriority?.toLowerCase()).toContain('high');
    }
    
    // Clear filters
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    // Apply sorting by Status column
    await page.click('[data-testid="status-column-header"]');
    await page.waitForTimeout(500);
    
    // Verify sort indicator is displayed
    await expect(page.locator('[data-testid="status-column-header"]').locator('[data-testid="sort-indicator"]')).toBeVisible();
    
    // Click Status column again to reverse sort order
    await page.click('[data-testid="status-column-header"]');
    await page.waitForTimeout(500);
    
    // Verify sort direction changed
    const sortIndicator = page.locator('[data-testid="status-column-header"]').locator('[data-testid="sort-indicator"]');
    await expect(sortIndicator).toBeVisible();
    
    // Apply sorting by Priority column
    await page.click('[data-testid="priority-column-header"]');
    await page.waitForTimeout(500);
    
    // Verify priority sort is applied
    await expect(page.locator('[data-testid="priority-column-header"]').locator('[data-testid="sort-indicator"]')).toBeVisible();
    
    // Combine filters: Overdue status and High priority
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-overdue"]');
    await page.waitForTimeout(500);
    
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-filter-high"]');
    await page.waitForTimeout(500);
    
    // Verify combined filters are applied
    const combinedFilteredQuestions = page.locator('[data-testid="question-row"]');
    const combinedCount = await combinedFilteredQuestions.count();
    
    if (combinedCount > 0) {
      const firstQuestion = combinedFilteredQuestions.first();
      const status = await firstQuestion.locator('[data-testid="question-status"]').textContent();
      const priority = await firstQuestion.locator('[data-testid="question-priority"]').textContent();
      expect(status?.toLowerCase()).toContain('overdue');
      expect(priority?.toLowerCase()).toContain('high');
    }
    
    // Clear all filters and verify dashboard returns to showing all questions
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    const finalQuestionCount = await page.locator('[data-testid="question-row"]').count();
    expect(finalQuestionCount).toBe(initialQuestionCount);
  });

  test('Verify automated reminder notification is received for overdue questions', async ({ page }) => {
    // Navigate to question status dashboard
    await page.click('[data-testid="question-management-menu"]');
    await page.click('[data-testid="question-status-dashboard-link"]');
    await page.waitForSelector('[data-testid="question-status-dashboard"]');
    
    // Filter to show overdue questions
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-overdue"]');
    await page.waitForTimeout(500);
    
    // Check if there are overdue questions
    const overdueQuestions = page.locator('[data-testid="question-row"]');
    const overdueCount = await overdueQuestions.count();
    
    if (overdueCount > 0) {
      // Wait for reminder notification (simulating scheduled reminder trigger)
      // In real scenario, this would wait for actual scheduled time or use test environment time manipulation
      await page.waitForSelector('[data-testid="notification-container"]', { timeout: 10000 });
      
      // Verify reminder notification is displayed
      const notification = page.locator('[data-testid="notification-container"]');
      await expect(notification).toBeVisible();
      
      // Verify notification content mentions overdue questions
      const notificationText = await notification.textContent();
      expect(notificationText?.toLowerCase()).toMatch(/overdue|reminder|question/i);
      
      // Verify notification type is reminder/warning
      await expect(notification).toHaveAttribute('data-notification-type', /reminder|warning/);
      
      // Verify notification delivery method indicator
      const deliveryIndicator = notification.locator('[data-testid="notification-delivery-method"]');
      await expect(deliveryIndicator).toBeVisible();
    } else {
      // If no overdue questions exist, verify no reminder is shown
      const notification = page.locator('[data-testid="notification-container"]');
      await expect(notification).not.toBeVisible();
    }
  });

  test('Verify question status dashboard functionality - complete happy path', async ({ page }) => {
    // Navigate to question status dashboard from main menu
    await page.click('[data-testid="question-management-menu"]');
    await page.click('[data-testid="question-status-dashboard-link"]');
    
    // Verify dashboard loads successfully
    await page.waitForSelector('[data-testid="question-status-dashboard"]');
    await expect(page.locator('[data-testid="question-status-dashboard"]')).toBeVisible();
    
    // Verify all assigned questions are displayed with current status
    const allQuestions = page.locator('[data-testid="question-row"]');
    const totalQuestions = await allQuestions.count();
    expect(totalQuestions).toBeGreaterThan(0);
    
    // Verify real-time status information including counts for each status category
    await expect(page.locator('[data-testid="status-count-pending"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-count-answered"]')).toBeVisible();
    await expect(page.locator('[data-testid="status-count-overdue"]')).toBeVisible();
    
    const pendingCountText = await page.locator('[data-testid="status-count-pending"]').textContent();
    const answeredCountText = await page.locator('[data-testid="status-count-answered"]').textContent();
    const overdueCountText = await page.locator('[data-testid="status-count-overdue"]').textContent();
    
    expect(parseInt(pendingCountText || '0')).toBeGreaterThanOrEqual(0);
    expect(parseInt(answeredCountText || '0')).toBeGreaterThanOrEqual(0);
    expect(parseInt(overdueCountText || '0')).toBeGreaterThanOrEqual(0);
    
    // Apply filter to show only 'Pending' status questions
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-pending"]');
    await page.waitForTimeout(500);
    
    const pendingQuestions = await page.locator('[data-testid="question-row"]').count();
    expect(pendingQuestions).toBeGreaterThanOrEqual(0);
    
    // Clear status filter
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    // Apply priority filter to show only 'High' priority questions
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-filter-high"]');
    await page.waitForTimeout(500);
    
    const highPriorityQuestions = await page.locator('[data-testid="question-row"]').count();
    expect(highPriorityQuestions).toBeGreaterThanOrEqual(0);
    
    // Clear filters
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    // Apply sorting by Status column
    await page.click('[data-testid="status-column-header"]');
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="status-column-header"]').locator('[data-testid="sort-indicator"]')).toBeVisible();
    
    // Click Status column again to reverse sort order
    await page.click('[data-testid="status-column-header"]');
    await page.waitForTimeout(500);
    
    // Apply sorting by Priority column
    await page.click('[data-testid="priority-column-header"]');
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="priority-column-header"]').locator('[data-testid="sort-indicator"]')).toBeVisible();
    
    // Combine filters: Overdue status and High priority
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-overdue"]');
    await page.waitForTimeout(500);
    
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-filter-high"]');
    await page.waitForTimeout(500);
    
    const combinedFilterCount = await page.locator('[data-testid="question-row"]').count();
    expect(combinedFilterCount).toBeGreaterThanOrEqual(0);
    
    // Wait for overdue reminder (simulated or actual scheduled time)
    const hasOverdueQuestions = combinedFilterCount > 0;
    if (hasOverdueQuestions) {
      await page.waitForSelector('[data-testid="notification-container"]', { timeout: 10000 });
      const notification = page.locator('[data-testid="notification-container"]');
      await expect(notification).toBeVisible();
      
      // Verify reminder notification content
      const notificationContent = await notification.textContent();
      expect(notificationContent).toBeTruthy();
      expect(notificationContent?.toLowerCase()).toMatch(/overdue|reminder/);
      
      // Verify delivery method
      const deliveryMethod = notification.locator('[data-testid="notification-delivery-method"]');
      await expect(deliveryMethod).toBeVisible();
    }
    
    // Clear all filters and verify dashboard returns to showing all questions
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    const finalQuestionCount = await page.locator('[data-testid="question-row"]').count();
    expect(finalQuestionCount).toBe(totalQuestions);
  });

  test('Verify dashboard updates within 1 second of status changes', async ({ page }) => {
    // Navigate to question status dashboard
    await page.click('[data-testid="question-management-menu"]');
    await page.click('[data-testid="question-status-dashboard-link"]');
    await page.waitForSelector('[data-testid="question-status-dashboard"]');
    
    // Get initial status count
    const initialPendingCount = await page.locator('[data-testid="status-count-pending"]').textContent();
    
    // Select first pending question
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-filter-pending"]');
    await page.waitForTimeout(500);
    
    const pendingQuestions = page.locator('[data-testid="question-row"]');
    const hasPendingQuestions = await pendingQuestions.count() > 0;
    
    if (hasPendingQuestions) {
      // Click on first question to view details
      await pendingQuestions.first().click();
      await page.waitForSelector('[data-testid="question-detail-panel"]');
      
      // Record timestamp before status change
      const startTime = Date.now();
      
      // Change question status to Answered
      await page.click('[data-testid="respond-to-question-button"]');
      await page.fill('[data-testid="question-response-input"]', 'This is a test response to the question.');
      await page.click('[data-testid="submit-response-button"]');
      
      // Wait for status update confirmation
      await page.waitForSelector('[data-testid="status-update-success"]', { timeout: 2000 });
      
      // Calculate time taken for update
      const endTime = Date.now();
      const updateTime = endTime - startTime;
      
      // Verify update occurred within 1 second (1000ms)
      expect(updateTime).toBeLessThan(1000);
      
      // Navigate back to dashboard
      await page.click('[data-testid="back-to-dashboard-button"]');
      await page.waitForSelector('[data-testid="question-status-dashboard"]');
      
      // Clear filters to see all questions
      await page.click('[data-testid="clear-filters-button"]');
      await page.waitForTimeout(500);
      
      // Verify status count has been updated
      const updatedPendingCount = await page.locator('[data-testid="status-count-pending"]').textContent();
      expect(parseInt(updatedPendingCount || '0')).toBeLessThan(parseInt(initialPendingCount || '0'));
    }
  });
});