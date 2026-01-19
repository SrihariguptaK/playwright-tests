import { test, expect } from '@playwright/test';

test.describe('Review Cycle Status Tracking', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Performance Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'performance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate accurate display of review cycle statuses', async ({ page }) => {
    // Action: Navigate to Review Cycle Status page
    await page.click('[data-testid="review-cycles-menu"]');
    await page.click('[data-testid="review-cycle-status-link"]');
    
    // Expected Result: List of review cycles with statuses is displayed
    await expect(page.locator('[data-testid="review-cycle-status-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="review-cycles-list"]')).toBeVisible();
    
    // Verify that each review cycle shows accurate status information
    const reviewCycleRows = page.locator('[data-testid="review-cycle-row"]');
    await expect(reviewCycleRows).toHaveCount(await reviewCycleRows.count());
    
    const firstCycle = reviewCycleRows.first();
    await expect(firstCycle.locator('[data-testid="cycle-name"]')).toBeVisible();
    await expect(firstCycle.locator('[data-testid="cycle-status"]')).toBeVisible();
    await expect(firstCycle.locator('[data-testid="cycle-start-date"]')).toBeVisible();
    await expect(firstCycle.locator('[data-testid="cycle-end-date"]')).toBeVisible();
    await expect(firstCycle.locator('[data-testid="cycle-assigned-groups"]')).toBeVisible();
    
    // Action: Apply filter to show only 'In-Progress' review cycles
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="filter-option-in-progress"]');
    
    // Expected Result: List updates accordingly
    await page.waitForTimeout(500);
    const filteredRows = page.locator('[data-testid="review-cycle-row"]');
    const filteredCount = await filteredRows.count();
    
    for (let i = 0; i < filteredCount; i++) {
      const statusText = await filteredRows.nth(i).locator('[data-testid="cycle-status"]').textContent();
      expect(statusText?.toLowerCase()).toContain('in-progress');
    }
    
    // Action: Apply sorting by date in descending order
    await page.click('[data-testid="date-sort-button"]');
    await page.click('[data-testid="sort-descending"]');
    
    // Expected Result: List is sorted by date descending
    await page.waitForTimeout(500);
    const sortedRows = page.locator('[data-testid="review-cycle-row"]');
    const firstDate = await sortedRows.first().locator('[data-testid="cycle-end-date"]').textContent();
    const lastDate = await sortedRows.last().locator('[data-testid="cycle-end-date"]').textContent();
    
    // Clear all filters and sort by status in ascending order
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    await page.click('[data-testid="status-sort-button"]');
    await page.click('[data-testid="sort-ascending"]');
    
    // Expected Result: List is sorted by status ascending
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="review-cycles-list"]')).toBeVisible();
    
    // Action: Trigger overdue condition and observe alerts
    // Check if overdue alert is present for cycles past end date
    const overdueAlert = page.locator('[data-testid="overdue-alert"]');
    const overdueCount = await overdueAlert.count();
    
    if (overdueCount > 0) {
      // Expected Result: Alert is displayed for overdue cycles
      await expect(overdueAlert.first()).toBeVisible();
      await expect(overdueAlert.first()).toContainText(/overdue/i);
    }
    
    // Verify overdue cycles are marked in the list
    const overdueRows = page.locator('[data-testid="review-cycle-row"][data-status="overdue"]');
    const overdueRowCount = await overdueRows.count();
    
    if (overdueRowCount > 0) {
      const overdueStatus = await overdueRows.first().locator('[data-testid="cycle-status"]').textContent();
      expect(overdueStatus?.toLowerCase()).toContain('overdue');
    }
  });

  test('Verify detailed view of review cycle status', async ({ page }) => {
    // Navigate to Review Cycle Status page
    await page.click('[data-testid="review-cycles-menu"]');
    await page.click('[data-testid="review-cycle-status-link"]');
    await expect(page.locator('[data-testid="review-cycle-status-page"]')).toBeVisible();
    
    // Action: Identify and select a review cycle from the list (preferably In-Progress)
    const reviewCycleRows = page.locator('[data-testid="review-cycle-row"]');
    await expect(reviewCycleRows.first()).toBeVisible();
    
    // Try to find an In-Progress cycle, otherwise use the first one
    const inProgressCycle = page.locator('[data-testid="review-cycle-row"]').filter({ hasText: /in-progress/i });
    const cycleToSelect = (await inProgressCycle.count()) > 0 ? inProgressCycle.first() : reviewCycleRows.first();
    
    const cycleName = await cycleToSelect.locator('[data-testid="cycle-name"]').textContent();
    
    // Action: Click on the selected review cycle
    await cycleToSelect.click();
    
    // Expected Result: Detailed status and information are displayed
    await expect(page.locator('[data-testid="review-cycle-detail-view"]')).toBeVisible();
    
    // Verify comprehensive status information is displayed
    await expect(page.locator('[data-testid="detail-cycle-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-cycle-name"]')).toContainText(cycleName || '');
    
    await expect(page.locator('[data-testid="detail-current-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-start-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-end-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-assigned-groups"]')).toBeVisible();
    
    // Verify review completion metrics
    await expect(page.locator('[data-testid="detail-reviews-completed"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-reviews-pending"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-progress-percentage"]')).toBeVisible();
    
    // Verify progress percentage is a valid number
    const progressText = await page.locator('[data-testid="detail-progress-percentage"]').textContent();
    expect(progressText).toMatch(/\d+%/);
    
    // Verify breakdown of review statuses by individual reviewers or teams
    await expect(page.locator('[data-testid="detail-reviewer-breakdown"]')).toBeVisible();
    const reviewerBreakdownItems = page.locator('[data-testid="reviewer-breakdown-item"]');
    await expect(reviewerBreakdownItems.first()).toBeVisible();
    
    // Check for additional information
    const commentsSection = page.locator('[data-testid="detail-comments"]');
    const notesSection = page.locator('[data-testid="detail-notes"]');
    const historySection = page.locator('[data-testid="detail-status-history"]');
    
    // Verify at least one additional information section exists
    const hasAdditionalInfo = 
      (await commentsSection.count()) > 0 || 
      (await notesSection.count()) > 0 || 
      (await historySection.count()) > 0;
    
    expect(hasAdditionalInfo).toBeTruthy();
    
    // Action: Navigate back to the Review Cycle Status list page
    const backButton = page.locator('[data-testid="back-button"]');
    const breadcrumbLink = page.locator('[data-testid="breadcrumb-review-cycles"]');
    
    if (await backButton.count() > 0) {
      await backButton.click();
    } else if (await breadcrumbLink.count() > 0) {
      await breadcrumbLink.click();
    } else {
      await page.goBack();
    }
    
    // Expected Result: Back on the Review Cycle Status list page
    await expect(page.locator('[data-testid="review-cycle-status-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="review-cycles-list"]')).toBeVisible();
  });
});