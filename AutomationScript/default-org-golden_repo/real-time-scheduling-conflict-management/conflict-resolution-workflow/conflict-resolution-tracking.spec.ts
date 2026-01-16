import { test, expect } from '@playwright/test';

test.describe('Conflict Resolution Status Tracking', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to scheduling system
    await page.goto('/scheduling');
    // Assume user is already authenticated
  });

  test('Track and update conflict resolution status', async ({ page }) => {
    // Step 1: Trigger a conflict detection by attempting to schedule overlapping resources
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T12:00');
    await page.click('[data-testid="submit-schedule-button"]');

    // Attempt to create overlapping schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T11:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T13:00');
    await page.click('[data-testid="submit-schedule-button"]');

    // Expected Result: Conflict is detected and status set to pending
    await expect(page.locator('[data-testid="conflict-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-status"]')).toHaveText('pending');

    // Step 2: Verify the conflict status is recorded
    const response = await page.request.get('/conflicts/status');
    expect(response.ok()).toBeTruthy();
    const conflicts = await response.json();
    const pendingConflict = conflicts.find((c: any) => c.status === 'pending');
    expect(pendingConflict).toBeDefined();
    expect(pendingConflict.status).toBe('pending');

    // Step 3: Access the conflict resolution interface
    await page.click('[data-testid="view-conflicts-button"]');
    await page.waitForSelector('[data-testid="conflict-list"]');
    
    // Select the pending conflict from the list
    const conflictId = pendingConflict.id;
    await page.click(`[data-testid="conflict-item-${conflictId}"]`);

    // Step 4: Apply a resolution action
    await page.click('[data-testid="resolve-conflict-button"]');
    await page.click('[data-testid="reschedule-option"]');
    await page.fill('[data-testid="new-start-time-input"]', '2024-01-15T13:00');
    await page.fill('[data-testid="new-end-time-input"]', '2024-01-15T15:00');
    await page.click('[data-testid="submit-resolution-button"]');

    // Expected Result: Status updates to resolved
    await expect(page.locator('[data-testid="resolution-success-message"]')).toBeVisible();

    // Step 5: Navigate to the conflict dashboard
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="conflict-dashboard-link"]');
    await page.waitForLoadState('networkidle');

    // Step 6: Verify the conflict status is displayed accurately
    await page.waitForSelector('[data-testid="dashboard-content"]');
    const resolvedConflict = page.locator(`[data-testid="conflict-row-${conflictId}"]`);
    await expect(resolvedConflict).toBeVisible();
    await expect(resolvedConflict.locator('[data-testid="status-cell"]')).toHaveText('resolved');
  });

  test('Filter and sort conflicts on dashboard', async ({ page }) => {
    // Step 1: Navigate to the conflict dashboard
    await page.click('[data-testid="dashboard-menu"]');
    await page.click('[data-testid="conflict-dashboard-link"]');
    
    // Wait for the initial load to complete
    await page.waitForLoadState('networkidle');
    await page.waitForSelector('[data-testid="dashboard-content"]');
    
    // Verify dashboard loads within 3 seconds
    const startTime = Date.now();
    await expect(page.locator('[data-testid="conflict-table"]')).toBeVisible();
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(3000);

    // Step 2: Locate the status filter dropdown
    const statusFilter = page.locator('[data-testid="status-filter-dropdown"]');
    await expect(statusFilter).toBeVisible();

    // Step 3: Select 'pending' from the status filter and apply
    await statusFilter.click();
    await page.click('[data-testid="filter-option-pending"]');
    await page.click('[data-testid="apply-filter-button"]');

    // Expected Result: Dashboard shows only pending conflicts
    await page.waitForSelector('[data-testid="conflict-row"]');
    const conflictRows = page.locator('[data-testid="conflict-row"]');
    const rowCount = await conflictRows.count();
    
    // Step 4: Verify the filtered results
    for (let i = 0; i < rowCount; i++) {
      const statusCell = conflictRows.nth(i).locator('[data-testid="status-cell"]');
      await expect(statusCell).toHaveText('pending');
    }

    // Step 5: Clear the status filter
    await statusFilter.click();
    await page.click('[data-testid="filter-option-all"]');
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForLoadState('networkidle');

    // Step 6: Locate the sort options and click on the Date column
    const dateColumnHeader = page.locator('[data-testid="date-column-header"]');
    await expect(dateColumnHeader).toBeVisible();
    
    // Step 7: Apply ascending date sort
    await dateColumnHeader.click();
    await page.waitForTimeout(500); // Wait for sort to apply

    // Verify the order of conflicts displayed
    const conflictDates = await page.locator('[data-testid="conflict-row"] [data-testid="date-cell"]').allTextContents();
    const sortedDates = [...conflictDates].sort();
    expect(conflictDates).toEqual(sortedDates);

    // Step 8: Click the date sort control again to reverse to descending
    await dateColumnHeader.click();
    await page.waitForTimeout(500);

    // Verify descending order
    const conflictDatesDesc = await page.locator('[data-testid="conflict-row"] [data-testid="date-cell"]').allTextContents();
    const sortedDatesDesc = [...conflictDatesDesc].sort().reverse();
    expect(conflictDatesDesc).toEqual(sortedDatesDesc);

    // Step 9: Combine filters by applying status filter while maintaining date sort
    await statusFilter.click();
    await page.click('[data-testid="filter-option-pending"]');
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForLoadState('networkidle');

    // Verify both filter and sort are applied
    const filteredRows = page.locator('[data-testid="conflict-row"]');
    const filteredCount = await filteredRows.count();
    
    for (let i = 0; i < filteredCount; i++) {
      const statusCell = filteredRows.nth(i).locator('[data-testid="status-cell"]');
      await expect(statusCell).toHaveText('pending');
    }
    
    // Verify sort order is maintained
    const filteredDates = await page.locator('[data-testid="conflict-row"] [data-testid="date-cell"]').allTextContents();
    const sortedFilteredDates = [...filteredDates].sort().reverse();
    expect(filteredDates).toEqual(sortedFilteredDates);
  });
});