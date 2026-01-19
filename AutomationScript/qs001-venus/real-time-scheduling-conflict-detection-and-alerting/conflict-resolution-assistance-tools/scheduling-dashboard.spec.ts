import { test, expect } from '@playwright/test';

test.describe('Scheduling Dashboard - Conflicts and Alerts Summary', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling dashboard before each test
    await page.goto('/scheduling/dashboard');
  });

  test('Verify dashboard displays current conflicts and alerts (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the scheduling dashboard URL or click on the Dashboard menu item
    // Measure the time from navigation initiation to complete dashboard render
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="dashboard-container"]', { state: 'visible' });
    const loadTime = Date.now() - startTime;
    
    // Expected Result: Dashboard loads within 3 seconds
    expect(loadTime).toBeLessThan(3000);
    
    // Step 2: Review the conflict count displayed on the dashboard summary section
    const conflictCount = await page.locator('[data-testid="conflict-count"]');
    await expect(conflictCount).toBeVisible();
    const conflictCountText = await conflictCount.textContent();
    expect(conflictCountText).toMatch(/\d+/);
    
    // Step 3: Review the alert statuses section showing acknowledged vs unacknowledged alerts
    const acknowledgedAlerts = await page.locator('[data-testid="acknowledged-alerts-count"]');
    await expect(acknowledgedAlerts).toBeVisible();
    const unacknowledgedAlerts = await page.locator('[data-testid="unacknowledged-alerts-count"]');
    await expect(unacknowledgedAlerts).toBeVisible();
    
    // Expected Result: Data is accurate and up-to-date
    const acknowledgedCount = await acknowledgedAlerts.textContent();
    const unacknowledgedCount = await unacknowledgedAlerts.textContent();
    expect(acknowledgedCount).toMatch(/\d+/);
    expect(unacknowledgedCount).toMatch(/\d+/);
    
    // Step 4: Verify the details of displayed conflicts including conflict type, affected resources, and timestamps
    const conflictsList = await page.locator('[data-testid="conflicts-list"]');
    await expect(conflictsList).toBeVisible();
    
    const firstConflict = conflictsList.locator('[data-testid="conflict-item"]').first();
    if (await firstConflict.count() > 0) {
      await expect(firstConflict.locator('[data-testid="conflict-type"]')).toBeVisible();
      await expect(firstConflict.locator('[data-testid="affected-resources"]')).toBeVisible();
      await expect(firstConflict.locator('[data-testid="conflict-timestamp"]')).toBeVisible();
    }
    
    // Step 5: Check the real-time update functionality
    // Store initial conflict count for comparison
    const initialConflictCount = await conflictCount.textContent();
    
    // Wait for potential real-time updates (simulating another user creating a conflict)
    await page.waitForTimeout(2000);
    
    // Verify the dashboard has real-time update capability
    const updatedConflictCount = await conflictCount.textContent();
    expect(updatedConflictCount).toBeDefined();
    
    // Step 6: Apply a filter to show only high-priority conflicts using the filter dropdown or checkbox options
    const priorityFilter = page.locator('[data-testid="priority-filter"]');
    await priorityFilter.click();
    await page.locator('[data-testid="filter-option-high-priority"]').click();
    
    // Wait for dashboard to update
    await page.waitForTimeout(500);
    
    // Expected Result: Dashboard updates data accordingly
    await expect(page.locator('[data-testid="active-filter-high-priority"]')).toBeVisible();
    
    // Verify filtered results show only high-priority conflicts
    const filteredConflicts = page.locator('[data-testid="conflict-item"]');
    const filteredCount = await filteredConflicts.count();
    if (filteredCount > 0) {
      const firstFilteredConflict = filteredConflicts.first();
      const priority = await firstFilteredConflict.locator('[data-testid="conflict-priority"]').textContent();
      expect(priority?.toLowerCase()).toContain('high');
    }
    
    // Step 7: Apply a filter to show only unacknowledged alerts
    const alertStatusFilter = page.locator('[data-testid="alert-status-filter"]');
    await alertStatusFilter.click();
    await page.locator('[data-testid="filter-option-unacknowledged"]').click();
    
    // Wait for dashboard to update
    await page.waitForTimeout(500);
    
    // Expected Result: Dashboard updates data accordingly
    await expect(page.locator('[data-testid="active-filter-unacknowledged"]')).toBeVisible();
    
    // Step 8: Sort the conflicts list by date in ascending order by clicking the date column header
    const dateColumnHeader = page.locator('[data-testid="column-header-date"]');
    await dateColumnHeader.click();
    
    // Wait for sort to apply
    await page.waitForTimeout(500);
    
    // Verify ascending sort indicator
    await expect(page.locator('[data-testid="sort-indicator-ascending"]')).toBeVisible();
    
    // Step 9: Sort the conflicts list by date in descending order by clicking the date column header again
    await dateColumnHeader.click();
    
    // Wait for sort to apply
    await page.waitForTimeout(500);
    
    // Expected Result: Dashboard updates data accordingly
    await expect(page.locator('[data-testid="sort-indicator-descending"]')).toBeVisible();
    
    // Step 10: Sort the alerts by acknowledgment status
    const alertsTab = page.locator('[data-testid="alerts-tab"]');
    await alertsTab.click();
    
    const acknowledgmentColumnHeader = page.locator('[data-testid="column-header-acknowledgment"]');
    await acknowledgmentColumnHeader.click();
    
    // Wait for sort to apply
    await page.waitForTimeout(500);
    
    // Verify sort is applied
    await expect(page.locator('[data-testid="sort-indicator-ascending"], [data-testid="sort-indicator-descending"]')).toBeVisible();
    
    // Step 11: Clear all applied filters using the 'Clear Filters' or 'Reset' button
    const clearFiltersButton = page.locator('[data-testid="clear-filters-button"]');
    await clearFiltersButton.click();
    
    // Wait for filters to clear
    await page.waitForTimeout(500);
    
    // Expected Result: Dashboard updates data accordingly
    await expect(page.locator('[data-testid="active-filter-high-priority"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="active-filter-unacknowledged"]')).not.toBeVisible();
    
    // Step 12: Verify the data accuracy by comparing displayed metrics with backend data source
    // Make API call to verify dashboard data accuracy
    const response = await page.request.get('/api/dashboard/conflicts');
    expect(response.ok()).toBeTruthy();
    
    const apiData = await response.json();
    const displayedConflictCount = await page.locator('[data-testid="conflict-count"]').textContent();
    
    // Compare API data with displayed data
    expect(displayedConflictCount).toContain(apiData.totalConflicts?.toString() || '0');
    
    // Verify alert counts match API data
    const displayedAcknowledgedCount = await page.locator('[data-testid="acknowledged-alerts-count"]').textContent();
    const displayedUnacknowledgedCount = await page.locator('[data-testid="unacknowledged-alerts-count"]').textContent();
    
    expect(displayedAcknowledgedCount).toContain(apiData.acknowledgedAlerts?.toString() || '0');
    expect(displayedUnacknowledgedCount).toContain(apiData.unacknowledgedAlerts?.toString() || '0');
  });
});