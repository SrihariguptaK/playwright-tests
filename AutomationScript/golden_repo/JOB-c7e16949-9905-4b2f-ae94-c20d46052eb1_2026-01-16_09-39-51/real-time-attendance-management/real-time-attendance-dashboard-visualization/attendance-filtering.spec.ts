import { test, expect } from '@playwright/test';

test.describe('Attendance Dashboard Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to attendance dashboard
    await page.goto('/dashboard/attendance');
    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="attendance-dashboard"]', { timeout: 5000 });
  });

  test('Validate filtering by team (happy-path)', async ({ page }) => {
    // Observe the initial dashboard state and note the total number of employees displayed
    const initialEmployeeCount = await page.locator('[data-testid="employee-record"]').count();
    expect(initialEmployeeCount).toBeGreaterThan(0);

    // Locate the team filter dropdown on the dashboard
    const teamFilterDropdown = page.locator('[data-testid="team-filter-dropdown"]');
    await expect(teamFilterDropdown).toBeVisible();

    // Click on the team filter dropdown
    await teamFilterDropdown.click();

    // Select a specific team from the dropdown list (e.g., 'Engineering Team')
    await page.locator('[data-testid="team-option-engineering"]').click();

    // Observe the dashboard update after team selection
    await page.waitForTimeout(500);
    const filteredEmployeeCount = await page.locator('[data-testid="employee-record"]').count();

    // Verify that all displayed employee records belong to the selected team
    const employeeRecords = await page.locator('[data-testid="employee-record"]').all();
    for (const record of employeeRecords) {
      const teamName = await record.locator('[data-testid="employee-team"]').textContent();
      expect(teamName).toContain('Engineering Team');
    }

    // Check the summary metrics (total present, absent, late)
    await expect(page.locator('[data-testid="summary-metrics"]')).toBeVisible();

    // Verify the team filter indicator shows the active filter
    const activeFilterIndicator = page.locator('[data-testid="active-team-filter"]');
    await expect(activeFilterIndicator).toBeVisible();
    await expect(activeFilterIndicator).toContainText('Engineering Team');

    // Locate and click the clear filter button or option
    const clearFilterButton = page.locator('[data-testid="clear-team-filter"]');
    await clearFilterButton.click();

    // Observe the dashboard after clearing the team filter
    await page.waitForTimeout(500);

    // Verify the employee count matches the original total before filtering
    const finalEmployeeCount = await page.locator('[data-testid="employee-record"]').count();
    expect(finalEmployeeCount).toBe(initialEmployeeCount);
  });

  test('Validate filtering by location (happy-path)', async ({ page }) => {
    // Observe the initial dashboard state and note the total number of employees displayed across all locations
    const initialEmployeeCount = await page.locator('[data-testid="employee-record"]').count();
    expect(initialEmployeeCount).toBeGreaterThan(0);

    // Locate the location filter dropdown on the dashboard
    const locationFilterDropdown = page.locator('[data-testid="location-filter-dropdown"]');
    await expect(locationFilterDropdown).toBeVisible();

    // Click on the location filter dropdown
    await locationFilterDropdown.click();

    // Select a specific location from the dropdown list (e.g., 'New York Office')
    await page.locator('[data-testid="location-option-newyork"]').click();

    // Observe the dashboard update after location selection
    await page.waitForTimeout(500);
    const filteredEmployeeCount = await page.locator('[data-testid="employee-record"]').count();

    // Verify that all displayed employee records belong to the selected location
    const employeeRecords = await page.locator('[data-testid="employee-record"]').all();
    for (const record of employeeRecords) {
      const locationName = await record.locator('[data-testid="employee-location"]').textContent();
      expect(locationName).toContain('New York Office');
    }

    // Check the summary metrics (total present, absent, late)
    await expect(page.locator('[data-testid="summary-metrics"]')).toBeVisible();

    // Verify the location filter indicator shows the active filter
    const activeFilterIndicator = page.locator('[data-testid="active-location-filter"]');
    await expect(activeFilterIndicator).toBeVisible();
    await expect(activeFilterIndicator).toContainText('New York Office');

    // Locate and click the clear filter button or option
    const clearFilterButton = page.locator('[data-testid="clear-location-filter"]');
    await clearFilterButton.click();

    // Observe the dashboard after clearing the location filter
    await page.waitForTimeout(500);

    // Verify the employee count matches the original total before filtering
    const finalEmployeeCount = await page.locator('[data-testid="employee-record"]').count();
    expect(finalEmployeeCount).toBe(initialEmployeeCount);
  });

  test('Validate combined filtering by team and location (happy-path)', async ({ page }) => {
    // Observe the initial dashboard state and note the total number of employees displayed
    const initialEmployeeCount = await page.locator('[data-testid="employee-record"]').count();
    expect(initialEmployeeCount).toBeGreaterThan(0);

    // Click on the team filter dropdown
    const teamFilterDropdown = page.locator('[data-testid="team-filter-dropdown"]');
    await teamFilterDropdown.click();

    // Select a specific team from the dropdown (e.g., 'Sales Team')
    await page.locator('[data-testid="team-option-sales"]').click();

    // Note the number of employees displayed after team filter is applied
    await page.waitForTimeout(500);
    const teamFilteredCount = await page.locator('[data-testid="employee-record"]').count();
    expect(teamFilteredCount).toBeGreaterThan(0);
    expect(teamFilteredCount).toBeLessThanOrEqual(initialEmployeeCount);

    // Click on the location filter dropdown while team filter is active
    const locationFilterDropdown = page.locator('[data-testid="location-filter-dropdown"]');
    await locationFilterDropdown.click();

    // Select a specific location from the dropdown (e.g., 'London Office')
    await page.locator('[data-testid="location-option-london"]').click();

    // Observe the dashboard update after applying both filters
    await page.waitForTimeout(500);
    const combinedFilteredCount = await page.locator('[data-testid="employee-record"]').count();

    // Verify each displayed employee record matches both filter criteria
    const employeeRecords = await page.locator('[data-testid="employee-record"]').all();
    for (const record of employeeRecords) {
      const teamName = await record.locator('[data-testid="employee-team"]').textContent();
      const locationName = await record.locator('[data-testid="employee-location"]').textContent();
      expect(teamName).toContain('Sales Team');
      expect(locationName).toContain('London Office');
    }

    // Check the summary metrics with combined filters applied
    await expect(page.locator('[data-testid="summary-metrics"]')).toBeVisible();

    // Verify both filter indicators show active filters
    const activeTeamFilter = page.locator('[data-testid="active-team-filter"]');
    const activeLocationFilter = page.locator('[data-testid="active-location-filter"]');
    await expect(activeTeamFilter).toBeVisible();
    await expect(activeTeamFilter).toContainText('Sales Team');
    await expect(activeLocationFilter).toBeVisible();
    await expect(activeLocationFilter).toContainText('London Office');

    // Locate and click the clear all filters button or clear each filter individually
    const clearAllFiltersButton = page.locator('[data-testid="clear-all-filters"]');
    if (await clearAllFiltersButton.isVisible()) {
      await clearAllFiltersButton.click();
    } else {
      await page.locator('[data-testid="clear-team-filter"]').click();
      await page.locator('[data-testid="clear-location-filter"]').click();
    }

    // Observe the dashboard after clearing all filters
    await page.waitForTimeout(500);

    // Verify the employee count matches the original total before any filtering
    const finalEmployeeCount = await page.locator('[data-testid="employee-record"]').count();
    expect(finalEmployeeCount).toBe(initialEmployeeCount);
  });

  test('Validate filtering by team - Dashboard updates to show attendance data for selected team only', async ({ page }) => {
    // Select a team from the filter dropdown
    await page.locator('[data-testid="team-filter-dropdown"]').click();
    await page.locator('[data-testid="team-option-engineering"]').click();
    
    // Expected Result: Dashboard updates to show attendance data for selected team only
    await page.waitForTimeout(500);
    const employeeRecords = await page.locator('[data-testid="employee-record"]').all();
    expect(employeeRecords.length).toBeGreaterThan(0);
    
    for (const record of employeeRecords) {
      const teamName = await record.locator('[data-testid="employee-team"]').textContent();
      expect(teamName).toContain('Engineering Team');
    }
  });

  test('Validate filtering by team - Clear team filter shows all teams', async ({ page }) => {
    // Apply team filter first
    await page.locator('[data-testid="team-filter-dropdown"]').click();
    await page.locator('[data-testid="team-option-engineering"]').click();
    await page.waitForTimeout(500);
    
    const filteredCount = await page.locator('[data-testid="employee-record"]').count();
    
    // Clear team filter
    await page.locator('[data-testid="clear-team-filter"]').click();
    
    // Expected Result: Dashboard shows attendance data for all teams
    await page.waitForTimeout(500);
    const allTeamsCount = await page.locator('[data-testid="employee-record"]').count();
    expect(allTeamsCount).toBeGreaterThanOrEqual(filteredCount);
  });

  test('Validate filtering by location - Dashboard updates to show attendance data for selected location only', async ({ page }) => {
    // Select a location from the filter dropdown
    await page.locator('[data-testid="location-filter-dropdown"]').click();
    await page.locator('[data-testid="location-option-newyork"]').click();
    
    // Expected Result: Dashboard updates to show attendance data for selected location only
    await page.waitForTimeout(500);
    const employeeRecords = await page.locator('[data-testid="employee-record"]').all();
    expect(employeeRecords.length).toBeGreaterThan(0);
    
    for (const record of employeeRecords) {
      const locationName = await record.locator('[data-testid="employee-location"]').textContent();
      expect(locationName).toContain('New York Office');
    }
  });

  test('Validate filtering by location - Clear location filter shows all locations', async ({ page }) => {
    // Apply location filter first
    await page.locator('[data-testid="location-filter-dropdown"]').click();
    await page.locator('[data-testid="location-option-newyork"]').click();
    await page.waitForTimeout(500);
    
    const filteredCount = await page.locator('[data-testid="employee-record"]').count();
    
    // Clear location filter
    await page.locator('[data-testid="clear-location-filter"]').click();
    
    // Expected Result: Dashboard shows attendance data for all locations
    await page.waitForTimeout(500);
    const allLocationsCount = await page.locator('[data-testid="employee-record"]').count();
    expect(allLocationsCount).toBeGreaterThanOrEqual(filteredCount);
  });

  test('Validate combined filtering by team and location - Dashboard shows data matching both filters', async ({ page }) => {
    // Select a team and a location from filters
    await page.locator('[data-testid="team-filter-dropdown"]').click();
    await page.locator('[data-testid="team-option-sales"]').click();
    await page.waitForTimeout(300);
    
    await page.locator('[data-testid="location-filter-dropdown"]').click();
    await page.locator('[data-testid="location-option-london"]').click();
    
    // Expected Result: Dashboard shows attendance data matching both filters
    await page.waitForTimeout(500);
    const employeeRecords = await page.locator('[data-testid="employee-record"]').all();
    
    for (const record of employeeRecords) {
      const teamName = await record.locator('[data-testid="employee-team"]').textContent();
      const locationName = await record.locator('[data-testid="employee-location"]').textContent();
      expect(teamName).toContain('Sales Team');
      expect(locationName).toContain('London Office');
    }
  });

  test('Validate combined filtering - Clear filters shows all attendance data', async ({ page }) => {
    const initialCount = await page.locator('[data-testid="employee-record"]').count();
    
    // Apply both filters
    await page.locator('[data-testid="team-filter-dropdown"]').click();
    await page.locator('[data-testid="team-option-sales"]').click();
    await page.waitForTimeout(300);
    
    await page.locator('[data-testid="location-filter-dropdown"]').click();
    await page.locator('[data-testid="location-option-london"]').click();
    await page.waitForTimeout(500);
    
    // Clear filters
    const clearAllButton = page.locator('[data-testid="clear-all-filters"]');
    if (await clearAllButton.isVisible()) {
      await clearAllButton.click();
    } else {
      await page.locator('[data-testid="clear-team-filter"]').click();
      await page.locator('[data-testid="clear-location-filter"]').click();
    }
    
    // Expected Result: Dashboard shows all attendance data
    await page.waitForTimeout(500);
    const finalCount = await page.locator('[data-testid="employee-record"]').count();
    expect(finalCount).toBe(initialCount);
  });
});