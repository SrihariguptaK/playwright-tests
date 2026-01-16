import { test, expect } from '@playwright/test';

test.describe('Attendance Dashboard Filtering - Story 15', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to attendance dashboard
    await page.goto('/attendance-dashboard');
    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="attendance-dashboard"]', { timeout: 10000 });
  });

  test('Validate filtering by department and team - single selection', async ({ page }) => {
    // Step 1: Manager selects one department and team in filter panel
    await page.click('[data-testid="filter-panel-toggle"]');
    await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();
    
    // Select department
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    // Select team
    await page.click('[data-testid="team-dropdown"]');
    await page.click('[data-testid="team-option-backend-team"]');
    
    // Apply filters
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for dashboard to update
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance-dashboard') && response.status() === 200
    );
    
    // Expected Result: Dashboard updates to show attendance data for selected filters
    await expect(page.locator('[data-testid="active-filter-department"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="active-filter-team"]')).toContainText('Backend Team');
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    
    // Verify filtered data is displayed
    const departmentCells = page.locator('[data-testid="table-cell-department"]');
    const count = await departmentCells.count();
    for (let i = 0; i < count; i++) {
      await expect(departmentCells.nth(i)).toContainText('Engineering');
    }
  });

  test('Validate filtering by department and team - clear filters', async ({ page }) => {
    // Apply initial filters
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);
    
    // Step 2: Manager clears filters
    await page.click('[data-testid="clear-filters-button"]');
    
    // Wait for dashboard to refresh
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance-dashboard') && response.status() === 200
    );
    
    // Expected Result: Dashboard displays unfiltered attendance data
    await expect(page.locator('[data-testid="active-filter-department"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="active-filter-team"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
  });

  test('Validate filtering by department and team - multiple filters simultaneously', async ({ page }) => {
    // Step 3: Manager applies multiple filters simultaneously
    await page.click('[data-testid="filter-panel-toggle"]');
    
    // Select multiple departments
    await page.click('[data-testid="department-dropdown"]');
    await page.check('[data-testid="department-checkbox-engineering"]');
    await page.check('[data-testid="department-checkbox-sales"]');
    await page.click('[data-testid="department-dropdown"]'); // Close dropdown
    
    // Select multiple teams
    await page.click('[data-testid="team-dropdown"]');
    await page.check('[data-testid="team-checkbox-backend-team"]');
    await page.check('[data-testid="team-checkbox-frontend-team"]');
    await page.check('[data-testid="team-checkbox-sales-team-a"]');
    await page.click('[data-testid="team-dropdown"]'); // Close dropdown
    
    // Apply filters
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for dashboard to update
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance-dashboard') && response.status() === 200
    );
    
    // Expected Result: Dashboard shows data matching all filter criteria
    await expect(page.locator('[data-testid="active-filters-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-tag"]')).toHaveCount(5); // 2 departments + 3 teams
    
    // Verify data matches filter criteria
    const departmentCells = page.locator('[data-testid="table-cell-department"]');
    const count = await departmentCells.count();
    for (let i = 0; i < count; i++) {
      const text = await departmentCells.nth(i).textContent();
      expect(['Engineering', 'Sales']).toContain(text?.trim());
    }
  });

  test('Verify date range filtering functionality - valid date range', async ({ page }) => {
    // Step 1: Manager selects custom date range in filter panel
    await page.click('[data-testid="filter-panel-toggle"]');
    
    // Calculate dates
    const today = new Date();
    const sevenDaysAgo = new Date(today);
    sevenDaysAgo.setDate(today.getDate() - 7);
    
    const startDateStr = sevenDaysAgo.toISOString().split('T')[0];
    const endDateStr = today.toISOString().split('T')[0];
    
    // Select start date
    await page.click('[data-testid="start-date-field"]');
    await page.fill('[data-testid="start-date-input"]', startDateStr);
    
    // Select end date
    await page.click('[data-testid="end-date-field"]');
    await page.fill('[data-testid="end-date-input"]', endDateStr);
    
    // Apply filters
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for dashboard to update
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance-dashboard') && response.status() === 200
    );
    
    // Expected Result: Dashboard displays attendance data within selected date range
    await expect(page.locator('[data-testid="date-range-display"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    
    // Verify dates in table are within range
    const dateCells = page.locator('[data-testid="table-cell-date"]');
    const dateCount = await dateCells.count();
    if (dateCount > 0) {
      const firstDate = await dateCells.first().textContent();
      expect(firstDate).toBeTruthy();
    }
  });

  test('Verify date range filtering functionality - invalid date range', async ({ page }) => {
    // Step 2: Manager selects invalid date range (end date before start date)
    await page.click('[data-testid="filter-panel-toggle"]');
    
    const today = new Date();
    const threeDaysAgo = new Date(today);
    threeDaysAgo.setDate(today.getDate() - 3);
    
    const startDateStr = today.toISOString().split('T')[0];
    const endDateStr = threeDaysAgo.toISOString().split('T')[0];
    
    // Select start date (today)
    await page.click('[data-testid="start-date-field"]');
    await page.fill('[data-testid="start-date-input"]', startDateStr);
    
    // Select end date (3 days ago - invalid)
    await page.click('[data-testid="end-date-field"]');
    await page.fill('[data-testid="end-date-input"]', endDateStr);
    
    // Attempt to apply filters
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: System displays validation error and prevents filter application
    await expect(page.locator('[data-testid="date-range-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-error"]')).toContainText(/end date.*before.*start date|invalid date range/i);
    
    // Verify filters were not applied
    await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();
  });

  test('Verify date range filtering functionality - corrected date range', async ({ page }) => {
    // Step 3: Manager adjusts date range to valid values
    await page.click('[data-testid="filter-panel-toggle"]');
    
    const today = new Date();
    const fiveDaysAgo = new Date(today);
    fiveDaysAgo.setDate(today.getDate() - 5);
    
    const startDateStr = fiveDaysAgo.toISOString().split('T')[0];
    const endDateStr = today.toISOString().split('T')[0];
    
    // Select valid start date
    await page.click('[data-testid="start-date-field"]');
    await page.fill('[data-testid="start-date-input"]', startDateStr);
    
    // Select valid end date
    await page.click('[data-testid="end-date-field"]');
    await page.fill('[data-testid="end-date-input"]', endDateStr);
    
    // Apply filters
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for dashboard to update
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance-dashboard') && response.status() === 200
    );
    
    // Expected Result: Dashboard updates data accordingly
    await expect(page.locator('[data-testid="date-range-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="date-range-display"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
  });

  test('Test filter preset save and load - save preset', async ({ page }) => {
    // Step 1: Manager applies filters and saves preset with name
    await page.click('[data-testid="filter-panel-toggle"]');
    
    // Apply specific filters
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    await page.click('[data-testid="team-dropdown"]');
    await page.click('[data-testid="team-option-backend-team"]');
    
    // Select date range preset
    await page.click('[data-testid="date-range-preset-dropdown"]');
    await page.click('[data-testid="date-range-preset-last-7-days"]');
    
    // Apply filters to confirm they work
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);
    
    // Save preset
    await page.click('[data-testid="save-preset-button"]');
    await expect(page.locator('[data-testid="save-preset-dialog"]')).toBeVisible();
    
    // Enter preset name
    await page.fill('[data-testid="preset-name-input"]', 'Engineering Backend Weekly');
    
    // Confirm save
    await page.click('[data-testid="confirm-save-preset-button"]');
    
    // Expected Result: Preset saved successfully
    await expect(page.locator('[data-testid="preset-saved-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="preset-saved-notification"]')).toContainText(/saved successfully/i);
  });

  test('Test filter preset save and load - load preset', async ({ page }) => {
    // Prerequisite: Ensure preset exists (save it first)
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="team-dropdown"]');
    await page.click('[data-testid="team-option-backend-team"]');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(500);
    await page.click('[data-testid="save-preset-button"]');
    await page.fill('[data-testid="preset-name-input"]', 'Engineering Backend Weekly');
    await page.click('[data-testid="confirm-save-preset-button"]');
    await page.waitForTimeout(1000);
    
    // Step 2: Clear all current filters to reset the dashboard
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(1000);
    
    // Open saved presets dropdown
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.click('[data-testid="saved-presets-dropdown"]');
    await expect(page.locator('[data-testid="presets-list"]')).toBeVisible();
    
    // Select the preset
    await page.click('[data-testid="preset-item-engineering-backend-weekly"]');
    
    // Wait for filters to be applied
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance-dashboard') && response.status() === 200
    );
    
    // Expected Result: Filters applied and dashboard updated accordingly
    await expect(page.locator('[data-testid="active-filter-department"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="active-filter-team"]')).toContainText('Backend Team');
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
  });

  test('Test filter preset save and load - delete preset', async ({ page }) => {
    // Prerequisite: Ensure preset exists
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(500);
    await page.click('[data-testid="save-preset-button"]');
    await page.fill('[data-testid="preset-name-input"]', 'Engineering Backend Weekly');
    await page.click('[data-testid="confirm-save-preset-button"]');
    await page.waitForTimeout(1000);
    
    // Step 3: Open the saved presets list
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.click('[data-testid="saved-presets-dropdown"]');
    await expect(page.locator('[data-testid="presets-list"]')).toBeVisible();
    
    // Locate the preset and click delete
    const presetItem = page.locator('[data-testid="preset-item-engineering-backend-weekly"]');
    await expect(presetItem).toBeVisible();
    
    await page.click('[data-testid="delete-preset-engineering-backend-weekly"]');
    
    // Confirm deletion if prompted
    const confirmDialog = page.locator('[data-testid="confirm-delete-dialog"]');
    if (await confirmDialog.isVisible()) {
      await page.click('[data-testid="confirm-delete-button"]');
    }
    
    // Expected Result: Preset removed from saved list
    await expect(page.locator('[data-testid="preset-deleted-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="preset-item-engineering-backend-weekly"]')).not.toBeVisible();
  });
});