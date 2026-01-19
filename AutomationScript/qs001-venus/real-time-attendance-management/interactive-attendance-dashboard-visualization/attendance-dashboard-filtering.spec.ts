import { test, expect } from '@playwright/test';

test.describe('Attendance Dashboard Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to attendance dashboard
    await page.goto('/attendance/dashboard');
    // Wait for dashboard to load
    await page.waitForLoadState('networkidle');
  });

  test('Validate dashboard filtering by department and date (happy-path)', async ({ page }) => {
    // Step 1: Locate the department filter dropdown on the dashboard
    const departmentFilter = page.locator('[data-testid="department-filter-dropdown"]');
    await expect(departmentFilter).toBeVisible();

    // Step 2: Click on the department filter dropdown and select a specific department (e.g., 'Engineering')
    await departmentFilter.click();
    await page.locator('[data-testid="department-option-engineering"]').click();

    // Step 3: Locate the date range filter and click on the date picker control
    const dateRangeFilter = page.locator('[data-testid="date-range-filter"]');
    await expect(dateRangeFilter).toBeVisible();
    await dateRangeFilter.click();

    // Step 4: Select a start date and end date for the desired range (e.g., last 30 days)
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    const endDate = new Date();
    
    await page.locator('[data-testid="start-date-input"]').fill(startDate.toISOString().split('T')[0]);
    await page.locator('[data-testid="end-date-input"]').fill(endDate.toISOString().split('T')[0]);

    // Step 5: Click Apply or wait for auto-refresh after filter selection
    const applyButton = page.locator('[data-testid="apply-filter-button"]');
    if (await applyButton.isVisible()) {
      await applyButton.click();
    }

    // Wait for dashboard to update (max 3 seconds as per requirements)
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance') && response.status() === 200,
      { timeout: 3000 }
    );

    // Step 6: Verify that the displayed attendance metrics reflect only the selected department and date range
    const dashboardData = page.locator('[data-testid="attendance-data-container"]');
    await expect(dashboardData).toBeVisible();
    
    const departmentLabel = page.locator('[data-testid="filtered-department-label"]');
    await expect(departmentLabel).toContainText('Engineering');
    
    const dateRangeLabel = page.locator('[data-testid="filtered-date-range-label"]');
    await expect(dateRangeLabel).toBeVisible();

    // Step 7: Locate and click the 'Save Filter Preset' or 'Save Filter' button
    const savePresetButton = page.locator('[data-testid="save-filter-preset-button"]');
    await expect(savePresetButton).toBeVisible();
    await savePresetButton.click();

    // Step 8: Enter a descriptive name for the filter preset (e.g., 'Engineering Last 30 Days') and click Save
    const presetNameInput = page.locator('[data-testid="preset-name-input"]');
    await expect(presetNameInput).toBeVisible();
    await presetNameInput.fill('Engineering Last 30 Days');
    
    const saveButton = page.locator('[data-testid="save-preset-confirm-button"]');
    await saveButton.click();

    // Verify preset saved successfully
    const successMessage = page.locator('[data-testid="preset-saved-message"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText('Preset saved');

    // Step 9: Apply different filters or navigate away from the current view, then select the saved preset from the presets dropdown
    await page.locator('[data-testid="department-filter-dropdown"]').click();
    await page.locator('[data-testid="department-option-sales"]').click();
    
    // Select saved preset
    const presetsDropdown = page.locator('[data-testid="filter-presets-dropdown"]');
    await presetsDropdown.click();
    await page.locator('[data-testid="preset-engineering-last-30-days"]').click();

    // Verify preset applied correctly
    await expect(departmentLabel).toContainText('Engineering');

    // Step 10: Locate and click the 'Clear Filters' or 'Reset' button
    const clearFiltersButton = page.locator('[data-testid="clear-filters-button"]');
    await expect(clearFiltersButton).toBeVisible();
    await clearFiltersButton.click();

    // Step 11: Verify that the dashboard displays unfiltered data after clearing filters
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance') && response.status() === 200
    );
    
    const defaultView = page.locator('[data-testid="attendance-data-container"]');
    await expect(defaultView).toBeVisible();
    
    // Verify filters are cleared
    const departmentFilterValue = await page.locator('[data-testid="department-filter-dropdown"]').textContent();
    expect(departmentFilterValue).toContain('All Departments');
  });

  test('Verify access control on filtered data (error-case)', async ({ page }) => {
    // Step 1: Click on the department filter dropdown to view available departments
    const departmentFilter = page.locator('[data-testid="department-filter-dropdown"]');
    await expect(departmentFilter).toBeVisible();
    await departmentFilter.click();

    // Step 2: Verify that unauthorized departments are not present in the filter options
    const departmentOptions = page.locator('[data-testid^="department-option-"]');
    const optionsCount = await departmentOptions.count();
    
    // Check that unauthorized department (e.g., Finance) is not in the list
    const financeOption = page.locator('[data-testid="department-option-finance"]');
    await expect(financeOption).not.toBeVisible();
    
    // Verify only authorized departments are visible
    const engineeringOption = page.locator('[data-testid="department-option-engineering"]');
    await expect(engineeringOption).toBeVisible();

    // Close dropdown
    await page.keyboard.press('Escape');

    // Step 3: Attempt to manually construct a URL or API request to access attendance data for an unauthorized department
    const unauthorizedResponse = await page.request.get('/api/attendance?department=finance', {
      failOnStatusCode: false
    });

    // Step 4: Observe the system response to the unauthorized access attempt
    expect(unauthorizedResponse.status()).toBe(403);
    
    const responseBody = await unauthorizedResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toContain('access');

    // Step 5: Verify that no attendance data for the unauthorized department is displayed on the dashboard
    // Attempt to navigate directly with unauthorized department parameter
    await page.goto('/attendance/dashboard?department=finance');
    
    const errorMessage = page.locator('[data-testid="access-denied-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText('access');
    
    // Verify no attendance data is displayed
    const attendanceData = page.locator('[data-testid="attendance-data-container"]');
    const dataRows = attendanceData.locator('[data-testid^="attendance-row-"]');
    await expect(dataRows).toHaveCount(0);

    // Step 6: Check application logs or security audit logs for the unauthorized access attempt
    // Note: In real implementation, this would involve checking server logs or audit trail
    // For UI automation, we verify the error is properly displayed
    const errorAlert = page.locator('[role="alert"]');
    await expect(errorAlert).toBeVisible();
    await expect(errorAlert).toContainText('You do not have permission');

    // Step 7: Return to normal dashboard operation by selecting an authorized department from the filter
    await page.goto('/attendance/dashboard');
    await page.waitForLoadState('networkidle');
    
    const departmentFilterReset = page.locator('[data-testid="department-filter-dropdown"]');
    await departmentFilterReset.click();
    await page.locator('[data-testid="department-option-engineering"]').click();
    
    // Wait for dashboard to update with authorized data
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance') && response.status() === 200,
      { timeout: 3000 }
    );
    
    // Verify authorized data is displayed
    const authorizedData = page.locator('[data-testid="attendance-data-container"]');
    await expect(authorizedData).toBeVisible();
    
    const departmentLabel = page.locator('[data-testid="filtered-department-label"]');
    await expect(departmentLabel).toContainText('Engineering');
  });
});