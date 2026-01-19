import { test, expect } from '@playwright/test';

test.describe('Story-16: Attendance Data Filtering by Department and Location', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the dashboard before each test
    await page.goto('/dashboard/attendance');
    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="attendance-dashboard"]', { timeout: 5000 });
  });

  test('Validate department and location filtering (happy-path)', async ({ page }) => {
    // Step 1: Select one department
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.waitForSelector('[data-testid="department-filter-options"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    // Expected Result: Dashboard updates to show only selected department
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="filtered-department-label"]')).toContainText('Engineering');
    const departmentCount = await page.locator('[data-testid="attendance-row"]').count();
    expect(departmentCount).toBeGreaterThan(0);

    // Step 2: Select additional departments using multi-select
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-sales"]', { modifiers: ['Control'] });
    await page.click('[data-testid="department-option-marketing"]', { modifiers: ['Control'] });
    
    // Expected Result: Dashboard updates to show selected departments
    await page.waitForTimeout(500);
    const selectedDepartments = await page.locator('[data-testid="selected-department-chip"]').count();
    expect(selectedDepartments).toBe(3);

    // Step 3: Select one location
    await page.click('[data-testid="location-filter-dropdown"]');
    await page.waitForSelector('[data-testid="location-filter-options"]');
    await page.click('[data-testid="location-option-new-york"]');
    
    // Expected Result: Dashboard updates to show only selected location
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="filtered-location-label"]')).toContainText('New York');

    // Step 4: Select additional locations using multi-select
    await page.click('[data-testid="location-filter-dropdown"]');
    await page.click('[data-testid="location-option-san-francisco"]', { modifiers: ['Control'] });
    await page.click('[data-testid="location-option-chicago"]', { modifiers: ['Control'] });
    
    // Expected Result: Dashboard updates to show selected locations
    await page.waitForTimeout(500);
    const selectedLocations = await page.locator('[data-testid="selected-location-chip"]').count();
    expect(selectedLocations).toBe(3);

    // Step 5: Reset filters
    await page.click('[data-testid="reset-filters-button"]');
    
    // Expected Result: Dashboard returns to default unfiltered view
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="selected-department-chip"]')).toHaveCount(0);
    await expect(page.locator('[data-testid="selected-location-chip"]')).toHaveCount(0);
    const unfilteredCount = await page.locator('[data-testid="attendance-row"]').count();
    expect(unfilteredCount).toBeGreaterThan(departmentCount);
  });

  test('Verify filter input validation (error-case)', async ({ page }) => {
    // Step 1: Attempt to enter invalid department name directly
    const departmentInput = page.locator('[data-testid="department-filter-input"]');
    if (await departmentInput.isVisible()) {
      await departmentInput.fill('InvalidDepartment123!@#');
      await page.keyboard.press('Enter');
      
      // Expected Result: System prevents selection and shows validation message
      await expect(page.locator('[data-testid="department-validation-error"]')).toBeVisible();
      await expect(page.locator('[data-testid="department-validation-error"]')).toContainText(/invalid|not found|does not exist/i);
    }

    // Step 2: Attempt to manipulate dropdown with invalid value using developer tools
    await page.evaluate(() => {
      const dropdown = document.querySelector('[data-testid="department-filter-dropdown"]');
      if (dropdown) {
        dropdown.setAttribute('data-value', 'INVALID_DEPT_999');
      }
    });
    
    // Try to apply the manipulated filter
    const applyButton = page.locator('[data-testid="apply-filters-button"]');
    if (await applyButton.isVisible()) {
      await applyButton.click();
      // Expected Result: System shows validation message
      await expect(page.locator('[data-testid="filter-validation-error"]')).toBeVisible();
    }

    // Step 3: Attempt to enter invalid location
    const locationInput = page.locator('[data-testid="location-filter-input"]');
    if (await locationInput.isVisible()) {
      await locationInput.fill('InvalidLocation999');
      await page.keyboard.press('Enter');
      
      // Expected Result: System prevents selection and shows validation message
      await expect(page.locator('[data-testid="location-validation-error"]')).toBeVisible();
      await expect(page.locator('[data-testid="location-validation-error"]')).toContainText(/invalid|not found|does not exist/i);
    }

    // Step 4: Try to select disabled option
    await page.click('[data-testid="department-filter-dropdown"]');
    const disabledOption = page.locator('[data-testid="department-option-disabled"]');
    if (await disabledOption.isVisible()) {
      const isDisabled = await disabledOption.getAttribute('disabled');
      expect(isDisabled).toBeTruthy();
      
      // Attempt to click disabled option
      await disabledOption.click({ force: true });
      
      // Expected Result: Option should not be selected
      await expect(page.locator('[data-testid="selected-department-chip"]')).toHaveCount(0);
    }
  });

  test('Test filter response time (happy-path)', async ({ page }) => {
    // Step 1: Verify current data set size
    await page.waitForSelector('[data-testid="total-employee-count"]');
    const totalEmployeeCount = await page.locator('[data-testid="total-employee-count"]').textContent();
    expect(parseInt(totalEmployeeCount || '0')).toBeGreaterThan(0);

    // Step 2: Start timer and select multiple departments
    const departmentStartTime = Date.now();
    
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.waitForSelector('[data-testid="department-filter-options"]');
    
    // Select 5 departments using multi-select
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="department-option-sales"]', { modifiers: ['Control'] });
    await page.click('[data-testid="department-option-marketing"]', { modifiers: ['Control'] });
    await page.click('[data-testid="department-option-hr"]', { modifiers: ['Control'] });
    await page.click('[data-testid="department-option-finance"]', { modifiers: ['Control'] });
    
    // Wait for dashboard to update
    await page.waitForSelector('[data-testid="attendance-data-loaded"]', { timeout: 3000 });
    
    const departmentEndTime = Date.now();
    const departmentResponseTime = departmentEndTime - departmentStartTime;
    
    // Expected Result: Filtered data loads within 2 seconds
    expect(departmentResponseTime).toBeLessThan(2000);
    console.log(`Department filter response time: ${departmentResponseTime}ms`);

    // Step 3: Start timer and select multiple locations
    const locationStartTime = Date.now();
    
    await page.click('[data-testid="location-filter-dropdown"]');
    await page.waitForSelector('[data-testid="location-filter-options"]');
    
    // Select 5 locations using multi-select
    await page.click('[data-testid="location-option-new-york"]');
    await page.click('[data-testid="location-option-san-francisco"]', { modifiers: ['Control'] });
    await page.click('[data-testid="location-option-chicago"]', { modifiers: ['Control'] });
    await page.click('[data-testid="location-option-boston"]', { modifiers: ['Control'] });
    await page.click('[data-testid="location-option-seattle"]', { modifiers: ['Control'] });
    
    // Wait for dashboard to update
    await page.waitForSelector('[data-testid="attendance-data-loaded"]', { timeout: 3000 });
    
    const locationEndTime = Date.now();
    const locationResponseTime = locationEndTime - locationStartTime;
    
    // Expected Result: Filtered data loads within 2 seconds
    expect(locationResponseTime).toBeLessThan(2000);
    console.log(`Location filter response time: ${locationResponseTime}ms`);

    // Step 4: Start timer and reset filters
    const resetStartTime = Date.now();
    
    await page.click('[data-testid="reset-filters-button"]');
    
    // Wait for dashboard to return to unfiltered state
    await page.waitForSelector('[data-testid="attendance-data-loaded"]', { timeout: 3000 });
    
    const resetEndTime = Date.now();
    const resetResponseTime = resetEndTime - resetStartTime;
    
    // Expected Result: Reset completes within 2 seconds
    expect(resetResponseTime).toBeLessThan(2000);
    console.log(`Reset filter response time: ${resetResponseTime}ms`);
    
    // Verify filters are cleared
    await expect(page.locator('[data-testid="selected-department-chip"]')).toHaveCount(0);
    await expect(page.locator('[data-testid="selected-location-chip"]')).toHaveCount(0);
  });
});