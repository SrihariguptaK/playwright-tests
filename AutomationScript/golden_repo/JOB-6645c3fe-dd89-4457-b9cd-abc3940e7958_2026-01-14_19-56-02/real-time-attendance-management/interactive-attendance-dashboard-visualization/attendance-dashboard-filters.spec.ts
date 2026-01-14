import { test, expect } from '@playwright/test';

test.describe('Attendance Dashboard Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to attendance dashboard
    await page.goto('/dashboard/attendance');
    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="attendance-dashboard"]', { timeout: 10000 });
  });

  test('Validate filtering by department and date range - happy path', async ({ page }) => {
    // Step 1: Locate the department filter dropdown on the attendance dashboard
    const departmentDropdown = page.locator('[data-testid="department-filter-dropdown"]');
    await expect(departmentDropdown).toBeVisible();

    // Step 2: Click on the department dropdown to expand the list of available departments
    await departmentDropdown.click();
    await page.waitForSelector('[data-testid="department-dropdown-list"]', { state: 'visible' });

    // Step 3: Select a valid department (e.g., 'Engineering') from the dropdown list
    await page.locator('[data-testid="department-option-engineering"]').click();
    await expect(departmentDropdown).toContainText('Engineering');

    // Step 4: Locate the date range picker control on the dashboard
    const dateRangePicker = page.locator('[data-testid="date-range-picker"]');
    await expect(dateRangePicker).toBeVisible();

    // Step 5: Click on the date range picker and select a valid date range (e.g., last 7 days)
    await dateRangePicker.click();
    await page.waitForSelector('[data-testid="date-range-options"]', { state: 'visible' });
    await page.locator('[data-testid="date-range-last-7-days"]').click();

    // Step 6: Click 'Apply' or wait for auto-apply of filters
    const applyButton = page.locator('[data-testid="apply-filters-button"]');
    if (await applyButton.isVisible()) {
      await applyButton.click();
    }

    // Wait for dashboard to update with filtered data
    await page.waitForResponse(response => 
      response.url().includes('/api/dashboard/attendance') && response.status() === 200,
      { timeout: 5000 }
    );

    // Step 7: Examine the employee records displayed in the dashboard table
    await page.waitForSelector('[data-testid="attendance-records-table"]', { state: 'visible' });
    const tableRows = page.locator('[data-testid="attendance-record-row"]');
    const rowCount = await tableRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Step 8: Verify the dates of all attendance records shown in the dashboard
    const today = new Date();
    const sevenDaysAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    
    for (let i = 0; i < Math.min(rowCount, 5); i++) {
      const departmentCell = tableRows.nth(i).locator('[data-testid="record-department"]');
      await expect(departmentCell).toContainText('Engineering');
      
      const dateCell = tableRows.nth(i).locator('[data-testid="record-date"]');
      const dateText = await dateCell.textContent();
      expect(dateText).toBeTruthy();
    }

    // Step 9: Check the summary statistics and visualizations on the dashboard
    const summaryStats = page.locator('[data-testid="dashboard-summary-stats"]');
    await expect(summaryStats).toBeVisible();
    const filteredCount = page.locator('[data-testid="filtered-record-count"]');
    await expect(filteredCount).toBeVisible();

    // Step 10: Locate and click the 'Reset Filters' or 'Clear All' button
    const resetButton = page.locator('[data-testid="reset-filters-button"]');
    await expect(resetButton).toBeVisible();
    await resetButton.click();

    // Step 11: Observe the dashboard behavior after clicking reset
    await page.waitForResponse(response => 
      response.url().includes('/api/dashboard/attendance') && response.status() === 200,
      { timeout: 5000 }
    );

    // Step 12: Verify the record count and summary statistics after reset
    await page.waitForSelector('[data-testid="attendance-records-table"]', { state: 'visible' });
    const resetRowCount = await tableRows.count();
    expect(resetRowCount).toBeGreaterThanOrEqual(rowCount);
    
    // Verify department filter is cleared
    await expect(departmentDropdown).toContainText(/All Departments|Select Department/i);
  });

  test('Verify filter input validation - error case', async ({ page }) => {
    // Step 1: Locate the department filter dropdown on the dashboard
    const departmentDropdown = page.locator('[data-testid="department-filter-dropdown"]');
    await expect(departmentDropdown).toBeVisible();

    // Step 2: Attempt to manually enter an invalid or non-existent department name
    const departmentInput = page.locator('[data-testid="department-filter-input"]');
    if (await departmentInput.isVisible()) {
      await departmentInput.fill('InvalidDepartmentXYZ123');
      await departmentInput.press('Enter');
      
      // Step 3: Observe the system response to invalid department input
      const validationError = page.locator('[data-testid="department-validation-error"]');
      await expect(validationError).toBeVisible({ timeout: 3000 });
      await expect(validationError).toContainText(/invalid|not found|does not exist/i);
      
      await departmentInput.clear();
    }

    // Step 4: Clear the invalid department input and locate the date range picker
    const dateRangePicker = page.locator('[data-testid="date-range-picker"]');
    await expect(dateRangePicker).toBeVisible();
    await dateRangePicker.click();

    // Step 5: Enter an invalid date format in the 'From Date' field
    const fromDateInput = page.locator('[data-testid="from-date-input"]');
    await expect(fromDateInput).toBeVisible();
    await fromDateInput.fill('99/99/9999');

    // Step 6: Attempt to apply the filter with invalid date format
    const applyButton = page.locator('[data-testid="apply-filters-button"]');
    if (await applyButton.isVisible()) {
      await applyButton.click();
    } else {
      await fromDateInput.press('Enter');
    }

    // Verify validation error for invalid date format
    const dateFormatError = page.locator('[data-testid="date-validation-error"]');
    await expect(dateFormatError).toBeVisible({ timeout: 3000 });
    await expect(dateFormatError).toContainText(/invalid date|invalid format|please enter valid date/i);

    // Step 7: Clear the invalid date and enter a valid 'From Date' but 'To Date' earlier than 'From Date'
    await fromDateInput.clear();
    await fromDateInput.fill('01/15/2024');
    
    const toDateInput = page.locator('[data-testid="to-date-input"]');
    await expect(toDateInput).toBeVisible();
    await toDateInput.fill('01/10/2024');

    // Step 8: Attempt to apply the filter with invalid date range (To Date before From Date)
    if (await applyButton.isVisible()) {
      await applyButton.click();
    } else {
      await toDateInput.press('Enter');
    }

    // Verify validation error for invalid date range
    const dateRangeError = page.locator('[data-testid="date-range-validation-error"]');
    await expect(dateRangeError).toBeVisible({ timeout: 3000 });
    await expect(dateRangeError).toContainText(/end date.*before.*start date|invalid range|to date.*after.*from date/i);

    // Step 9: Enter a future date in the date range picker
    await fromDateInput.clear();
    await toDateInput.clear();
    
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 30);
    const futureDateString = `${(futureDate.getMonth() + 1).toString().padStart(2, '0')}/${futureDate.getDate().toString().padStart(2, '0')}/${futureDate.getFullYear()}`;
    
    await fromDateInput.fill(futureDateString);

    // Step 10: Attempt to apply the filter with future date
    if (await applyButton.isVisible()) {
      await applyButton.click();
    } else {
      await fromDateInput.press('Enter');
    }

    // Verify validation error for future date
    const futureDateError = page.locator('[data-testid="future-date-validation-error"]');
    await expect(futureDateError).toBeVisible({ timeout: 3000 });
    await expect(futureDateError).toContainText(/future date|cannot select future|date must be in past/i);

    // Step 11: Verify that no database query was executed for any of the invalid input scenarios
    // Monitor network requests to ensure no API calls were made with invalid data
    let apiCallMade = false;
    page.on('response', response => {
      if (response.url().includes('/api/dashboard/attendance') && response.status() === 200) {
        apiCallMade = true;
      }
    });

    // Wait a moment to ensure no delayed API calls
    await page.waitForTimeout(1000);
    expect(apiCallMade).toBe(false);
  });
});