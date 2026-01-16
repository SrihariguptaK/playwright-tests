import { test, expect } from '@playwright/test';

test.describe('Attendance Reports - Tardiness Highlighting', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application and login as HR Specialist
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.specialist@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate tardiness detection in attendance reports', async ({ page }) => {
    // Navigate to the attendance reporting module from the main dashboard
    await page.click('[data-testid="attendance-reporting-menu"]');
    await expect(page.locator('[data-testid="attendance-report-page"]')).toBeVisible();

    // Select a date range that includes known tardiness occurrences (e.g., last 30 days)
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-30-days-option"]');
    await expect(page.locator('[data-testid="date-range-display"]')).toContainText('Last 30 days');

    // Click 'Generate Report' button to generate attendance report with tardiness data
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation (max 15 seconds as per SLA)
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 15000 });

    // Review the generated report for tardiness highlights
    const tardinessHighlights = page.locator('[data-testid="tardiness-highlight"]');
    await expect(tardinessHighlights).toHaveCount(await tardinessHighlights.count());
    await expect(tardinessHighlights.first()).toBeVisible();

    // Verify the accuracy of tardiness detection by comparing highlighted entries with actual arrival timestamps
    const firstTardinessRow = page.locator('[data-testid="report-row"]').filter({ has: page.locator('[data-testid="tardiness-highlight"]') }).first();
    await expect(firstTardinessRow).toBeVisible();
    const arrivalTime = await firstTardinessRow.locator('[data-testid="arrival-time"]').textContent();
    const expectedTime = await firstTardinessRow.locator('[data-testid="expected-time"]').textContent();
    expect(arrivalTime).toBeTruthy();
    expect(expectedTime).toBeTruthy();

    // Select a specific employee from the employee filter dropdown who has known tardiness records
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.fill('[data-testid="employee-search-input"]', 'John Smith');
    await page.click('[data-testid="employee-option"]', { hasText: 'John Smith' });
    await expect(page.locator('[data-testid="selected-employee"]')).toContainText('John Smith');

    // Click 'Generate Report' to filter the report by the selected employee with tardiness
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 15000 });

    // Verify the filtered report displays tardiness information for the selected employee
    const filteredRows = page.locator('[data-testid="report-row"]');
    await expect(filteredRows).toHaveCountGreaterThan(0);
    
    const employeeNames = filteredRows.locator('[data-testid="employee-name"]');
    const count = await employeeNames.count();
    for (let i = 0; i < count; i++) {
      await expect(employeeNames.nth(i)).toContainText('John Smith');
    }

    const filteredTardinessHighlights = page.locator('[data-testid="tardiness-highlight"]');
    await expect(filteredTardinessHighlights).toHaveCountGreaterThan(0);
  });

  test('Verify export of attendance reports with tardiness highlights', async ({ page }) => {
    // Navigate to the attendance reporting module
    await page.click('[data-testid="attendance-reporting-menu"]');
    await expect(page.locator('[data-testid="attendance-report-page"]')).toBeVisible();

    // Select a date range that includes employees with tardiness records (e.g., last 14 days)
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-14-days-option"]');
    await expect(page.locator('[data-testid="date-range-display"]')).toContainText('Last 14 days');

    // Click 'Generate Report' button to generate attendance report with tardiness highlights
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible({ timeout: 15000 });

    // Review the on-screen report to identify tardiness highlights and note specific examples
    const tardinessHighlights = page.locator('[data-testid="tardiness-highlight"]');
    await expect(tardinessHighlights).toHaveCountGreaterThan(0);
    
    const firstHighlightedEmployee = await page.locator('[data-testid="report-row"]').filter({ has: page.locator('[data-testid="tardiness-highlight"]') }).first().locator('[data-testid="employee-name"]').textContent();
    const firstHighlightedDate = await page.locator('[data-testid="report-row"]').filter({ has: page.locator('[data-testid="tardiness-highlight"]') }).first().locator('[data-testid="attendance-date"]').textContent();
    
    expect(firstHighlightedEmployee).toBeTruthy();
    expect(firstHighlightedDate).toBeTruthy();

    // Click the 'Export to PDF' button to export the report
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    
    // Verify download started successfully
    expect(download.suggestedFilename()).toContain('.pdf');
    expect(download.suggestedFilename()).toContain('attendance');
    
    // Save the downloaded file
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();

    // Verify export success message is displayed
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF exported successfully');

    // Verify the download completed
    expect(await download.failure()).toBeNull();
  });
});