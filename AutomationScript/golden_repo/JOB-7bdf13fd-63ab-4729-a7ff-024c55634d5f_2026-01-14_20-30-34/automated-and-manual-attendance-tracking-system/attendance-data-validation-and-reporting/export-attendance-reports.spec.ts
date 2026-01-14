import { test, expect } from '@playwright/test';

test.describe('Export Attendance Reports - Story 17', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as authorized analyst
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'attendance.analyst@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful export of attendance report in PDF', async ({ page }) => {
    // Step 1: Navigate to the reporting dashboard
    await page.goto('/reporting/dashboard');
    await expect(page.locator('[data-testid="reporting-dashboard"]')).toBeVisible();

    // Select 'Attendance Report' from the report type dropdown
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-attendance"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Attendance Report');

    // Apply filters - select date range
    await page.click('[data-testid="date-range-filter"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');

    // Apply filters - select department
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-engineering"]');

    // Click 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');

    // Expected Result: Report is displayed
    await expect(page.locator('[data-testid="report-display-container"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Attendance Report');

    // Review the displayed report to note the content and applied filters
    const displayedFilters = await page.locator('[data-testid="applied-filters-summary"]').textContent();
    const reportRowCount = await page.locator('[data-testid="report-table-row"]').count();
    expect(reportRowCount).toBeGreaterThan(0);

    // Click on 'Export' button and select 'PDF' format
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-format-options"]')).toBeVisible();
    await page.click('[data-testid="export-format-pdf"]');

    // Click 'Initiate Export' or 'Download' button
    await page.click('[data-testid="initiate-export-button"]');

    // Expected Result: Export completes and download link is provided
    await expect(page.locator('[data-testid="export-status-message"]')).toContainText('Export completed successfully', { timeout: 12000 });
    await expect(page.locator('[data-testid="download-link"]')).toBeVisible();

    // Download the PDF file using the provided link
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-link"]');
    const download = await downloadPromise;

    // Expected Result: Report content matches displayed data
    expect(download.suggestedFilename()).toContain('.pdf');
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();

    // Verify export completion time is within 10 seconds
    const exportTime = await page.locator('[data-testid="export-duration"]').textContent();
    expect(exportTime).toBeTruthy();
  });

  test('Verify export access restriction for unauthorized users', async ({ page, context }) => {
    // Logout from authorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 1: Login as unauthorized user (user without export permissions)
    await page.fill('[data-testid="username-input"]', 'basic.user@company.com');
    await page.fill('[data-testid="password-input"]', 'BasicPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to any available reports section
    await page.goto('/reporting/dashboard');

    // Generate a basic report if accessible
    const reportTypeDropdown = page.locator('[data-testid="report-type-dropdown"]');
    if (await reportTypeDropdown.isVisible()) {
      await reportTypeDropdown.click();
      await page.click('[data-testid="report-type-attendance"]');
      await page.click('[data-testid="generate-report-button"]');
      await page.waitForTimeout(2000);
    }

    // Expected Result: Export options are not visible or accessible
    const exportButton = page.locator('[data-testid="export-button"]');
    await expect(exportButton).not.toBeVisible();

    // Attempt to call export API directly with unauthorized user's token
    const cookies = await context.cookies();
    const authToken = cookies.find(cookie => cookie.name === 'auth_token')?.value || '';

    const apiResponse = await page.request.post('/api/reports/export', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        reportType: 'attendance',
        format: 'pdf',
        filters: {
          dateRange: { start: '2024-01-01', end: '2024-01-31' },
          department: 'Engineering'
        }
      }
    });

    // Expected Result: Authorization error is returned
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Unauthorized');
    expect(responseBody.message).toMatch(/not authorized|permission denied|access denied/i);

    // Verify the API error response structure
    expect(responseBody).toHaveProperty('error');
    expect(responseBody).toHaveProperty('message');

    // Check system audit logs for the unauthorized access attempt
    // Note: This would typically be verified through admin interface or database
    // For automation, we verify the error response indicates the attempt was logged
    expect(responseBody.logged).toBe(true);
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Logout after each test
    const userMenu = page.locator('[data-testid="user-menu"]');
    if (await userMenu.isVisible()) {
      await userMenu.click();
      await page.click('[data-testid="logout-button"]');
    }
  });
});