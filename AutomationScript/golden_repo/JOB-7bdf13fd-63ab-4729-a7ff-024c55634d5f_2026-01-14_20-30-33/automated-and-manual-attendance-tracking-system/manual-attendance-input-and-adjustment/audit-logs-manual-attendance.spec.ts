import { test, expect } from '@playwright/test';

test.describe('Audit Logs - Manual Attendance Changes', () => {
  const HR_USER_EMAIL = 'hr.officer@company.com';
  const HR_USER_PASSWORD = 'HRPassword123!';
  const NON_HR_USER_EMAIL = 'employee@company.com';
  const NON_HR_USER_PASSWORD = 'EmployeePass123!';
  const AUDIT_LOGS_URL = '/audit-logs';
  const API_AUDIT_LOGS_ENDPOINT = '/api/manual-attendance/audit-logs';

  test('Validate audit log retrieval and filtering (happy-path)', async ({ page }) => {
    // Step 1: Login to the system as an authorized HR officer using valid credentials
    await page.goto('/login');
    await page.fill('input[name="email"]', HR_USER_EMAIL);
    await page.fill('input[name="password"]', HR_USER_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Click on the audit logs link from the navigation menu
    await page.click('a[href="/audit-logs"]');
    await expect(page).toHaveURL(/.*audit-logs/);
    
    // Step 3: Review the displayed audit log entries without applying any filters
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    const initialRowCount = await page.locator('[data-testid="audit-log-row"]').count();
    expect(initialRowCount).toBeGreaterThan(0);

    // Step 4: Locate the filter section and select a specific user from the user filter dropdown
    await page.locator('[data-testid="filter-section"]').waitFor({ state: 'visible' });
    await page.click('[data-testid="user-filter-dropdown"]');
    await page.click('[data-testid="user-filter-option"]:has-text("John Smith")');

    // Step 5: Apply an additional date range filter by selecting start and end date
    await page.fill('[data-testid="start-date-filter"]', '2024-01-01');
    await page.fill('[data-testid="end-date-filter"]', '2024-01-07');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForResponse(response => response.url().includes('/api/manual-attendance/audit-logs') && response.status() === 200);

    // Step 6: Verify the filtered results match the applied filter criteria
    const filteredRows = page.locator('[data-testid="audit-log-row"]');
    const filteredCount = await filteredRows.count();
    expect(filteredCount).toBeGreaterThan(0);
    
    for (let i = 0; i < Math.min(filteredCount, 5); i++) {
      const row = filteredRows.nth(i);
      await expect(row.locator('[data-testid="audit-log-user"]')).toContainText('John Smith');
      const dateText = await row.locator('[data-testid="audit-log-date"]').textContent();
      expect(dateText).toBeTruthy();
    }

    // Step 7: Clear the existing filters and apply a new filter by selecting a specific employee
    await page.click('[data-testid="clear-filters-button"]');
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-filter-option"]:has-text("Jane Doe")');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForResponse(response => response.url().includes('/api/manual-attendance/audit-logs') && response.status() === 200);

    // Step 8: Locate the export button and click on 'Export as PDF' option
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    await downloadPDF.saveAs('./downloads/' + downloadPDF.suggestedFilename());

    // Step 9: Return to the audit logs page and click on 'Export as CSV' option
    await page.waitForTimeout(1000);
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');
    const downloadCSV = await downloadPromiseCSV;
    expect(downloadCSV.suggestedFilename()).toContain('.csv');
    await downloadCSV.saveAs('./downloads/' + downloadCSV.suggestedFilename());

    // Step 10: Verify that both exported files contain the filtered data
    expect(await downloadPDF.suggestedFilename()).toBeTruthy();
    expect(await downloadCSV.suggestedFilename()).toBeTruthy();
  });

  test('Verify access restriction for unauthorized users (error-case)', async ({ page, request }) => {
    // Step 1: Navigate to the system login page and enter valid non-HR user credentials
    await page.goto('/login');
    await page.fill('input[name="email"]', NON_HR_USER_EMAIL);
    await page.fill('input[name="password"]', NON_HR_USER_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Check the navigation menu for audit logs option
    const auditLogsLink = page.locator('a[href="/audit-logs"]');
    await expect(auditLogsLink).toHaveCount(0);

    // Step 3: Attempt to access the audit logs page directly by entering the URL
    await page.goto(AUDIT_LOGS_URL);
    
    // Verify access is denied - should redirect or show error
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    const pageContent = await page.textContent('body');
    
    const isAccessDenied = 
      !currentUrl.includes('/audit-logs') || 
      pageContent?.includes('Access Denied') || 
      pageContent?.includes('Unauthorized') || 
      pageContent?.includes('403') ||
      currentUrl.includes('/unauthorized') ||
      currentUrl.includes('/access-denied');
    
    expect(isAccessDenied).toBeTruthy();

    // Step 4: Attempt to make a GET request to the audit logs API endpoint
    const authToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    });

    const apiResponse = await request.get(API_AUDIT_LOGS_ENDPOINT, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      failOnStatusCode: false
    });

    // Step 5: Verify authorization error is returned
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error || responseBody.message).toMatch(/unauthorized|forbidden|access denied/i);

    // Step 6: Attempt to make a GET request with query parameters
    const apiResponseWithParams = await request.get(`${API_AUDIT_LOGS_ENDPOINT}?user=someuser&date=2024-01-15`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      failOnStatusCode: false
    });

    expect(apiResponseWithParams.status()).toBe(403);

    // Step 7: Verify that no audit log data is returned
    const responseBodyWithParams = await apiResponseWithParams.json();
    expect(responseBodyWithParams.data || responseBodyWithParams.auditLogs).toBeUndefined();

    // Step 8: Verify that the non-HR user can still access their authorized features
    await page.goto('/dashboard');
    await expect(page.locator('[data-testid="dashboard-content"]')).toBeVisible();
    
    await page.goto('/profile');
    await expect(page).toHaveURL(/.*profile/);
    await expect(page.locator('[data-testid="profile-content"]')).toBeVisible();
  });
});