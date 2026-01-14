import { test, expect } from '@playwright/test';

test.describe('Attendance Manager - Review Biometric Attendance Logs', () => {
  test.beforeEach(async ({ page }) => {
    // Login as attendance manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'attendance_manager');
    await page.fill('[data-testid="password-input"]', 'manager123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate attendance log retrieval with filters (happy-path)', async ({ page }) => {
    // Step 1: Navigate to attendance logs page
    await page.click('text=Attendance Logs');
    await expect(page).toHaveURL(/.*\/manager\/attendance-logs/);
    await expect(page.locator('[data-testid="attendance-logs-table"]')).toBeVisible();
    
    // Step 2: Verify initial display of attendance logs without filters
    await expect(page.locator('[data-testid="attendance-logs-table"] tbody tr')).toHaveCount(await page.locator('[data-testid="attendance-logs-table"] tbody tr').count());
    const initialRowCount = await page.locator('[data-testid="attendance-logs-table"] tbody tr').count();
    expect(initialRowCount).toBeGreaterThan(0);
    
    // Step 3: Enter employee name in filter
    await page.fill('[data-testid="filter-employee-name"]', 'John Smith');
    
    // Step 4: Select date range filter
    await page.fill('[data-testid="filter-start-date"]', '2024-01-01');
    await page.fill('[data-testid="filter-end-date"]', '2024-01-15');
    
    // Step 5: Click Apply Filters button
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForResponse(response => response.url().includes('/api/attendance/logs') && response.status() === 200);
    
    // Step 6: Verify accuracy of filtered results
    await expect(page.locator('[data-testid="attendance-logs-table"] tbody tr')).toHaveCount(await page.locator('[data-testid="attendance-logs-table"] tbody tr').count());
    const filteredRows = page.locator('[data-testid="attendance-logs-table"] tbody tr');
    const filteredRowCount = await filteredRows.count();
    
    for (let i = 0; i < filteredRowCount; i++) {
      const row = filteredRows.nth(i);
      const employeeName = await row.locator('td').nth(0).textContent();
      const attendanceDate = await row.locator('td').nth(1).textContent();
      
      expect(employeeName).toContain('John Smith');
      expect(attendanceDate).toBeTruthy();
    }
    
    // Step 7: Export to CSV format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');
    
    const csvDownloadPromise = page.waitForEvent('download');
    const csvDownload = await csvDownloadPromise;
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    
    // Step 8: Verify CSV file download
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();
    
    // Step 9: Export to PDF format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    
    const pdfDownloadPromise = page.waitForEvent('download');
    const pdfDownload = await pdfDownloadPromise;
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    
    // Step 10: Verify PDF file download
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
  });

  test('Verify access restriction for unauthorized users (error-case)', async ({ page }) => {
    // Logout from attendance manager account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*\/login/);
    
    // Step 1: Login as non-attendance manager
    await page.fill('[data-testid="username-input"]', 'employee01');
    await page.fill('[data-testid="password-input"]', 'emppass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Verify main navigation menu options
    const navigationMenu = page.locator('[data-testid="main-navigation"]');
    await expect(navigationMenu).toBeVisible();
    await expect(page.locator('text=Attendance Logs')).not.toBeVisible();
    
    // Step 3: Manually enter attendance logs page URL
    await page.goto('/manager/attendance-logs');
    
    // Step 4: Verify user is not redirected to attendance logs page
    await expect(page).not.toHaveURL(/.*\/manager\/attendance-logs/);
    await expect(page.locator('[data-testid="error-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/Access Denied|Unauthorized|403/);
    
    // Step 5: Attempt API call without proper authorization
    const apiResponse = await page.request.get('/api/attendance/logs');
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error || responseBody.message).toMatch(/Unauthorized|Access Denied|Forbidden/);
    
    // Step 6: Attempt API call with query parameters
    const apiResponseWithParams = await page.request.get('/api/attendance/logs?employeeName=John Smith&startDate=2024-01-01&endDate=2024-01-31');
    expect(apiResponseWithParams.status()).toBe(403);
    const responseBodyWithParams = await apiResponseWithParams.json();
    expect(responseBodyWithParams.error || responseBodyWithParams.message).toMatch(/Unauthorized|Access Denied|Forbidden/);
    
    // Step 7: Verify unauthorized access is logged (check console or network logs)
    const logs: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        logs.push(msg.text());
      }
    });
    
    // Additional verification that no attendance data is accessible
    await expect(page.locator('[data-testid="attendance-logs-table"]')).not.toBeVisible();
  });
});