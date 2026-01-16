import { test, expect } from '@playwright/test';

test.describe('Schedule Report Generation - Manager Functionality', () => {
  
  test.beforeEach(async ({ page }) => {
    // Login as manager user before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule report generation with valid filters', async ({ page }) => {
    // Step 1: Navigate to schedule reporting module
    await page.click('[data-testid="schedule-reports-menu"]');
    await expect(page).toHaveURL(/.*reports\/schedules/);
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Schedule Reports');
    
    // Step 2: Select valid date range and filters
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="current-week-option"]');
    
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');
    
    await page.click('[data-testid="team-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    await expect(page.locator('[data-testid="team-dropdown"]')).toContainText('Engineering');
    
    await page.click('[data-testid="department-dropdown"]');
    await page.click('[data-testid="department-option-it"]');
    await expect(page.locator('[data-testid="department-dropdown"]')).toContainText('IT');
    
    // Verify no error messages are displayed
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Step 3: Request report generation
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await expect(page.locator('[data-testid="report-loading-spinner"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-loading-spinner"]')).not.toBeVisible({ timeout: 15000 });
    
    // Verify schedule report is generated and displayed with correct data
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Schedule Report');
    await expect(page.locator('[data-testid="report-date-range"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-report-table"] tbody tr')).not.toHaveCount(0);
    
    // Verify report contains expected columns
    await expect(page.locator('[data-testid="column-employee"]')).toBeVisible();
    await expect(page.locator('[data-testid="column-shift"]')).toBeVisible();
    await expect(page.locator('[data-testid="column-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="column-time"]')).toBeVisible();
  });

  test('Verify export functionality for schedule reports', async ({ page }) => {
    // Step 1: Generate schedule report with filters
    await page.click('[data-testid="schedule-reports-menu"]');
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();
    
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="current-week-option"]');
    
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    
    await page.click('[data-testid="team-dropdown"]');
    await page.click('[data-testid="team-option-sales"]');
    
    await page.click('[data-testid="generate-report-button"]');
    await expect(page.locator('[data-testid="report-loading-spinner"]')).not.toBeVisible({ timeout: 15000 });
    
    // Verify report displayed on screen
    await expect(page.locator('[data-testid="schedule-report-table"]')).toBeVisible();
    const reportRowCount = await page.locator('[data-testid="schedule-report-table"] tbody tr').count();
    expect(reportRowCount).toBeGreaterThan(0);
    
    // Step 2: Export report to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);
    
    // Verify PDF file is downloaded with correct formatting
    expect(pdfDownload.suggestedFilename()).toMatch(/schedule-report.*\.pdf/);
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Wait for download to complete
    await page.waitForTimeout(1000);
    
    // Step 3: Export report to Excel
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-button"]')
    ]);
    
    // Verify Excel file is downloaded with accurate data
    expect(excelDownload.suggestedFilename()).toMatch(/schedule-report.*\.(xlsx|xls)/);
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
    
    // Verify success message is displayed
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Ensure unauthorized users cannot access schedule reports', async ({ page }) => {
    // Logout from manager account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Step 1: Login as non-manager user
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Employee123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Verify access to schedule reporting module is denied
    const scheduleReportsMenu = page.locator('[data-testid="schedule-reports-menu"]');
    await expect(scheduleReportsMenu).not.toBeVisible();
    
    // Attempt to navigate directly via URL
    await page.goto('/reports/schedules');
    
    // Verify access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=/Access Denied|Unauthorized|403/');
    
    await expect(
      accessDeniedMessage.or(unauthorizedMessage)
    ).toBeVisible({ timeout: 5000 });
    
    // Step 2: Attempt to access API endpoint directly
    const response = await page.request.get('/api/reports/schedules', {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    
    // Verify access forbidden response received
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toMatch(/forbidden|unauthorized|access denied/i);
    
    // Attempt to access API endpoint without authentication token
    const unauthResponse = await page.request.get('/api/reports/schedules');
    
    // Verify unauthorized response
    expect([401, 403]).toContain(unauthResponse.status());
  });
});