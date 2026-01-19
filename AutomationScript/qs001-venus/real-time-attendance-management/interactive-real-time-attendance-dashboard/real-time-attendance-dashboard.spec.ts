import { test, expect } from '@playwright/test';

test.describe('Real-time Attendance Dashboard - Story 15', () => {
  const DASHBOARD_URL = process.env.DASHBOARD_URL || 'https://app.example.com/dashboard';
  const MANAGER_USERNAME = process.env.MANAGER_USERNAME || 'manager@example.com';
  const MANAGER_PASSWORD = process.env.MANAGER_PASSWORD || 'Manager123!';
  const DASHBOARD_LOAD_TIMEOUT = 3000;
  const DATA_LATENCY_THRESHOLD = 30000;

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(DASHBOARD_URL + '/login');
  });

  test('Validate real-time attendance data display (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the dashboard login page and enter valid manager credentials
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Dashboard loads with attendance data
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible({ timeout: DASHBOARD_LOAD_TIMEOUT });
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    
    // Verify attendance records are present
    const attendanceRecords = page.locator('[data-testid="attendance-record"]');
    await expect(attendanceRecords.first()).toBeVisible();

    // Step 2: Check the timestamp of the most recent attendance record and compare with current system time
    const timestampElement = page.locator('[data-testid="last-updated-timestamp"]').first();
    await expect(timestampElement).toBeVisible();
    
    const timestampText = await timestampElement.textContent();
    const recordTimestamp = new Date(timestampText || '');
    const currentTime = new Date();
    const latencyMs = currentTime.getTime() - recordTimestamp.getTime();

    // Expected Result: Data is fresh and up-to-date (latency under 30 seconds)
    expect(latencyMs).toBeLessThan(DATA_LATENCY_THRESHOLD);

    // Step 3: Locate the department filter dropdown and select a specific department
    await page.click('[data-testid="department-filter-dropdown"]');
    await expect(page.locator('[data-testid="department-filter-options"]')).toBeVisible();
    
    await page.click('[data-testid="department-option-engineering"]');

    // Expected Result: Dashboard displays filtered attendance data
    await page.waitForResponse(response => 
      response.url().includes('/dashboard/attendance') && response.status() === 200
    );
    
    await expect(page.locator('[data-testid="filtered-department-label"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="attendance-record"]').first()).toBeVisible();
    
    // Verify filtered data is displayed
    const filteredRecords = await page.locator('[data-testid="attendance-record"]').count();
    expect(filteredRecords).toBeGreaterThan(0);
  });

  test('Verify export functionality (happy-path)', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();

    // Step 1: Locate export options and click 'Export to PDF'
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Expected Result: PDF report is generated and downloadable
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    expect(downloadPDF.suggestedFilename()).toMatch(/attendance.*\.pdf/i);
    
    // Verify PDF download completed successfully
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();

    // Step 2: Return to dashboard and click 'Export to Excel'
    await page.waitForTimeout(500); // Brief pause between exports
    
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-button"]');
    
    // Expected Result: Excel report is generated and downloadable
    const downloadExcel = await downloadPromiseExcel;
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(downloadExcel.suggestedFilename()).toMatch(/attendance.*\.(xlsx|xls)/i);
    
    // Verify Excel download completed successfully
    const excelPath = await downloadExcel.path();
    expect(excelPath).toBeTruthy();
  });

  test('Test dashboard load performance (happy-path)', async ({ page, context }) => {
    // Step 1: Clear browser cache and cookies
    await context.clearCookies();
    await context.clearPermissions();

    // Navigate to dashboard URL
    await page.goto(DASHBOARD_URL + '/login');

    // Enter valid manager credentials
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);

    // Start timer immediately before clicking Login
    const startTime = Date.now();
    await page.click('[data-testid="login-button"]');

    // Wait for dashboard to load completely
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    
    // Ensure data is loaded (at least one attendance record visible)
    await expect(page.locator('[data-testid="attendance-record"]').first()).toBeVisible();

    // Calculate load time
    const endTime = Date.now();
    const loadTimeMs = endTime - startTime;

    // Expected Result: Dashboard loads within 3 seconds
    expect(loadTimeMs).toBeLessThan(DASHBOARD_LOAD_TIMEOUT);
    
    // Additional verification: Check that key dashboard elements are present
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-pdf-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-excel-button"]')).toBeVisible();
    
    // Verify late arrivals and absences indicators are visible
    const lateArrivalsIndicator = page.locator('[data-testid="late-arrivals-indicator"]');
    const absencesIndicator = page.locator('[data-testid="absences-indicator"]');
    
    await expect(lateArrivalsIndicator.or(page.locator('[data-testid="no-late-arrivals"]'))).toBeVisible();
    await expect(absencesIndicator.or(page.locator('[data-testid="no-absences"]'))).toBeVisible();
  });
});