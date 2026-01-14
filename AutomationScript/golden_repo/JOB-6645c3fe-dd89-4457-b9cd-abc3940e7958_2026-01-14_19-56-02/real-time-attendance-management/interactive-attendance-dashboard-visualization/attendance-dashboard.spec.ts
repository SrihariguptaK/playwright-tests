import { test, expect } from '@playwright/test';

test.describe('Attendance Dashboard - Real-time Status Visibility', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate real-time attendance data display on dashboard', async ({ page }) => {
    // Step 1: Login as Manager and open attendance dashboard
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard navigation
    await page.waitForURL('**/dashboard');
    
    // Click on attendance dashboard menu
    await page.click('[data-testid="attendance-dashboard-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Dashboard loads with current attendance data
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    
    // Verify timestamp is present and recent
    const timestampElement = page.locator('[data-testid="data-timestamp"]');
    await expect(timestampElement).toBeVisible();
    const timestampText = await timestampElement.textContent();
    expect(timestampText).toBeTruthy();
    
    // Note current attendance count
    const initialAttendanceCount = await page.locator('[data-testid="total-attendance-count"]').textContent();
    
    // Step 2: Wait for 60 seconds for auto-refresh
    await page.waitForTimeout(61000);
    
    // Expected Result: Dashboard data refreshes automatically
    const refreshedTimestamp = await page.locator('[data-testid="data-timestamp"]').textContent();
    expect(refreshedTimestamp).not.toBe(timestampText);
    
    // Verify data has been updated
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    
    // Step 3: Filter dashboard by department
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    // Expected Result: Dashboard updates to show filtered data
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="filtered-department-label"]')).toContainText('Engineering');
    
    // Verify filtered data is displayed
    const filteredRows = page.locator('[data-testid="attendance-row"]');
    await expect(filteredRows.first()).toBeVisible();
    
    // Verify all displayed rows belong to selected department
    const departmentCells = page.locator('[data-testid="employee-department"]');
    const count = await departmentCells.count();
    for (let i = 0; i < count; i++) {
      await expect(departmentCells.nth(i)).toContainText('Engineering');
    }
  });

  test('Verify export of attendance dashboard reports', async ({ page }) => {
    // Login as Manager
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    // Navigate to attendance dashboard
    await page.click('[data-testid="attendance-dashboard-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Step 1: Locate and click the Export button
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    
    // Select Export as PDF option
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-option"]')
    ]);
    
    // Expected Result: PDF is generated and downloaded correctly
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Wait for download to complete
    await page.waitForTimeout(2000);
    
    // Return to dashboard and click Export button again
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    
    // Select Export as Excel option
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-option"]')
    ]);
    
    // Expected Result: Excel is generated and downloaded correctly
    const excelFilename = excelDownload.suggestedFilename();
    expect(excelFilename.endsWith('.xlsx') || excelFilename.endsWith('.xls')).toBeTruthy();
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
  });

  test('Test dashboard load performance', async ({ page, context }) => {
    // Step 1: Clear browser cache and cookies
    await context.clearCookies();
    await context.clearPermissions();
    
    // Step 2: Navigate to login page
    await page.goto('/login');
    
    // Enter valid Manager credentials
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    
    // Step 3: Start performance timer and click attendance dashboard
    const startTime = Date.now();
    
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    // Click on attendance dashboard menu option
    await page.click('[data-testid="attendance-dashboard-menu"]');
    
    // Wait for all dashboard elements to be fully rendered
    await page.waitForSelector('[data-testid="attendance-dashboard"]', { state: 'visible' });
    await page.waitForSelector('[data-testid="attendance-data-table"]', { state: 'visible' });
    await page.waitForSelector('[data-testid="total-attendance-count"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    await page.waitForLoadState('domcontentloaded');
    
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;
    
    // Expected Result: Dashboard loads within 3 seconds
    expect(loadTime).toBeLessThan(3);
    
    // Verify all dashboard elements are interactive and data is populated
    await expect(page.locator('[data-testid="department-filter-dropdown"]')).toBeEnabled();
    await expect(page.locator('[data-testid="export-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    
    // Verify data is fully populated
    const attendanceRows = page.locator('[data-testid="attendance-row"]');
    await expect(attendanceRows.first()).toBeVisible();
    
    const totalCount = await page.locator('[data-testid="total-attendance-count"]').textContent();
    expect(totalCount).toBeTruthy();
    expect(parseInt(totalCount || '0')).toBeGreaterThan(0);
    
    // Test absent/late employee highlights
    const absentEmployees = page.locator('[data-testid="employee-status-absent"]');
    const lateEmployees = page.locator('[data-testid="employee-status-late"]');
    
    // Verify visual indicators are present if there are absent or late employees
    const absentCount = await absentEmployees.count();
    const lateCount = await lateEmployees.count();
    
    if (absentCount > 0) {
      await expect(absentEmployees.first()).toHaveClass(/absent|highlight|warning/);
    }
    
    if (lateCount > 0) {
      await expect(lateEmployees.first()).toHaveClass(/late|highlight|warning/);
    }
  });

  test('Verify dashboard filtering by date range', async ({ page }) => {
    // Login as Manager
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    // Navigate to attendance dashboard
    await page.click('[data-testid="attendance-dashboard-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Click date range filter
    await page.click('[data-testid="date-range-filter"]');
    
    // Select start date
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    
    // Select end date
    await page.fill('[data-testid="end-date-input"]', '2024-01-31');
    
    // Apply filter
    await page.click('[data-testid="apply-date-filter-button"]');
    
    // Expected Result: Dashboard updates with filtered date range
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-label"]')).toContainText('2024-01-01');
  });

  test('Verify absent and late employee visual indicators', async ({ page }) => {
    // Login as Manager
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    // Navigate to attendance dashboard
    await page.click('[data-testid="attendance-dashboard-menu"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: System highlights absent and late employees
    const absentEmployees = page.locator('[data-testid="employee-status-absent"]');
    const lateEmployees = page.locator('[data-testid="employee-status-late"]');
    
    // Check if absent employees have visual indicators
    const absentCount = await absentEmployees.count();
    if (absentCount > 0) {
      const firstAbsent = absentEmployees.first();
      await expect(firstAbsent).toBeVisible();
      
      // Verify CSS class or styling for highlighting
      const classList = await firstAbsent.getAttribute('class');
      expect(classList).toMatch(/absent|highlight|warning|danger/);
    }
    
    // Check if late employees have visual indicators
    const lateCount = await lateEmployees.count();
    if (lateCount > 0) {
      const firstLate = lateEmployees.first();
      await expect(firstLate).toBeVisible();
      
      // Verify CSS class or styling for highlighting
      const classList = await firstLate.getAttribute('class');
      expect(classList).toMatch(/late|highlight|warning/);
    }
    
    // Verify summary counts
    await expect(page.locator('[data-testid="absent-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="late-count"]')).toBeVisible();
  });
});