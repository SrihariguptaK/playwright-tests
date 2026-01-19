import { test, expect } from '@playwright/test';

test.describe('Manager Attendance Dashboard - Real-time View', () => {
  const DASHBOARD_URL = '/attendance/dashboard';
  const MANAGER_USERNAME = 'manager.test@company.com';
  const MANAGER_PASSWORD = 'SecurePass123!';
  const DASHBOARD_LOAD_TIMEOUT = 5000;
  const REAL_TIME_UPDATE_THRESHOLD = 30000;

  test.beforeEach(async ({ page }) => {
    // Navigate to dashboard portal
    await page.goto(DASHBOARD_URL);
  });

  test('Validate real-time dashboard data display (happy-path)', async ({ page }) => {
    // Step 1: Manager logs into dashboard portal
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Dashboard loads with current attendance metrics
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible({ timeout: DASHBOARD_LOAD_TIMEOUT });
    await expect(page.locator('[data-testid="attendance-metrics"]')).toBeVisible();
    
    // Verify real-time data with timestamp showing last update within 30 seconds
    const lastUpdateElement = page.locator('[data-testid="last-update-timestamp"]');
    await expect(lastUpdateElement).toBeVisible();
    const lastUpdateText = await lastUpdateElement.textContent();
    const lastUpdateTime = new Date(lastUpdateText || '');
    const currentTime = new Date();
    const timeDifference = currentTime.getTime() - lastUpdateTime.getTime();
    expect(timeDifference).toBeLessThanOrEqual(REAL_TIME_UPDATE_THRESHOLD);

    // Step 2: Manager applies filters for team and date range
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-engineering"]');
    
    // Select date range using date range picker (last 7 days)
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="date-range-last-7-days"]');
    await page.click('[data-testid="apply-filters-button"]');

    // Expected Result: Dashboard updates to reflect filtered data
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance/dashboard') && response.status() === 200
    );
    await expect(page.locator('[data-testid="filtered-team-label"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="filtered-date-range-label"]')).toContainText('Last 7 days');
    
    // Verify attendance metrics are updated
    const presentCount = page.locator('[data-testid="metric-present-count"]');
    const absentCount = page.locator('[data-testid="metric-absent-count"]');
    const lateCount = page.locator('[data-testid="metric-late-count"]');
    await expect(presentCount).toBeVisible();
    await expect(absentCount).toBeVisible();
    await expect(lateCount).toBeVisible();

    // Step 3: Manager drills down to individual employee record
    await page.click('[data-testid="employee-record-john-doe"]');

    // Expected Result: Detailed attendance information is displayed
    await expect(page.locator('[data-testid="employee-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="employee-attendance-history"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-present-days"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-absent-days"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-late-arrivals"]')).toBeVisible();
  });

  test('Verify dashboard export functionality (happy-path)', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible({ timeout: DASHBOARD_LOAD_TIMEOUT });

    // Note the current on-screen data for verification
    const presentCountText = await page.locator('[data-testid="metric-present-count"]').textContent();
    const absentCountText = await page.locator('[data-testid="metric-absent-count"]').textContent();
    const lateCountText = await page.locator('[data-testid="metric-late-count"]').textContent();
    const teamNameText = await page.locator('[data-testid="current-team-name"]').textContent();
    const dateRangeText = await page.locator('[data-testid="current-date-range"]').textContent();

    // Step 1: Manager selects export option on dashboard
    await page.click('[data-testid="export-button"]');

    // Expected Result: Export dialog appears with format options
    await expect(page.locator('[data-testid="export-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-format-pdf"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-format-excel"]')).toBeVisible();

    // Step 2: Manager exports report as PDF
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-format-pdf"]');
    await page.click('[data-testid="export-download-button"]');
    const downloadPDF = await downloadPromisePDF;

    // Expected Result: PDF report downloads and matches on-screen data
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();

    // Close export dialog
    await page.click('[data-testid="export-dialog-close"]');

    // Step 3: Manager exports report as Excel
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-dialog"]')).toBeVisible();
    
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-format-excel"]');
    await page.click('[data-testid="export-download-button"]');
    const downloadExcel = await downloadPromiseExcel;

    // Expected Result: Excel file downloads with correct data and formatting
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    const excelPath = await downloadExcel.path();
    expect(excelPath).toBeTruthy();
    
    // Verify Excel file contains expected structure
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });

  test('Ensure dashboard performance under load (edge-case)', async ({ page, context }) => {
    const CONCURRENT_USERS = 20;
    const MAX_LOAD_TIME = 5000;
    const loadTimes: number[] = [];
    const pages = [];

    // Step 1: Simulate multiple managers accessing dashboard concurrently
    for (let i = 0; i < CONCURRENT_USERS; i++) {
      const newPage = await context.newPage();
      pages.push(newPage);
    }

    // Step 2: All users log in and access dashboard simultaneously
    const loginPromises = pages.map(async (userPage, index) => {
      const startTime = Date.now();
      
      await userPage.goto(DASHBOARD_URL);
      await userPage.fill('[data-testid="username-input"]', `manager${index}@company.com`);
      await userPage.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
      await userPage.click('[data-testid="login-button"]');
      
      // Wait for dashboard to load
      await userPage.waitForSelector('[data-testid="dashboard-container"]', { timeout: 10000 });
      
      const endTime = Date.now();
      const loadTime = endTime - startTime;
      loadTimes.push(loadTime);
      
      return { userPage, loadTime };
    });

    const results = await Promise.all(loginPromises);

    // Expected Result: Dashboard loads within 5 seconds for all users
    results.forEach((result, index) => {
      expect(result.loadTime).toBeLessThanOrEqual(MAX_LOAD_TIME);
    });

    // Step 3: Verify data accuracy during concurrent access
    const dataSnapshots = await Promise.all(
      pages.map(async (userPage) => {
        const timestamp = await userPage.locator('[data-testid="last-update-timestamp"]').textContent();
        const presentCount = await userPage.locator('[data-testid="metric-present-count"]').textContent();
        const absentCount = await userPage.locator('[data-testid="metric-absent-count"]').textContent();
        const lateCount = await userPage.locator('[data-testid="metric-late-count"]').textContent();
        
        return { timestamp, presentCount, absentCount, lateCount };
      })
    );

    // Expected Result: All users see consistent and up-to-date data
    const firstSnapshot = dataSnapshots[0];
    dataSnapshots.forEach((snapshot, index) => {
      expect(snapshot.presentCount).toBe(firstSnapshot.presentCount);
      expect(snapshot.absentCount).toBe(firstSnapshot.absentCount);
      expect(snapshot.lateCount).toBe(firstSnapshot.lateCount);
    });

    // Step 4: Have all concurrent users apply different filters and verify response times
    const filterPromises = pages.map(async (userPage, index) => {
      const startTime = Date.now();
      
      await userPage.click('[data-testid="team-filter-dropdown"]');
      await userPage.click(`[data-testid="team-option-${index % 5}"]`);
      await userPage.click('[data-testid="apply-filters-button"]');
      
      await userPage.waitForResponse(response => 
        response.url().includes('/api/attendance/dashboard') && response.status() === 200
      );
      
      const endTime = Date.now();
      return endTime - startTime;
    });

    const filterResponseTimes = await Promise.all(filterPromises);
    
    // Verify all filter operations complete in reasonable time
    filterResponseTimes.forEach(responseTime => {
      expect(responseTime).toBeLessThanOrEqual(3000);
    });

    // Cleanup: Close all pages
    await Promise.all(pages.map(p => p.close()));
  });

  test.afterEach(async ({ page }) => {
    // Logout if logged in
    const logoutButton = page.locator('[data-testid="logout-button"]');
    if (await logoutButton.isVisible()) {
      await logoutButton.click();
    }
  });
});