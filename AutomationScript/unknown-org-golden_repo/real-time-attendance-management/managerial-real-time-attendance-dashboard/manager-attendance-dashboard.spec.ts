import { test, expect } from '@playwright/test';

test.describe('Manager Attendance Dashboard - Real-time Status', () => {
  const DASHBOARD_URL = '/dashboard';
  const MANAGER_USERNAME = 'manager@company.com';
  const MANAGER_PASSWORD = 'Manager123!';
  const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate dashboard real-time data updates', async ({ page }) => {
    // Step 1: Manager logs into the dashboard
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard loads with current attendance data
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
    
    // Verify initial data is loaded
    const initialDataRows = await page.locator('[data-testid="attendance-row"]').count();
    expect(initialDataRows).toBeGreaterThan(0);

    // Step 2: Manager applies filters for team and date
    await page.click('[data-testid="filter-panel"]');
    await page.selectOption('[data-testid="team-dropdown"]', { label: 'Engineering Team' });
    
    // Select today's date
    await page.click('[data-testid="date-picker"]');
    await page.click('[data-testid="date-today"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Dashboard updates data according to filters
    await expect(page.locator('[data-testid="filter-applied-badge"]')).toContainText('Engineering Team');
    await page.waitForLoadState('networkidle');
    const filteredDataRows = await page.locator('[data-testid="attendance-row"]').count();
    expect(filteredDataRows).toBeGreaterThan(0);

    // Step 3: Wait 30 seconds and observe data refresh
    // Capture initial timestamp
    const initialTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    
    // Wait for auto-refresh (30 seconds)
    await page.waitForTimeout(AUTO_REFRESH_INTERVAL);
    
    // Expected Result: Attendance data refreshes automatically with latest information
    await expect(page.locator('[data-testid="refresh-indicator"]')).toBeVisible({ timeout: 5000 });
    const updatedTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(updatedTimestamp).not.toBe(initialTimestamp);
    
    // Verify data is still displayed after refresh
    await expect(page.locator('[data-testid="attendance-data-table"]')).toBeVisible();
  });

  test('Verify export functionality for attendance reports', async ({ page }) => {
    // Login to dashboard
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();

    // Step 1: Manager selects export option on dashboard
    await page.click('[data-testid="export-button"]');
    
    // Expected Result: Export options for CSV and PDF are displayed
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-csv-option"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-pdf-option"]')).toBeVisible();

    // Step 2: Manager exports report in CSV format
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-option"]')
    ]);
    
    // Expected Result: CSV file downloads with correct attendance data
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    expect(csvDownload.suggestedFilename()).toContain('attendance');
    await csvDownload.saveAs(`./downloads/${csvDownload.suggestedFilename()}`);

    // Step 3: Manager exports report in PDF format
    await page.click('[data-testid="export-button"]');
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-option"]')
    ]);
    
    // Expected Result: PDF file downloads with formatted attendance report
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('attendance');
    await pdfDownload.saveAs(`./downloads/${pdfDownload.suggestedFilename()}`);
  });

  test('Test dashboard accessibility on mobile devices', async ({ page, context }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Step 1: Access dashboard URL from mobile browser
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard loads with responsive layout
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="mobile-dashboard-container"]')).toBeVisible();
    
    // Verify responsive design elements
    const dashboardWidth = await page.locator('[data-testid="attendance-dashboard"]').boundingBox();
    expect(dashboardWidth?.width).toBeLessThanOrEqual(375);

    // Step 2: Navigate through filters and data views
    // Open mobile filter menu
    await page.click('[data-testid="hamburger-menu"]');
    await expect(page.locator('[data-testid="mobile-filter-panel"]')).toBeVisible();
    
    // Select department
    await page.selectOption('[data-testid="department-dropdown"]', { label: 'Sales' });
    
    // Select team
    await page.selectOption('[data-testid="team-dropdown"]', { label: 'Sales Team A' });
    
    // Select date using mobile date picker
    await page.click('[data-testid="mobile-date-picker"]');
    await page.click('[data-testid="date-today"]');
    
    // Apply filters
    await page.click('[data-testid="apply-button"]');
    
    // Expected Result: All features function correctly on mobile
    await expect(page.locator('[data-testid="filter-applied-badge"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    // Scroll through attendance data
    await page.locator('[data-testid="attendance-data-table"]').scrollIntoViewIfNeeded();
    const attendanceRows = page.locator('[data-testid="attendance-row"]');
    expect(await attendanceRows.count()).toBeGreaterThan(0);
    
    // Tap on individual record to view details
    await attendanceRows.first().click();
    await expect(page.locator('[data-testid="attendance-details-modal"]')).toBeVisible();
    await page.click('[data-testid="close-details-button"]');

    // Step 3: Export report from mobile device
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    
    // Export CSV
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-option"]')
    ]);
    
    // Expected Result: Export completes successfully and file is accessible
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    await csvDownload.saveAs(`./downloads/mobile-${csvDownload.suggestedFilename()}`);
    
    // Export PDF
    await page.click('[data-testid="export-button"]');
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-option"]')
    ]);
    
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    await pdfDownload.saveAs(`./downloads/mobile-${pdfDownload.suggestedFilename()}`);
  });
});