import { test, expect } from '@playwright/test';

test.describe('Biometric Attendance Logs - Real-time Monitoring', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const MANAGER_USERNAME = 'manager001';
  const MANAGER_PASSWORD = 'Manager@123';
  const UNAUTHORIZED_USERNAME = 'employee002';
  const UNAUTHORIZED_PASSWORD = 'Employee@123';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Validate real-time attendance log updates (happy-path)', async ({ page }) => {
    // Login as attendance manager
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to attendance dashboard from the main menu
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="biometric-logs-link"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();

    // Note the current timestamp and total number of attendance entries displayed
    const initialEntriesCount = await page.locator('[data-testid="attendance-log-row"]').count();
    const currentTimestamp = new Date().toISOString();

    // Trigger a new biometric attendance capture on a test device (simulate employee punch-in)
    // This would typically be done via API call to simulate biometric device
    await page.evaluate(async () => {
      await fetch('/api/attendance/biometric/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          employeeId: 'EMP-12345',
          deviceId: 'DEVICE-001',
          timestamp: new Date().toISOString(),
          type: 'punch-in'
        })
      });
    });

    // Wait for 30 seconds and observe the dashboard
    await page.waitForTimeout(30000);
    
    // Verify dashboard updates with new attendance entries
    const updatedEntriesCount = await page.locator('[data-testid="attendance-log-row"]').count();
    expect(updatedEntriesCount).toBeGreaterThan(initialEntriesCount);

    // Click on the filter dropdown and select specific employee 'EMP-12345' from the employee filter
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.fill('[data-testid="employee-search-input"]', 'EMP-12345');
    await page.click('[data-testid="employee-option-EMP-12345"]');

    // Select today's date from the date filter and click 'Apply Filters'
    await page.click('[data-testid="date-filter-input"]');
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="date-filter-input"]', today);
    await page.click('[data-testid="apply-filters-button"]');

    // Verify the filtered results show correct employee name, date, and time entries
    await expect(page.locator('[data-testid="attendance-log-row"]').first()).toBeVisible();
    const firstRow = page.locator('[data-testid="attendance-log-row"]').first();
    await expect(firstRow.locator('[data-testid="employee-id"]')).toContainText('EMP-12345');
    await expect(firstRow.locator('[data-testid="attendance-date"]')).toContainText(today);
    await expect(firstRow.locator('[data-testid="attendance-time"]')).toBeVisible();
  });

  test('Verify anomaly highlighting in attendance logs (happy-path)', async ({ page }) => {
    // Login as attendance manager
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to attendance dashboard from the main menu
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="biometric-logs-link"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();

    // Scan the attendance log entries for visual indicators of anomalies
    const anomalyIndicators = page.locator('[data-testid="anomaly-indicator"]');
    await expect(anomalyIndicators.first()).toBeVisible();

    // Identify and click on an entry with missing punch-out for employee 'EMP-67890'
    const missingPunchOutRow = page.locator('[data-testid="attendance-log-row"]').filter({
      has: page.locator('[data-testid="employee-id"]:has-text("EMP-67890")')
    }).filter({
      has: page.locator('[data-testid="anomaly-type"]:has-text("missing-punch-out")')
    }).first();
    await expect(missingPunchOutRow).toBeVisible();
    await expect(missingPunchOutRow.locator('[data-testid="anomaly-highlight"]')).toHaveClass(/highlighted|anomaly/);
    await missingPunchOutRow.click();

    // Locate duplicate attendance entries for the same employee at similar timestamps
    const duplicateEntries = page.locator('[data-testid="attendance-log-row"]').filter({
      has: page.locator('[data-testid="anomaly-type"]:has-text("duplicate")')
    });
    await expect(duplicateEntries.first()).toBeVisible();

    // Apply filter to show only anomalous entries by selecting 'Show Anomalies Only' checkbox
    await page.click('[data-testid="show-anomalies-checkbox"]');
    await expect(page.locator('[data-testid="show-anomalies-checkbox"]')).toBeChecked();

    // Verify all visible entries have anomaly indicators
    const visibleRows = page.locator('[data-testid="attendance-log-row"]');
    const visibleRowsCount = await visibleRows.count();
    for (let i = 0; i < visibleRowsCount; i++) {
      await expect(visibleRows.nth(i).locator('[data-testid="anomaly-indicator"]')).toBeVisible();
    }

    // Click the 'Export' button to download filtered logs
    await page.click('[data-testid="export-button"]');

    // Confirm export by clicking 'Download CSV'
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="download-csv-button"]');
    const download = await downloadPromise;

    // Open the downloaded CSV file and verify contents
    expect(download.suggestedFilename()).toContain('.csv');
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Ensure access control for attendance dashboard (error-case)', async ({ page }) => {
    // Login to the attendance management system using unauthorized user credentials
    await page.fill('[data-testid="username-input"]', UNAUTHORIZED_USERNAME);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify that attendance dashboard menu option is not visible in the navigation menu
    const attendanceMenu = page.locator('[data-testid="attendance-menu"]');
    const biometricLogsLink = page.locator('[data-testid="biometric-logs-link"]');
    
    // Check if attendance menu exists but biometric logs is not accessible
    const isAttendanceMenuVisible = await attendanceMenu.isVisible().catch(() => false);
    if (isAttendanceMenuVisible) {
      await attendanceMenu.click();
      await expect(biometricLogsLink).not.toBeVisible();
    } else {
      await expect(attendanceMenu).not.toBeVisible();
    }

    // Attempt to navigate to attendance dashboard by entering the URL directly
    await page.goto(`${BASE_URL}/attendance/dashboard`);
    
    // Verify access is denied - should show error message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const errorMessage = page.locator('[data-testid="error-message"]');
    
    const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false);
    const isError = await errorMessage.isVisible().catch(() => false);
    
    expect(isAccessDenied || isError || page.url().includes('unauthorized') || page.url().includes('403')).toBeTruthy();

    // Logout from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Login to the attendance management system using Attendance Manager credentials
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify that attendance dashboard menu option is visible in the navigation menu
    await expect(page.locator('[data-testid="attendance-menu"]')).toBeVisible();
    await page.click('[data-testid="attendance-menu"]');
    await expect(page.locator('[data-testid="biometric-logs-link"]')).toBeVisible();

    // Navigate to attendance dashboard by clicking the menu link
    await page.click('[data-testid="biometric-logs-link"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page).toHaveURL(/.*attendance\/dashboard/);
  });
});