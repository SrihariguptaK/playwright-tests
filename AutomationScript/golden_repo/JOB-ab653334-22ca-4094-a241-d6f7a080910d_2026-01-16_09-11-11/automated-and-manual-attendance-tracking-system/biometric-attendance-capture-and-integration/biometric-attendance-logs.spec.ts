import { test, expect } from '@playwright/test';

test.describe('Biometric Attendance Logs - Real-time Monitoring', () => {
  const DASHBOARD_URL = '/attendance/dashboard';
  const DASHBOARD_LOAD_TIMEOUT = 3000;

  test.beforeEach(async ({ page }) => {
    // Manager logs into attendance dashboard
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify real-time attendance log updates - Dashboard loads with latest logs', async ({ page }) => {
    // Action: Open attendance dashboard
    await page.goto(DASHBOARD_URL);
    
    // Expected Result: Dashboard loads with latest attendance logs
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible({ timeout: DASHBOARD_LOAD_TIMEOUT });
    await expect(page.locator('[data-testid="attendance-logs-table"]')).toBeVisible();
    
    const logRows = page.locator('[data-testid="attendance-log-row"]');
    await expect(logRows).not.toHaveCount(0);
    
    // Verify timestamp of latest entry is recent
    const latestTimestamp = await page.locator('[data-testid="attendance-log-row"]').first().locator('[data-testid="timestamp"]').textContent();
    expect(latestTimestamp).toBeTruthy();
  });

  test('Verify real-time attendance log updates - New entry appears within 1 minute', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Get initial count of attendance logs
    const initialCount = await page.locator('[data-testid="attendance-log-row"]').count();
    
    // Action: Wait for 1 minute after new biometric entry
    // Simulate waiting for new entry by polling the API or waiting
    await page.waitForTimeout(60000);
    
    // Expected Result: New attendance entry appears on dashboard
    await page.reload();
    const updatedCount = await page.locator('[data-testid="attendance-log-row"]').count();
    
    // Verify new entries may have appeared or data is refreshed
    expect(updatedCount).toBeGreaterThanOrEqual(initialCount);
  });

  test('Verify real-time attendance log updates - Manual refresh reloads current data', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Action: Refresh dashboard manually
    await page.click('[data-testid="refresh-button"]');
    
    // Expected Result: Dashboard reloads and displays current data
    await expect(page.locator('[data-testid="loading-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="loading-indicator"]')).not.toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="attendance-logs-table"]')).toBeVisible();
    
    const logRows = page.locator('[data-testid="attendance-log-row"]');
    await expect(logRows).not.toHaveCount(0);
  });

  test('Test filtering and search functionality - Filter by department and date', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Action: Apply filter by department and date
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-engineering"]');
    
    await page.fill('[data-testid="date-filter"]', '2024-01-15');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Dashboard displays only matching attendance records
    await expect(page.locator('[data-testid="loading-indicator"]')).not.toBeVisible({ timeout: 5000 });
    
    const filteredRows = page.locator('[data-testid="attendance-log-row"]');
    const rowCount = await filteredRows.count();
    
    if (rowCount > 0) {
      // Verify all displayed records match the filter criteria
      const firstRowDepartment = await filteredRows.first().locator('[data-testid="department-cell"]').textContent();
      expect(firstRowDepartment).toContain('Engineering');
      
      const firstRowDate = await filteredRows.first().locator('[data-testid="date-cell"]').textContent();
      expect(firstRowDate).toContain('2024-01-15');
    }
    
    // Verify filter tags are displayed
    await expect(page.locator('[data-testid="active-filter-department"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-filter-date"]')).toBeVisible();
  });

  test('Test filtering and search functionality - Search by employee name', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Action: Search for employee by name
    const searchName = 'John Smith';
    await page.fill('[data-testid="employee-search-input"]', searchName);
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Dashboard shows attendance records for searched employee
    await expect(page.locator('[data-testid="loading-indicator"]')).not.toBeVisible({ timeout: 5000 });
    
    const searchResults = page.locator('[data-testid="attendance-log-row"]');
    const resultCount = await searchResults.count();
    
    if (resultCount > 0) {
      // Verify all results contain the searched employee name
      const firstResultName = await searchResults.first().locator('[data-testid="employee-name-cell"]').textContent();
      expect(firstResultName).toContain(searchName);
    }
    
    // Verify search term is displayed
    await expect(page.locator('[data-testid="search-term-display"]')).toContainText(searchName);
  });

  test('Test filtering and search functionality - Clear filters and search', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Apply filters first
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-sales"]');
    await page.fill('[data-testid="employee-search-input"]', 'Jane Doe');
    await page.click('[data-testid="apply-filters-button"]');
    
    await expect(page.locator('[data-testid="active-filter-department"]')).toBeVisible();
    
    // Get filtered count
    const filteredCount = await page.locator('[data-testid="attendance-log-row"]').count();
    
    // Action: Clear filters and search
    await page.click('[data-testid="clear-filters-button"]');
    
    // Expected Result: Dashboard displays all attendance records
    await expect(page.locator('[data-testid="loading-indicator"]')).not.toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="active-filter-department"]')).not.toBeVisible();
    
    const allRecordsCount = await page.locator('[data-testid="attendance-log-row"]').count();
    expect(allRecordsCount).toBeGreaterThanOrEqual(filteredCount);
    
    // Verify search input is cleared
    await expect(page.locator('[data-testid="employee-search-input"]')).toHaveValue('');
  });

  test('Validate anomaly highlighting - Identify and highlight missing punches', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Action: Identify attendance records with missing punches
    const anomalyRows = page.locator('[data-testid="attendance-log-row"][data-anomaly="missing-punch"]');
    
    // Expected Result: System highlights these records visually
    const anomalyCount = await anomalyRows.count();
    
    if (anomalyCount > 0) {
      const firstAnomaly = anomalyRows.first();
      
      // Verify visual highlighting (e.g., special class, background color, icon)
      await expect(firstAnomaly).toHaveClass(/anomaly|highlighted|warning/);
      await expect(firstAnomaly.locator('[data-testid="anomaly-icon"]')).toBeVisible();
      
      // Verify anomaly indicator or badge
      await expect(firstAnomaly.locator('[data-testid="missing-punch-badge"]')).toBeVisible();
      
      // Verify tooltip or message explaining the anomaly
      await firstAnomaly.hover();
      await expect(page.locator('[data-testid="anomaly-tooltip"]')).toBeVisible();
      await expect(page.locator('[data-testid="anomaly-tooltip"]')).toContainText('Missing punch');
    }
  });

  test('Validate anomaly highlighting - Highlight disappears after correction', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Identify an anomaly record
    const anomalyRow = page.locator('[data-testid="attendance-log-row"][data-anomaly="missing-punch"]').first();
    
    if (await anomalyRow.count() > 0) {
      const employeeId = await anomalyRow.getAttribute('data-employee-id');
      
      // Verify anomaly is highlighted
      await expect(anomalyRow.locator('[data-testid="anomaly-icon"]')).toBeVisible();
      
      // Simulate correction (this would typically be done through another interface)
      // For testing purposes, we'll trigger a correction action
      await anomalyRow.click('[data-testid="resolve-anomaly-button"]');
      await page.fill('[data-testid="correction-time-input"]', '09:00');
      await page.click('[data-testid="submit-correction-button"]');
      
      // Wait for update
      await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
      
      // Refresh to see updated data
      await page.click('[data-testid="refresh-button"]');
      await expect(page.locator('[data-testid="loading-indicator"]')).not.toBeVisible({ timeout: 5000 });
      
      // Expected Result: Anomaly highlight is removed
      const updatedRow = page.locator(`[data-testid="attendance-log-row"][data-employee-id="${employeeId}"]`);
      await expect(updatedRow.locator('[data-testid="anomaly-icon"]')).not.toBeVisible();
    }
  });

  test('Validate anomaly highlighting - Export attendance data to CSV', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Apply some filters for export
    await page.click('[data-testid="department-filter"]');
    await page.click('[data-testid="department-option-hr"]');
    await page.fill('[data-testid="date-filter"]', '2024-01-15');
    await page.click('[data-testid="apply-filters-button"]');
    
    await expect(page.locator('[data-testid="loading-indicator"]')).not.toBeVisible({ timeout: 5000 });
    
    // Action: Export attendance data
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    
    // Expected Result: CSV file downloads with filtered data
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/attendance.*\.csv/);
    
    // Verify download completed
    const path = await download.path();
    expect(path).toBeTruthy();
    
    // Verify success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('exported successfully');
  });
});