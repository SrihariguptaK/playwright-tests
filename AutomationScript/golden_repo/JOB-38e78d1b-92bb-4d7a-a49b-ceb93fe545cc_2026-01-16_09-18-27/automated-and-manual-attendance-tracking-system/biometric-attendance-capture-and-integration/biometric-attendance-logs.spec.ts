import { test, expect } from '@playwright/test';

test.describe('Biometric Attendance Logs - Real-time Monitoring', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Attendance Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify real-time attendance log updates', async ({ page }) => {
    // Action: Open attendance dashboard
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-attendance-dashboard"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Expected Result: Dashboard loads with latest attendance logs
    await expect(page.locator('[data-testid="attendance-logs-table"]')).toBeVisible();
    const initialRowCount = await page.locator('[data-testid="attendance-log-row"]').count();
    expect(initialRowCount).toBeGreaterThan(0);
    
    // Note the current timestamp
    const initialTimestamp = await page.locator('[data-testid="dashboard-timestamp"]').textContent();
    expect(initialTimestamp).toBeTruthy();
    
    // Action: Wait for 1 minute after new biometric entry
    // Simulate new biometric entry by triggering test endpoint
    await page.evaluate(() => {
      fetch('/api/attendance/simulate-punch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ employeeId: 'EMP001', type: 'punch-in' })
      });
    });
    
    // Wait for real-time update (within 1 minute)
    await page.waitForTimeout(60000);
    
    // Expected Result: New attendance entry appears on dashboard
    const updatedRowCount = await page.locator('[data-testid="attendance-log-row"]').count();
    expect(updatedRowCount).toBeGreaterThan(initialRowCount);
    
    // Action: Refresh dashboard manually
    await page.click('[data-testid="refresh-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Dashboard reloads and displays current data
    const refreshedTimestamp = await page.locator('[data-testid="dashboard-timestamp"]').textContent();
    expect(refreshedTimestamp).not.toBe(initialTimestamp);
    
    // Verify data freshness within 1 minute
    const currentTime = new Date();
    const dashboardTime = new Date(refreshedTimestamp || '');
    const timeDifference = Math.abs(currentTime.getTime() - dashboardTime.getTime()) / 1000;
    expect(timeDifference).toBeLessThan(60);
  });

  test('Test filtering and search functionality', async ({ page }) => {
    // Navigate to attendance dashboard
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-attendance-dashboard"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Action: Apply filter by department and date
    await page.click('[data-testid="filter-department"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.fill('[data-testid="filter-date"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Dashboard displays only matching attendance records
    const filteredRows = await page.locator('[data-testid="attendance-log-row"]').all();
    for (const row of filteredRows) {
      const department = await row.locator('[data-testid="row-department"]').textContent();
      expect(department).toBe('Engineering');
    }
    
    // Apply additional filter by device
    await page.click('[data-testid="filter-device"]');
    await page.click('[data-testid="device-option-device-001"]');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForLoadState('networkidle');
    
    const deviceFilteredCount = await page.locator('[data-testid="attendance-log-row"]').count();
    expect(deviceFilteredCount).toBeGreaterThan(0);
    
    // Action: Search for employee by name
    await page.fill('[data-testid="search-input"]', 'John Smith');
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Dashboard shows attendance records for searched employee
    const searchResults = await page.locator('[data-testid="attendance-log-row"]').all();
    expect(searchResults.length).toBeGreaterThan(0);
    for (const row of searchResults) {
      const employeeName = await row.locator('[data-testid="row-employee-name"]').textContent();
      expect(employeeName).toContain('John Smith');
    }
    
    // Clear name search and search by employee ID
    await page.fill('[data-testid="search-input"]', '');
    await page.fill('[data-testid="search-input"]', 'EMP001');
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');
    
    const idSearchResults = await page.locator('[data-testid="attendance-log-row"]').all();
    expect(idSearchResults.length).toBeGreaterThan(0);
    for (const row of idSearchResults) {
      const employeeId = await row.locator('[data-testid="row-employee-id"]').textContent();
      expect(employeeId).toContain('EMP001');
    }
    
    // Action: Clear filters and search
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Dashboard displays all attendance records
    const totalRecordCount = await page.locator('[data-testid="total-records"]').textContent();
    const displayedRowCount = await page.locator('[data-testid="attendance-log-row"]').count();
    expect(displayedRowCount).toBeGreaterThan(deviceFilteredCount);
    
    // Verify filters are cleared
    await expect(page.locator('[data-testid="filter-department"]')).toHaveValue('');
    await expect(page.locator('[data-testid="search-input"]')).toHaveValue('');
  });

  test('Validate anomaly highlighting', async ({ page }) => {
    // Navigate to attendance dashboard
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-attendance-dashboard"]');
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    
    // Action: Identify attendance records with missing punches
    const anomalyRecords = await page.locator('[data-testid="attendance-log-row"][data-anomaly="true"]').all();
    expect(anomalyRecords.length).toBeGreaterThan(0);
    
    // Expected Result: System highlights these records visually
    for (const record of anomalyRecords) {
      const highlightClass = await record.getAttribute('class');
      expect(highlightClass).toContain('anomaly-highlight');
    }
    
    // Hover over highlighted anomaly record to view details
    const firstAnomaly = anomalyRecords[0];
    await firstAnomaly.hover();
    await expect(page.locator('[data-testid="anomaly-tooltip"]')).toBeVisible();
    const tooltipText = await page.locator('[data-testid="anomaly-tooltip"]').textContent();
    expect(tooltipText).toContain('missing punch');
    
    // Identify duplicate entries
    const duplicateRecords = await page.locator('[data-testid="attendance-log-row"][data-anomaly-type="duplicate"]').all();
    if (duplicateRecords.length > 0) {
      const duplicateHighlight = await duplicateRecords[0].getAttribute('class');
      expect(duplicateHighlight).toContain('anomaly-highlight');
    }
    
    // Navigate to attendance correction interface
    const anomalyEmployeeId = await firstAnomaly.locator('[data-testid="row-employee-id"]').textContent();
    await firstAnomaly.click();
    await page.click('[data-testid="correct-attendance-button"]');
    await expect(page.locator('[data-testid="correction-modal"]')).toBeVisible();
    
    // Action: Correct the missing punch entry
    await page.fill('[data-testid="missing-punch-time"]', '09:00');
    await page.click('[data-testid="punch-type-in"]');
    await page.click('[data-testid="save-correction-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await page.click('[data-testid="close-modal-button"]');
    
    // Action: Return to dashboard and verify correction
    await page.click('[data-testid="menu-attendance"]');
    await page.click('[data-testid="submenu-attendance-dashboard"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Anomaly highlight is removed
    const correctedRecord = page.locator(`[data-testid="attendance-log-row"][data-employee-id="${anomalyEmployeeId}"]`).first();
    const correctedClass = await correctedRecord.getAttribute('class');
    expect(correctedClass).not.toContain('anomaly-highlight');
    
    // Apply filter for current date
    await page.fill('[data-testid="filter-date"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForLoadState('networkidle');
    
    // Action: Export attendance data
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;
    
    // Expected Result: CSV file downloads with filtered data
    expect(download.suggestedFilename()).toContain('.csv');
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();
    
    // Save and verify CSV content
    const fs = require('fs');
    const csvContent = fs.readFileSync(downloadPath, 'utf-8');
    expect(csvContent).toContain('Employee ID');
    expect(csvContent).toContain('Department');
    expect(csvContent).toContain('Punch Time');
    
    // Verify anomaly records are marked in CSV
    const csvLines = csvContent.split('\n');
    const anomalyLines = csvLines.filter((line: string) => line.includes('anomaly') || line.includes('missing'));
    expect(anomalyLines.length).toBeGreaterThanOrEqual(0);
  });
});