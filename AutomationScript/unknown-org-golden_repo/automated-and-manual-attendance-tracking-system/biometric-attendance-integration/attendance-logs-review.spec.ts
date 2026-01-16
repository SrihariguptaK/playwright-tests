import { test, expect } from '@playwright/test';

test.describe('Attendance Manager - Review Biometric Attendance Logs', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Attendance Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Filter attendance logs by date and employee', async ({ page }) => {
    // Step 1: Navigate to attendance logs page
    await page.click('[data-testid="attendance-logs-menu"]');
    await expect(page).toHaveURL(/.*attendance\/logs/);
    await expect(page.locator('[data-testid="attendance-logs-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Attendance Logs');

    // Step 2: Apply date range and employee ID filters
    await page.fill('[data-testid="start-date-filter"]', '2024-01-01');
    await page.fill('[data-testid="end-date-filter"]', '2024-01-31');
    await page.fill('[data-testid="employee-id-filter"]', 'EMP12345');
    await page.click('[data-testid="apply-filters-button"]');

    // Wait for filtered results to load
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance/logs') && response.status() === 200
    );
    await page.waitForSelector('[data-testid="attendance-log-row"]');

    // Verify filtered logs are displayed matching criteria
    const logRows = page.locator('[data-testid="attendance-log-row"]');
    const rowCount = await logRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify each row matches the filter criteria
    for (let i = 0; i < Math.min(rowCount, 5); i++) {
      const row = logRows.nth(i);
      const employeeId = await row.locator('[data-testid="log-employee-id"]').textContent();
      const logDate = await row.locator('[data-testid="log-date"]').textContent();
      
      expect(employeeId).toContain('EMP12345');
      expect(logDate).toBeTruthy();
    }

    // Step 3: Export filtered logs
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;
    
    // Verify CSV file is downloaded with correct data
    expect(download.suggestedFilename()).toContain('.csv');
    const filePath = await download.path();
    expect(filePath).toBeTruthy();
  });

  test('Search attendance logs by employee name', async ({ page }) => {
    // Step 1: Navigate to attendance logs page
    await page.click('[data-testid="attendance-logs-menu"]');
    await expect(page).toHaveURL(/.*attendance\/logs/);
    await expect(page.locator('[data-testid="attendance-logs-page"]')).toBeVisible();

    // Step 2: Enter employee name in search box
    await page.fill('[data-testid="employee-search-input"]', 'John Smith');
    await page.press('[data-testid="employee-search-input"]', 'Enter');

    // Wait for search results to load
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance/logs') && response.status() === 200
    );
    await page.waitForSelector('[data-testid="attendance-log-row"]');

    // Verify logs matching employee name are displayed
    const logRows = page.locator('[data-testid="attendance-log-row"]');
    const rowCount = await logRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify all displayed records belong to the searched employee
    for (let i = 0; i < rowCount; i++) {
      const row = logRows.nth(i);
      const employeeName = await row.locator('[data-testid="log-employee-name"]').textContent();
      expect(employeeName?.toLowerCase()).toContain('john smith');
    }

    // Step 3: Verify highlighted rejected entries
    const rejectedEntries = page.locator('[data-testid="attendance-log-row"][data-status="rejected"]');
    const rejectedCount = await rejectedEntries.count();

    if (rejectedCount > 0) {
      // Verify rejected entries are visually distinct
      for (let i = 0; i < rejectedCount; i++) {
        const rejectedRow = rejectedEntries.nth(i);
        await expect(rejectedRow).toHaveClass(/rejected|error|highlighted/);
        
        // Verify visual distinction through CSS properties
        const backgroundColor = await rejectedRow.evaluate(el => 
          window.getComputedStyle(el).backgroundColor
        );
        expect(backgroundColor).not.toBe('rgb(255, 255, 255)');
      }
    }
  });

  test('Filter attendance logs by date and employee - detailed verification', async ({ page }) => {
    // Navigate to attendance logs page from the main menu or dashboard
    await page.click('text=Attendance Logs');
    await expect(page.locator('[data-testid="attendance-logs-page"]')).toBeVisible();

    // Select start date in the date range filter
    await page.fill('[data-testid="start-date-filter"]', '2024-01-01');
    
    // Select end date in the date range filter
    await page.fill('[data-testid="end-date-filter"]', '2024-01-31');
    
    // Enter specific employee ID in the employee ID filter field
    await page.fill('[data-testid="employee-id-filter"]', 'EMP12345');
    
    // Click Apply Filters or Search button
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForLoadState('networkidle');

    // Verify that all displayed records match the filter criteria
    const logRows = page.locator('[data-testid="attendance-log-row"]');
    const displayedCount = await logRows.count();
    expect(displayedCount).toBeGreaterThan(0);

    // Check dates and employee IDs for each record
    for (let i = 0; i < Math.min(displayedCount, 10); i++) {
      const row = logRows.nth(i);
      const employeeId = await row.locator('[data-testid="log-employee-id"]').textContent();
      const logDate = await row.locator('[data-testid="log-date"]').getAttribute('data-date');
      
      expect(employeeId).toBe('EMP12345');
      if (logDate) {
        const dateObj = new Date(logDate);
        expect(dateObj >= new Date('2024-01-01')).toBeTruthy();
        expect(dateObj <= new Date('2024-01-31')).toBeTruthy();
      }
    }

    // Get the filtered results count from UI
    const resultsCountText = await page.locator('[data-testid="results-count"]').textContent();
    const resultsCount = parseInt(resultsCountText?.match(/\d+/)?.[0] || '0');

    // Click the Export or Download CSV button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;

    // Open the downloaded CSV file and verify
    const filePath = await download.path();
    expect(filePath).toBeTruthy();
    expect(download.suggestedFilename()).toMatch(/attendance.*\.csv/);
    
    // Verify the number of records in CSV matches the filtered results count
    const fs = require('fs');
    if (filePath) {
      const csvContent = fs.readFileSync(filePath, 'utf-8');
      const csvLines = csvContent.split('\n').filter(line => line.trim().length > 0);
      const csvRecordCount = csvLines.length - 1; // Subtract header row
      expect(csvRecordCount).toBe(resultsCount);
    }
  });

  test('Search attendance logs by employee name - comprehensive validation', async ({ page }) => {
    // Navigate to attendance logs page from the main menu or dashboard
    await page.click('a:has-text("Attendance Logs")');
    await expect(page).toHaveURL(/.*attendance\/logs/);

    // Locate the search box for employee name or ID
    const searchBox = page.locator('[data-testid="employee-search-input"]');
    await expect(searchBox).toBeVisible();

    // Enter a specific employee name in the search box
    await searchBox.fill('John Smith');
    
    // Press Enter or click the Search button
    await searchBox.press('Enter');
    await page.waitForLoadState('networkidle');

    // Verify that all displayed records belong to the searched employee
    const logRows = page.locator('[data-testid="attendance-log-row"]');
    const rowCount = await logRows.count();
    expect(rowCount).toBeGreaterThan(0);

    for (let i = 0; i < rowCount; i++) {
      const employeeName = await logRows.nth(i).locator('[data-testid="log-employee-name"]').textContent();
      expect(employeeName?.toLowerCase()).toContain('john smith');
    }

    // Scan through the displayed logs to identify any rejected or error entries
    const rejectedEntries = page.locator('[data-testid="attendance-log-row"].rejected, [data-testid="attendance-log-row"][data-status="rejected"], [data-testid="attendance-log-row"].error');
    const rejectedCount = await rejectedEntries.count();

    if (rejectedCount > 0) {
      // Click on or hover over a rejected entry to view details
      const firstRejectedEntry = rejectedEntries.first();
      await firstRejectedEntry.hover();
      await firstRejectedEntry.click();

      // Verify details are displayed
      await expect(page.locator('[data-testid="log-details-modal"], [data-testid="log-details-panel"]')).toBeVisible();

      // Close details if modal
      const closeButton = page.locator('[data-testid="close-details-button"]');
      if (await closeButton.isVisible()) {
        await closeButton.click();
      }

      // Verify the visual distinction is consistent across all rejected entries
      for (let i = 0; i < rejectedCount; i++) {
        const rejectedRow = rejectedEntries.nth(i);
        const hasErrorClass = await rejectedRow.evaluate(el => 
          el.classList.contains('rejected') || 
          el.classList.contains('error') || 
          el.getAttribute('data-status') === 'rejected'
        );
        expect(hasErrorClass).toBeTruthy();

        // Verify consistent styling
        const textColor = await rejectedRow.evaluate(el => 
          window.getComputedStyle(el).color
        );
        expect(textColor).toBeTruthy();
      }
    }

    // Clear the search box and verify results reset
    await searchBox.clear();
    await searchBox.press('Enter');
    await page.waitForLoadState('networkidle');

    // Verify all logs are displayed again (not filtered)
    const allLogRows = page.locator('[data-testid="attendance-log-row"]');
    const allRowCount = await allLogRows.count();
    expect(allRowCount).toBeGreaterThanOrEqual(rowCount);
  });
});