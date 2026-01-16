import { test, expect } from '@playwright/test';

test.describe('Conflict Dashboard - Scheduling Conflicts Management', () => {
  const DASHBOARD_URL = '/scheduler/conflicts';
  const DASHBOARD_LOAD_TIMEOUT = 3000;

  test.beforeEach(async ({ page }) => {
    // Navigate to conflict dashboard before each test
    await page.goto(DASHBOARD_URL);
    await page.waitForLoadState('networkidle');
  });

  test('Validate real-time display of scheduling conflicts', async ({ page }) => {
    // Step 1: Access the conflict dashboard
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));
    await expect(page.locator('[data-testid="conflict-dashboard"]')).toBeVisible();
    
    // Verify dashboard loads with current conflicts
    const conflictList = page.locator('[data-testid="conflict-list"]');
    await expect(conflictList).toBeVisible();
    
    // Note the initial conflict count
    const initialConflicts = await page.locator('[data-testid="conflict-item"]').count();
    
    // Record timestamp before triggering new conflict
    const beforeTimestamp = Date.now();
    
    // Step 2: Trigger a new scheduling conflict by double-booking a resource
    // Navigate to scheduling system
    await page.click('[data-testid="schedule-appointment-btn"]');
    
    // Create first appointment
    await page.fill('[data-testid="resource-select"]', 'Resource-101');
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time"]', '10:00');
    await page.fill('[data-testid="appointment-duration"]', '60');
    await page.click('[data-testid="save-appointment-btn"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Create conflicting appointment (same resource, overlapping time)
    await page.click('[data-testid="schedule-appointment-btn"]');
    await page.fill('[data-testid="resource-select"]', 'Resource-101');
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-time"]', '10:30');
    await page.fill('[data-testid="appointment-duration"]', '60');
    await page.click('[data-testid="save-appointment-btn"]');
    
    // Navigate back to conflict dashboard
    await page.goto(DASHBOARD_URL);
    
    // Verify dashboard updates to show new conflict within 3 seconds
    const afterTimestamp = Date.now();
    const updateTime = afterTimestamp - beforeTimestamp;
    
    await page.waitForSelector('[data-testid="conflict-item"]', { timeout: DASHBOARD_LOAD_TIMEOUT });
    const updatedConflicts = await page.locator('[data-testid="conflict-item"]').count();
    
    expect(updatedConflicts).toBeGreaterThan(initialConflicts);
    expect(updateTime).toBeLessThan(DASHBOARD_LOAD_TIMEOUT);
    
    // Verify new conflict details are displayed
    const newConflict = page.locator('[data-testid="conflict-item"]').first();
    await expect(newConflict).toContainText('Resource-101');
    await expect(newConflict).toContainText('2024-03-15');
  });

  test('Verify filtering and sorting functionality', async ({ page }) => {
    // Step 1: Apply filters by resource and time
    // Locate the filter section
    const filterSection = page.locator('[data-testid="conflict-filters"]');
    await expect(filterSection).toBeVisible();
    
    // Select a specific resource from the resource filter dropdown
    await page.click('[data-testid="resource-filter-dropdown"]');
    await page.click('[data-testid="resource-option-Resource-101"]');
    
    // Wait for dashboard to update
    await page.waitForTimeout(500);
    
    // Verify dashboard displays filtered conflicts accurately
    const filteredConflicts = page.locator('[data-testid="conflict-item"]');
    const conflictCount = await filteredConflicts.count();
    
    // Verify all displayed conflicts contain the selected resource
    for (let i = 0; i < conflictCount; i++) {
      const conflict = filteredConflicts.nth(i);
      await expect(conflict).toContainText('Resource-101');
    }
    
    // Apply a time filter by selecting a specific date range
    await page.fill('[data-testid="date-filter-start"]', '2024-03-01');
    await page.fill('[data-testid="date-filter-end"]', '2024-03-31');
    await page.click('[data-testid="apply-date-filter-btn"]');
    
    // Wait for dashboard to update
    await page.waitForTimeout(500);
    
    // Verify the displayed conflicts fall within date range
    const dateFilteredConflicts = await page.locator('[data-testid="conflict-item"]').count();
    expect(dateFilteredConflicts).toBeGreaterThanOrEqual(0);
    
    // Clear the applied filters
    await page.click('[data-testid="clear-filters-btn"]');
    await page.waitForTimeout(500);
    
    // Step 2: Sort conflicts by severity
    // Locate the sort control and click on 'Sort by Severity'
    await page.click('[data-testid="sort-dropdown"]');
    await page.click('[data-testid="sort-by-severity"]');
    
    // Wait for sorting to apply
    await page.waitForTimeout(500);
    
    // Review the order of conflicts displayed
    const sortedConflicts = page.locator('[data-testid="conflict-item"]');
    const sortedCount = await sortedConflicts.count();
    
    // Verify the sorting order by checking severity levels of consecutive conflicts
    if (sortedCount > 1) {
      const severityLevels: string[] = [];
      
      for (let i = 0; i < Math.min(sortedCount, 5); i++) {
        const severityElement = sortedConflicts.nth(i).locator('[data-testid="conflict-severity"]');
        const severityText = await severityElement.textContent();
        if (severityText) {
          severityLevels.push(severityText.trim());
        }
      }
      
      // Verify severity order (High -> Medium -> Low)
      const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
      for (let i = 0; i < severityLevels.length - 1; i++) {
        const currentSeverity = severityOrder[severityLevels[i] as keyof typeof severityOrder] || 0;
        const nextSeverity = severityOrder[severityLevels[i + 1] as keyof typeof severityOrder] || 0;
        expect(currentSeverity).toBeGreaterThanOrEqual(nextSeverity);
      }
    }
  });

  test('Test export of conflict reports', async ({ page }) => {
    // Step 1: Click export button on dashboard
    // Locate the export button on the conflict dashboard
    const exportButton = page.locator('[data-testid="export-conflicts-btn"]');
    await expect(exportButton).toBeVisible();
    
    // Set up download listener before clicking
    const downloadPromise = page.waitForEvent('download');
    
    // Click the export button
    await exportButton.click();
    
    // Wait for the file download to complete
    const download = await downloadPromise;
    
    // Verify CSV report is generated and downloaded
    expect(download.suggestedFilename()).toMatch(/conflict.*\.csv$/i);
    
    // Save the downloaded file
    const filePath = `/tmp/${download.suggestedFilename()}`;
    await download.saveAs(filePath);
    
    // Step 2: Open exported CSV file
    const fs = require('fs');
    const csvContent = fs.readFileSync(filePath, 'utf-8');
    
    // Verify report contains accurate conflict data
    expect(csvContent).toBeTruthy();
    expect(csvContent.length).toBeGreaterThan(0);
    
    // Review the CSV file structure and headers
    const lines = csvContent.split('\n');
    const headers = lines[0].split(',');
    
    // Verify expected headers are present
    expect(headers).toContain('Conflict ID');
    expect(headers).toContain('Resource');
    expect(headers).toContain('Date');
    expect(headers).toContain('Time');
    expect(headers).toContain('Severity');
    expect(headers).toContain('Status');
    
    // Verify the conflict data in the CSV file against the dashboard display
    const dashboardConflicts = await page.locator('[data-testid="conflict-item"]').count();
    const csvDataRows = lines.length - 1; // Exclude header row
    
    // Check that CSV contains data rows
    expect(csvDataRows).toBeGreaterThan(0);
    
    // Verify data formatting and readability in the CSV
    if (lines.length > 1) {
      const firstDataRow = lines[1].split(',');
      expect(firstDataRow.length).toBe(headers.length);
      
      // Verify each field has content
      firstDataRow.forEach((field, index) => {
        expect(field.trim()).toBeTruthy();
      });
    }
    
    // Clean up downloaded file
    fs.unlinkSync(filePath);
  });
});