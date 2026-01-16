import { test, expect } from '@playwright/test';

test.describe('Conflict History - View and Analyze Scheduling Conflicts', () => {
  
  test.beforeEach(async ({ page }) => {
    // Login as authorized scheduler user before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify conflict history retrieval with filters (happy-path)', async ({ page }) => {
    // Step 1: Navigate to conflict history page by clicking on 'Conflict History' menu item
    await page.click('[data-testid="conflict-history-menu"]');
    await expect(page).toHaveURL(/.*\/conflicts\/history/);
    
    // Expected Result: Page loads with empty filter form
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="resource-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-type-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="apply-filters-button"]')).toBeVisible();
    
    // Step 2: Select start date as '01/01/2024' and end date as '01/31/2024' in date range filter
    await page.fill('[data-testid="start-date-input"]', '01/01/2024');
    await page.fill('[data-testid="end-date-input"]', '01/31/2024');
    
    // Step 3: Select a specific resource 'Conference Room A' from resource dropdown filter
    await page.click('[data-testid="resource-filter"]');
    await page.click('[data-testid="resource-option-conference-room-a"]');
    
    // Step 4: Click 'Apply Filters' button
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Filtered conflict records are displayed
    await expect(page.locator('[data-testid="conflict-results-table"]')).toBeVisible();
    await page.waitForSelector('[data-testid="conflict-record-row"]');
    
    // Step 5: Review the displayed conflict records in the results table
    const conflictRows = page.locator('[data-testid="conflict-record-row"]');
    const rowCount = await conflictRows.count();
    expect(rowCount).toBeGreaterThan(0);
    
    // Step 6: Verify each displayed record's date falls within selected range and resource matches filter
    for (let i = 0; i < rowCount; i++) {
      const row = conflictRows.nth(i);
      const dateText = await row.locator('[data-testid="conflict-date"]').textContent();
      const resourceText = await row.locator('[data-testid="conflict-resource"]').textContent();
      
      // Expected Result: Only relevant conflicts are shown
      expect(resourceText).toContain('Conference Room A');
      
      // Verify date is within range (basic validation)
      const conflictDate = new Date(dateText || '');
      const startDate = new Date('01/01/2024');
      const endDate = new Date('01/31/2024');
      expect(conflictDate.getTime()).toBeGreaterThanOrEqual(startDate.getTime());
      expect(conflictDate.getTime()).toBeLessThanOrEqual(endDate.getTime());
    }
  });

  test('Validate export functionality for conflict history (happy-path)', async ({ page }) => {
    // Step 1: Navigate to conflict history page
    await page.click('[data-testid="conflict-history-menu"]');
    await expect(page).toHaveURL(/.*\/conflicts\/history/);
    
    // Step 2: Apply date range filter from '01/01/2024' to '01/15/2024'
    await page.fill('[data-testid="start-date-input"]', '01/01/2024');
    await page.fill('[data-testid="end-date-input"]', '01/15/2024');
    
    // Step 3: Select conflict type 'Resource Double Booking' from type filter dropdown
    await page.click('[data-testid="conflict-type-filter"]');
    await page.click('[data-testid="conflict-type-option-resource-double-booking"]');
    
    // Step 4: Click 'Apply Filters' button
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Filtered results displayed
    await expect(page.locator('[data-testid="conflict-results-table"]')).toBeVisible();
    await page.waitForSelector('[data-testid="conflict-record-row"]');
    
    // Step 5: Click 'Export to CSV' button
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const downloadCSV = await downloadPromiseCSV;
    
    // Expected Result: CSV file is downloaded with correct data
    expect(downloadCSV.suggestedFilename()).toContain('.csv');
    expect(downloadCSV.suggestedFilename()).toContain('conflict');
    
    // Step 6: Open downloaded CSV file in spreadsheet application (verify download completed)
    const csvPath = await downloadCSV.path();
    expect(csvPath).toBeTruthy();
    
    // Step 7: Return to conflict history page and click 'Export to PDF' button
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const downloadPDF = await downloadPromisePDF;
    
    // Expected Result: PDF file is downloaded with correct data
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    expect(downloadPDF.suggestedFilename()).toContain('conflict');
    
    // Step 8: Open downloaded PDF file in PDF reader (verify download completed)
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();
  });

  test('Ensure access control for conflict history (error-case)', async ({ page, context }) => {
    // Logout from scheduler account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*\/login/);
    
    // Step 1: Log in to the system using unauthorized user credentials (user without Scheduler role)
    await page.fill('[data-testid="username-input"]', 'regularuser@example.com');
    await page.fill('[data-testid="password-input"]', 'regularPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Attempt to navigate to conflict history page by entering URL '/conflicts/history' directly in browser
    await page.goto('/conflicts/history');
    
    // Expected Result: Access is denied with appropriate message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    const errorMessage = await page.locator('[data-testid="access-denied-message"]').textContent();
    expect(errorMessage).toMatch(/access denied|unauthorized|permission/i);
    
    // Step 3: Verify error message displayed on screen
    await expect(page.locator('[data-testid="error-container"]')).toBeVisible();
    
    // Step 4: Check main navigation menu for conflict history option
    const conflictHistoryMenuItem = page.locator('[data-testid="conflict-history-menu"]');
    await expect(conflictHistoryMenuItem).not.toBeVisible();
    
    // Step 5: Attempt to access conflict history API endpoint directly using GET /conflicts/history
    const response = await page.request.get('/conflicts/history');
    
    // Expected Result: API returns 403 Forbidden or 401 Unauthorized
    expect([401, 403]).toContain(response.status());
    
    const responseBody = await response.json();
    expect(responseBody.error || responseBody.message).toMatch(/unauthorized|forbidden|access denied/i);
  });

});