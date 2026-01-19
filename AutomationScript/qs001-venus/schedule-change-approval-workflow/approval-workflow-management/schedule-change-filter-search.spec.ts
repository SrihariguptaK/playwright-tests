import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Filtering and Search', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to approval dashboard before each test
    await page.goto('/approval-dashboard');
    await expect(page).toHaveURL(/.*approval-dashboard/);
  });

  test('Filter schedule change requests by status and date', async ({ page }) => {
    // Approver locates the status filter dropdown and selects 'Pending'
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-pending"]');
    
    // Approver locates the date range filter and selects 'Last 7 days'
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-7-days"]');
    
    // Approver clicks 'Apply Filters' button
    const startTime = Date.now();
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for filtered results to load
    await page.waitForSelector('[data-testid="schedule-requests-list"]');
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    // Verify response time is within 2 seconds
    expect(responseTime).toBeLessThan(2000);
    
    // Verify filtered list displays only matching requests
    const requestRows = page.locator('[data-testid="request-row"]');
    const rowCount = await requestRows.count();
    expect(rowCount).toBeGreaterThan(0);
    
    // Verify each row has 'Pending' status
    for (let i = 0; i < rowCount; i++) {
      const statusCell = requestRows.nth(i).locator('[data-testid="request-status"]');
      await expect(statusCell).toHaveText('Pending');
    }
    
    // Verify date is within last 7 days
    const currentDate = new Date();
    const sevenDaysAgo = new Date(currentDate.getTime() - 7 * 24 * 60 * 60 * 1000);
    
    for (let i = 0; i < Math.min(rowCount, 3); i++) {
      const dateCell = requestRows.nth(i).locator('[data-testid="request-date"]');
      const dateText = await dateCell.textContent();
      const requestDate = new Date(dateText || '');
      expect(requestDate.getTime()).toBeGreaterThanOrEqual(sevenDaysAgo.getTime());
    }
    
    // Approver clicks 'Clear Filters' button
    await page.click('[data-testid="clear-filters-button"]');
    
    // Verify full list of requests is displayed
    await page.waitForSelector('[data-testid="schedule-requests-list"]');
    const allRequestRows = page.locator('[data-testid="request-row"]');
    const allRowCount = await allRequestRows.count();
    expect(allRowCount).toBeGreaterThanOrEqual(rowCount);
  });

  test('Search schedule change requests by keyword', async ({ page }) => {
    // Approver locates the search box and clicks inside it
    const searchBox = page.locator('[data-testid="search-box"]');
    await searchBox.click();
    
    // Approver types the keyword 'maintenance' into the search box
    await searchBox.fill('maintenance');
    
    // Approver presses Enter key or clicks the search icon button
    const startTime = Date.now();
    await page.keyboard.press('Enter');
    
    // Wait for search results to load
    await page.waitForSelector('[data-testid="schedule-requests-list"]');
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    // Verify response time is within 2 seconds
    expect(responseTime).toBeLessThan(2000);
    
    // Verify requests containing 'maintenance' are displayed
    const requestRows = page.locator('[data-testid="request-row"]');
    const rowCount = await requestRows.count();
    expect(rowCount).toBeGreaterThan(0);
    
    // Verify each displayed request contains the keyword 'maintenance'
    for (let i = 0; i < rowCount; i++) {
      const requestDetails = requestRows.nth(i).locator('[data-testid="request-details"]');
      const detailsText = await requestDetails.textContent();
      expect(detailsText?.toLowerCase()).toContain('maintenance');
    }
    
    // Approver clicks 'Clear Search' button or deletes text from search box
    await searchBox.clear();
    await page.keyboard.press('Enter');
    
    // Verify full list of requests is displayed
    await page.waitForSelector('[data-testid="schedule-requests-list"]');
    const allRequestRows = page.locator('[data-testid="request-row"]');
    const allRowCount = await allRequestRows.count();
    expect(allRowCount).toBeGreaterThanOrEqual(rowCount);
  });

  test('Save and reuse filter presets', async ({ page }) => {
    // Approver applies multiple filters: status 'Pending' and priority 'High'
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-pending"]');
    
    await page.click('[data-testid="priority-filter-dropdown"]');
    await page.click('[data-testid="priority-option-high"]');
    
    // Approver clicks 'Apply Filters' button to view filtered results
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForSelector('[data-testid="schedule-requests-list"]');
    
    // Store the filtered results count for later verification
    const initialRequestRows = page.locator('[data-testid="request-row"]');
    const initialRowCount = await initialRequestRows.count();
    expect(initialRowCount).toBeGreaterThan(0);
    
    // Approver clicks 'Save Preset' button
    await page.click('[data-testid="save-preset-button"]');
    
    // Approver enters preset name 'Urgent Requests' in the name field
    const presetNameInput = page.locator('[data-testid="preset-name-input"]');
    await presetNameInput.fill('Urgent Requests');
    
    // Approver clicks 'Save' button in the preset dialog
    await page.click('[data-testid="save-preset-confirm-button"]');
    
    // Verify preset saved successfully
    await expect(page.locator('[data-testid="preset-saved-message"]')).toBeVisible();
    
    // Approver clicks 'Clear Filters' to reset the view
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForSelector('[data-testid="schedule-requests-list"]');
    
    // Verify filters are cleared
    const allRequestRows = page.locator('[data-testid="request-row"]');
    const allRowCount = await allRequestRows.count();
    expect(allRowCount).toBeGreaterThanOrEqual(initialRowCount);
    
    // Approver locates the saved presets dropdown and selects 'Urgent Requests'
    await page.click('[data-testid="saved-presets-dropdown"]');
    await page.click('[data-testid="preset-urgent-requests"]');
    
    // Approver clicks 'Load Preset' or 'Apply' button
    await page.click('[data-testid="load-preset-button"]');
    await page.waitForSelector('[data-testid="schedule-requests-list"]');
    
    // Verify loaded preset displays the same filtered results
    const loadedRequestRows = page.locator('[data-testid="request-row"]');
    const loadedRowCount = await loadedRequestRows.count();
    expect(loadedRowCount).toBe(initialRowCount);
    
    // Verify filters are applied correctly
    for (let i = 0; i < loadedRowCount; i++) {
      const statusCell = loadedRequestRows.nth(i).locator('[data-testid="request-status"]');
      await expect(statusCell).toHaveText('Pending');
      
      const priorityCell = loadedRequestRows.nth(i).locator('[data-testid="request-priority"]');
      await expect(priorityCell).toHaveText('High');
    }
  });
});