import { test, expect } from '@playwright/test';

test.describe('Approver Filter and Sort Schedule Change Requests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the pending requests dashboard before each test
    await page.goto('/approvals/pending');
    await page.waitForLoadState('networkidle');
  });

  test('Validate filtering by status and date range', async ({ page }) => {
    // Locate and click on the status filter dropdown
    await page.click('[data-testid="status-filter-dropdown"]');
    
    // Select 'Pending' status from the dropdown
    await page.click('[data-testid="status-option-pending"]');
    
    // Locate the date range filter and click on the 'From Date' field
    await page.click('[data-testid="from-date-field"]');
    
    // Select a specific start date (e.g., first day of current month)
    const currentDate = new Date();
    const firstDayOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
    const fromDate = firstDayOfMonth.toISOString().split('T')[0];
    await page.fill('[data-testid="from-date-field"]', fromDate);
    
    // Click on the 'To Date' field
    await page.click('[data-testid="to-date-field"]');
    
    // Select a specific end date (e.g., last day of current month)
    const lastDayOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
    const toDate = lastDayOfMonth.toISOString().split('T')[0];
    await page.fill('[data-testid="to-date-field"]', toDate);
    
    // Click 'Apply Filter' button
    await page.click('[data-testid="apply-filter-button"]');
    
    // Wait for the request list to update
    await page.waitForResponse(response => 
      response.url().includes('/approvals/pending') && response.status() === 200
    );
    
    // Verify each displayed request has 'Pending' status
    const statusCells = await page.locator('[data-testid="request-status"]').all();
    for (const cell of statusCells) {
      const statusText = await cell.textContent();
      expect(statusText?.trim()).toBe('Pending');
    }
    
    // Verify each displayed request falls within the selected date range
    const dateCells = await page.locator('[data-testid="request-submission-date"]').all();
    for (const cell of dateCells) {
      const dateText = await cell.textContent();
      const requestDate = new Date(dateText?.trim() || '');
      expect(requestDate.getTime()).toBeGreaterThanOrEqual(firstDayOfMonth.getTime());
      expect(requestDate.getTime()).toBeLessThanOrEqual(lastDayOfMonth.getTime());
    }
  });

  test('Validate sorting by priority and submission date', async ({ page }) => {
    // Locate the 'Priority' column header and click on it to sort
    await page.click('[data-testid="priority-column-header"]');
    
    // Wait for sorting to complete
    await page.waitForTimeout(500);
    
    // Verify the first 3 requests displayed have 'High' priority
    const firstThreePriorities = await page.locator('[data-testid="request-priority"]').first().locator('xpath=../..').locator('[data-testid="request-priority"]').nth(0).textContent();
    const secondPriority = await page.locator('[data-testid="request-priority"]').nth(1).textContent();
    const thirdPriority = await page.locator('[data-testid="request-priority"]').nth(2).textContent();
    
    expect(firstThreePriorities?.trim()).toBe('High');
    expect(secondPriority?.trim()).toBe('High');
    expect(thirdPriority?.trim()).toBe('High');
    
    // Scroll down and verify requests with 'Low' priority appear at the bottom
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(300);
    
    const lastPriority = await page.locator('[data-testid="request-priority"]').last().textContent();
    expect(lastPriority?.trim()).toBe('Low');
    
    // Locate the 'Submission Date' column header and click on it
    await page.click('[data-testid="submission-date-column-header"]');
    
    // Wait for sorting to complete
    await page.waitForTimeout(500);
    
    // Verify the first request has the oldest submission date
    const firstDate = await page.locator('[data-testid="request-submission-date"]').first().textContent();
    const firstDateObj = new Date(firstDate?.trim() || '');
    
    // Scroll to the bottom and verify the last request has the most recent submission date
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(300);
    
    const lastDate = await page.locator('[data-testid="request-submission-date"]').last().textContent();
    const lastDateObj = new Date(lastDate?.trim() || '');
    
    expect(firstDateObj.getTime()).toBeLessThan(lastDateObj.getTime());
    
    // Click on 'Submission Date' column header again to reverse sort
    await page.click('[data-testid="submission-date-column-header"]');
    await page.waitForTimeout(500);
    
    // Verify sort order is reversed
    const newFirstDate = await page.locator('[data-testid="request-submission-date"]').first().textContent();
    const newFirstDateObj = new Date(newFirstDate?.trim() || '');
    
    expect(newFirstDateObj.getTime()).toBeGreaterThanOrEqual(firstDateObj.getTime());
  });

  test('Validate saving and applying filter presets', async ({ page }) => {
    // Apply filter for 'Pending' status
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-pending"]');
    
    // Apply date range filter for current month
    const currentDate = new Date();
    const firstDayOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
    const lastDayOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
    
    await page.fill('[data-testid="from-date-field"]', firstDayOfMonth.toISOString().split('T')[0]);
    await page.fill('[data-testid="to-date-field"]', lastDayOfMonth.toISOString().split('T')[0]);
    await page.click('[data-testid="apply-filter-button"]');
    
    // Wait for filters to apply
    await page.waitForResponse(response => 
      response.url().includes('/approvals/pending') && response.status() === 200
    );
    
    // Sort the filtered results by priority descending
    await page.click('[data-testid="priority-column-header"]');
    await page.waitForTimeout(500);
    
    // Locate and click on 'Save Filter Preset' button or icon
    await page.click('[data-testid="save-filter-preset-button"]');
    
    // Enter preset name 'Current Month High Priority' in the name field
    await page.fill('[data-testid="preset-name-field"]', 'Current Month High Priority');
    
    // Click 'Save' button in the preset dialog
    await page.click('[data-testid="save-preset-confirm-button"]');
    
    // Wait for success confirmation
    await expect(page.locator('[data-testid="preset-saved-message"]')).toBeVisible();
    
    // Clear all current filters by clicking 'Clear Filters' or 'Reset' button
    await page.click('[data-testid="clear-filters-button"]');
    
    // Wait for filters to clear
    await page.waitForTimeout(500);
    
    // Verify the request list shows all requests without any filters
    const allRequests = await page.locator('[data-testid="request-row"]').count();
    expect(allRequests).toBeGreaterThan(0);
    
    // Verify no filter indicators are shown
    await expect(page.locator('[data-testid="active-filter-indicator"]')).not.toBeVisible();
    
    // Locate and click on 'Saved Presets' dropdown or button
    await page.click('[data-testid="saved-presets-dropdown"]');
    
    // Select 'Current Month High Priority' preset from the list
    await page.click('[data-testid="preset-option-current-month-high-priority"]');
    
    // Wait for preset to apply
    await page.waitForResponse(response => 
      response.url().includes('/approvals/pending') && response.status() === 200
    );
    
    // Verify filter indicators show 'Pending' status and current month date range
    await expect(page.locator('[data-testid="status-filter-indicator"]')).toContainText('Pending');
    await expect(page.locator('[data-testid="date-range-filter-indicator"]')).toBeVisible();
    
    // Verify sort indicator shows priority descending
    await expect(page.locator('[data-testid="priority-sort-indicator"]')).toHaveAttribute('data-sort-direction', 'desc');
    
    // Verify the request list matches the previously saved filter criteria
    const filteredRequests = await page.locator('[data-testid="request-row"]').all();
    for (const request of filteredRequests) {
      const status = await request.locator('[data-testid="request-status"]').textContent();
      expect(status?.trim()).toBe('Pending');
      
      const dateText = await request.locator('[data-testid="request-submission-date"]').textContent();
      const requestDate = new Date(dateText?.trim() || '');
      expect(requestDate.getTime()).toBeGreaterThanOrEqual(firstDayOfMonth.getTime());
      expect(requestDate.getTime()).toBeLessThanOrEqual(lastDayOfMonth.getTime());
    }
  });
});