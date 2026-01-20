import { test, expect } from '@playwright/test';

test.describe('Approver Schedule Change Request Filtering and Searching', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to pending approvals dashboard before each test
    await page.goto('/approvals/pending');
    await page.waitForLoadState('networkidle');
  });

  test('Validate filtering by status and date range', async ({ page }) => {
    // Step 1: Locate and click on the status filter dropdown
    await page.click('[data-testid="status-filter-dropdown"]');
    
    // Step 2: Select 'Pending' from the status filter dropdown
    await page.click('[data-testid="status-option-pending"]');
    
    // Step 3: Locate and click on the date range filter, select 'Last 7 days' option
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-7-days"]');
    
    // Step 4: Click 'Apply Filters' button
    await page.click('[data-testid="apply-filters-button"]');
    
    // Wait for filtered results to load
    await page.waitForResponse(response => 
      response.url().includes('/api/approvals/pending') && response.status() === 200
    );
    
    // Step 5: Verify each displayed request matches the filter criteria
    const requestRows = await page.locator('[data-testid="request-row"]').all();
    expect(requestRows.length).toBeGreaterThan(0);
    
    for (const row of requestRows) {
      // Verify status is 'Pending'
      const status = await row.locator('[data-testid="request-status"]').textContent();
      expect(status?.trim()).toBe('Pending');
      
      // Verify submission date is within last 7 days
      const submissionDate = await row.locator('[data-testid="submission-date"]').textContent();
      const dateValue = new Date(submissionDate || '');
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      expect(dateValue.getTime()).toBeGreaterThanOrEqual(sevenDaysAgo.getTime());
    }
    
    // Step 6: Click 'Clear Filters' button
    await page.click('[data-testid="clear-filters-button"]');
    
    // Step 7: Verify full list of pending approvals displayed
    await page.waitForLoadState('networkidle');
    const allRequestRows = await page.locator('[data-testid="request-row"]').all();
    expect(allRequestRows.length).toBeGreaterThanOrEqual(requestRows.length);
  });

  test('Test keyword search functionality', async ({ page }) => {
    // Step 1: Locate the keyword search input field
    const searchInput = page.locator('[data-testid="keyword-search-input"]');
    await expect(searchInput).toBeVisible();
    
    // Step 2: Enter a keyword that exists in at least one request's details
    const existingKeyword = 'vacation';
    await searchInput.fill(existingKeyword);
    
    // Step 3: Press Enter or click 'Search' button
    await page.click('[data-testid="search-button"]');
    
    // Wait for search results
    await page.waitForResponse(response => 
      response.url().includes('/api/approvals/pending') && response.status() === 200
    );
    
    // Step 4: Verify that all displayed requests contain the searched keyword
    const matchingRows = await page.locator('[data-testid="request-row"]').all();
    expect(matchingRows.length).toBeGreaterThan(0);
    
    for (const row of matchingRows) {
      const requestDetails = await row.locator('[data-testid="request-details"]').textContent();
      expect(requestDetails?.toLowerCase()).toContain(existingKeyword.toLowerCase());
    }
    
    // Step 5: Clear the search field and enter a keyword that does not exist
    await searchInput.clear();
    const nonExistentKeyword = 'xyzabc123nonexistent';
    await searchInput.fill(nonExistentKeyword);
    
    // Step 6: Press Enter or click 'Search' button
    await page.click('[data-testid="search-button"]');
    
    // Wait for search results
    await page.waitForLoadState('networkidle');
    
    // Step 7: Verify no results displayed
    const noResultsMessage = page.locator('[data-testid="no-results-message"]');
    await expect(noResultsMessage).toBeVisible();
    
    const noResultsRows = await page.locator('[data-testid="request-row"]').count();
    expect(noResultsRows).toBe(0);
    
    // Step 8: Clear the search field
    await searchInput.clear();
  });

  test('Verify sorting of filtered results', async ({ page }) => {
    // Step 1: Apply any filter (e.g., status 'Pending') to create a filtered result set
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-pending"]');
    await page.click('[data-testid="apply-filters-button"]');
    
    await page.waitForResponse(response => 
      response.url().includes('/api/approvals/pending') && response.status() === 200
    );
    
    // Step 2: Locate the 'Submission Date' column header and click to sort descending
    await page.click('[data-testid="submission-date-header"]');
    await page.waitForLoadState('networkidle');
    
    // Step 3: Verify the order by checking submission dates of first and last visible requests
    let requestRows = await page.locator('[data-testid="request-row"]').all();
    if (requestRows.length > 1) {
      const firstDate = await requestRows[0].locator('[data-testid="submission-date"]').textContent();
      const lastDate = await requestRows[requestRows.length - 1].locator('[data-testid="submission-date"]').textContent();
      
      const firstDateTime = new Date(firstDate || '').getTime();
      const lastDateTime = new Date(lastDate || '').getTime();
      
      expect(firstDateTime).toBeGreaterThanOrEqual(lastDateTime);
    }
    
    // Step 4: Click on 'Submission Date' column header again to toggle sort to ascending
    await page.click('[data-testid="submission-date-header"]');
    await page.waitForLoadState('networkidle');
    
    requestRows = await page.locator('[data-testid="request-row"]').all();
    if (requestRows.length > 1) {
      const firstDate = await requestRows[0].locator('[data-testid="submission-date"]').textContent();
      const lastDate = await requestRows[requestRows.length - 1].locator('[data-testid="submission-date"]').textContent();
      
      const firstDateTime = new Date(firstDate || '').getTime();
      const lastDateTime = new Date(lastDate || '').getTime();
      
      expect(firstDateTime).toBeLessThanOrEqual(lastDateTime);
    }
    
    // Step 5: Locate the 'Priority' column header and click to sort ascending
    await page.click('[data-testid="priority-header"]');
    await page.waitForLoadState('networkidle');
    
    // Step 6: Verify the order by checking priority values of displayed requests
    requestRows = await page.locator('[data-testid="request-row"]').all();
    if (requestRows.length > 1) {
      const priorities: number[] = [];
      for (const row of requestRows) {
        const priorityText = await row.locator('[data-testid="request-priority"]').textContent();
        priorities.push(parseInt(priorityText || '0'));
      }
      
      // Verify ascending order
      for (let i = 0; i < priorities.length - 1; i++) {
        expect(priorities[i]).toBeLessThanOrEqual(priorities[i + 1]);
      }
    }
    
    // Step 7: Click on 'Priority' column header again to toggle sort to descending
    await page.click('[data-testid="priority-header"]');
    await page.waitForLoadState('networkidle');
    
    requestRows = await page.locator('[data-testid="request-row"]').all();
    if (requestRows.length > 1) {
      const priorities: number[] = [];
      for (const row of requestRows) {
        const priorityText = await row.locator('[data-testid="request-priority"]').textContent();
        priorities.push(parseInt(priorityText || '0'));
      }
      
      // Verify descending order
      for (let i = 0; i < priorities.length - 1; i++) {
        expect(priorities[i]).toBeGreaterThanOrEqual(priorities[i + 1]);
      }
    }
  });
});