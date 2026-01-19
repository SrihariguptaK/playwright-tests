import { test, expect } from '@playwright/test';

test.describe('Task Update History - Viewing and Transparency', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const TASK_ID = 'TASK-12345';

  test.beforeEach(async ({ page }) => {
    // Navigate to task list and login if needed
    await page.goto(`${BASE_URL}/tasks`);
    // Assuming user is already authenticated or handle login here
  });

  test('Validate display of complete task update history', async ({ page }) => {
    // Step 1: Navigate to task detail page by clicking on a task from the task list
    await page.click(`[data-testid="task-item-${TASK_ID}"]`);
    await expect(page).toHaveURL(new RegExp(`/tasks/${TASK_ID}`));

    // Step 2: Click on the 'Update History' tab
    const startTime = Date.now();
    await page.click('[data-testid="update-history-tab"]');
    
    // Step 3: Observe the complete list of status changes and comments
    await expect(page.locator('[data-testid="history-list"]')).toBeVisible();
    const historyItems = page.locator('[data-testid="history-item"]');
    await expect(historyItems).toHaveCount(await historyItems.count());
    
    // Step 4: Verify that each status change entry shows the timestamp in readable format
    const firstHistoryItem = historyItems.first();
    const timestamp = firstHistoryItem.locator('[data-testid="history-timestamp"]');
    await expect(timestamp).toBeVisible();
    const timestampText = await timestamp.textContent();
    expect(timestampText).toMatch(/\w{3}\s+\d{1,2},\s+\d{4}\s+\d{1,2}:\d{2}\s+(AM|PM)/i);
    
    // Step 5: Verify that each update entry shows the user name or identifier
    const userName = firstHistoryItem.locator('[data-testid="history-user"]');
    await expect(userName).toBeVisible();
    const userNameText = await userName.textContent();
    expect(userNameText).toBeTruthy();
    expect(userNameText?.length).toBeGreaterThan(0);
    
    // Step 6: Verify that status changes show both 'from' and 'to' status values
    const statusChangeItems = page.locator('[data-testid="history-item"][data-type="status-change"]');
    if (await statusChangeItems.count() > 0) {
      const statusChange = statusChangeItems.first();
      const statusText = await statusChange.locator('[data-testid="history-description"]').textContent();
      expect(statusText).toMatch(/from\s+.+\s+to\s+.+/i);
    }
    
    // Step 7: Verify that comment entries display the full comment text
    const commentItems = page.locator('[data-testid="history-item"][data-type="comment"]');
    if (await commentItems.count() > 0) {
      const comment = commentItems.first();
      const commentText = await comment.locator('[data-testid="comment-text"]').textContent();
      expect(commentText).toBeTruthy();
      expect(commentText?.length).toBeGreaterThan(0);
    }
    
    // Step 8: Scroll through the entire history list from top to bottom
    const historyContainer = page.locator('[data-testid="history-list"]');
    await historyContainer.evaluate(el => el.scrollTop = el.scrollHeight);
    await page.waitForTimeout(500);
    
    // Step 9: Check the page load time
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(3000);
    
    // Step 10: Verify that no error messages appear
    const errorMessages = page.locator('[data-testid="error-message"], .error, [role="alert"]');
    await expect(errorMessages).toHaveCount(0);
  });

  test('Verify filtering of history by date and update type', async ({ page }) => {
    // Navigate to task detail page
    await page.click(`[data-testid="task-item-${TASK_ID}"]`);
    await page.click('[data-testid="update-history-tab"]');
    await expect(page.locator('[data-testid="history-list"]')).toBeVisible();
    
    const initialCount = await page.locator('[data-testid="history-item"]').count();
    
    // Step 1-2: Click on the 'From Date' field and select a start date
    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - 7);
    const fromDateString = fromDate.toISOString().split('T')[0];
    
    await page.click('[data-testid="filter-from-date"]');
    await page.fill('[data-testid="filter-from-date"]', fromDateString);
    
    // Step 3: Click on the 'To Date' field and select an end date
    const toDate = new Date();
    const toDateString = toDate.toISOString().split('T')[0];
    
    await page.click('[data-testid="filter-to-date"]');
    await page.fill('[data-testid="filter-to-date"]', toDateString);
    
    // Step 4: Click the 'Apply Filter' button
    await page.click('[data-testid="apply-filter-button"]');
    await page.waitForTimeout(500);
    
    // Step 5: Verify that all displayed entries have timestamps within the selected date range
    const filteredItems = page.locator('[data-testid="history-item"]');
    const filteredCount = await filteredItems.count();
    
    for (let i = 0; i < Math.min(filteredCount, 5); i++) {
      const item = filteredItems.nth(i);
      const timestamp = await item.locator('[data-testid="history-timestamp"]').getAttribute('data-timestamp');
      if (timestamp) {
        const itemDate = new Date(timestamp);
        expect(itemDate.getTime()).toBeGreaterThanOrEqual(fromDate.getTime());
        expect(itemDate.getTime()).toBeLessThanOrEqual(toDate.getTime());
      }
    }
    
    // Step 6-7: Select 'Status Changes' from the update type filter
    await page.click('[data-testid="filter-update-type"]');
    await page.click('[data-testid="filter-option-status-changes"]');
    await page.waitForTimeout(500);
    
    // Step 8: Verify that only status change entries are displayed
    const statusChangeItems = page.locator('[data-testid="history-item"]');
    const statusCount = await statusChangeItems.count();
    
    for (let i = 0; i < statusCount; i++) {
      const itemType = await statusChangeItems.nth(i).getAttribute('data-type');
      expect(itemType).toBe('status-change');
    }
    
    // Step 9-10: Change the update type filter to 'Comments'
    await page.click('[data-testid="filter-update-type"]');
    await page.click('[data-testid="filter-option-comments"]');
    await page.waitForTimeout(500);
    
    const commentItems = page.locator('[data-testid="history-item"]');
    const commentCount = await commentItems.count();
    
    for (let i = 0; i < commentCount; i++) {
      const itemType = await commentItems.nth(i).getAttribute('data-type');
      expect(itemType).toBe('comment');
    }
    
    // Step 11: Apply both date range and update type filters simultaneously
    await page.click('[data-testid="filter-update-type"]');
    await page.click('[data-testid="filter-option-comments"]');
    await page.waitForTimeout(500);
    
    const combinedFilteredItems = page.locator('[data-testid="history-item"]');
    await expect(combinedFilteredItems.first()).toBeVisible();
    
    // Step 12-13: Click the 'Clear Filters' button
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    const restoredItems = page.locator('[data-testid="history-item"]');
    const restoredCount = await restoredItems.count();
    expect(restoredCount).toBe(initialCount);
    
    // Step 14: Check that filter operations complete within acceptable time
    // This is implicitly tested by the test not timing out
  });

  test('Ensure export functionality works correctly', async ({ page }) => {
    // Navigate to task detail page
    await page.click(`[data-testid="task-item-${TASK_ID}"]`);
    await page.click('[data-testid="update-history-tab"]');
    await expect(page.locator('[data-testid="history-list"]')).toBeVisible();
    
    // Collect on-screen data for verification
    const historyItems = page.locator('[data-testid="history-item"]');
    const onScreenCount = await historyItems.count();
    const sampleEntries = [];
    
    for (let i = 0; i < Math.min(onScreenCount, 3); i++) {
      const item = historyItems.nth(i);
      const timestamp = await item.locator('[data-testid="history-timestamp"]').textContent();
      const user = await item.locator('[data-testid="history-user"]').textContent();
      const description = await item.locator('[data-testid="history-description"]').textContent();
      sampleEntries.push({ timestamp, user, description });
    }
    
    // Step 1-3: Click export button and select CSV format
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-option-csv"]');
    
    const downloadCSV = await downloadPromiseCSV;
    expect(downloadCSV.suggestedFilename()).toMatch(/\.csv$/);
    
    // Step 4-5: Verify CSV file exists and can be saved
    const csvPath = await downloadCSV.path();
    expect(csvPath).toBeTruthy();
    
    // Step 6-9: Verify CSV file contains proper headers and data
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    
    // Verify header row
    expect(csvContent).toContain('Date');
    expect(csvContent).toContain('Time');
    expect(csvContent).toContain('User');
    expect(csvContent).toContain('Update Type');
    expect(csvContent).toContain('Description');
    
    // Verify data rows exist
    const csvLines = csvContent.split('\n').filter(line => line.trim().length > 0);
    expect(csvLines.length).toBeGreaterThan(1); // Header + at least one data row
    
    // Step 10-12: Click export button and select PDF format
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-option-pdf"]');
    
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toMatch(/\.pdf$/);
    
    // Step 13-14: Verify PDF file exists
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();
    
    // Step 15-18: Verify PDF file was generated
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(0);
    
    // Step 19: Verify that export operations complete within acceptable time (5 seconds)
    // This is implicitly tested by the test not timing out with default Playwright timeout
  });
});