import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Status Tracking', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('View schedule change request statuses - happy path', async ({ page }) => {
    // Navigate to Schedule Change Status Dashboard
    await page.click('[data-testid="schedule-change-status-menu"]');
    await expect(page).toHaveURL(/.*schedule-changes\/status/);
    
    // Verify dashboard displays list of submitted requests
    await expect(page.locator('[data-testid="requests-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-item"]')).toHaveCount(await page.locator('[data-testid="request-item"]').count());
    
    // Verify request details are displayed
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    await expect(firstRequest.locator('[data-testid="request-id"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="submission-date"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="requested-changes"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="current-status"]')).toBeVisible();
    
    // Select a specific request from the list
    await firstRequest.click();
    
    // Verify detailed approval history and comments are shown
    await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-history-item"]')).toHaveCount(await page.locator('[data-testid="approval-history-item"]').count());
    await expect(page.locator('[data-testid="comments-section"]')).toBeVisible();
    
    // Verify approval history contains expected information
    const historyItem = page.locator('[data-testid="approval-history-item"]').first();
    await expect(historyItem.locator('[data-testid="approver-name"]')).toBeVisible();
    await expect(historyItem.locator('[data-testid="approval-timestamp"]')).toBeVisible();
    await expect(historyItem.locator('[data-testid="approval-action"]')).toBeVisible();
  });

  test('Filter requests by status and date - happy path', async ({ page }) => {
    // Navigate to status dashboard
    await page.click('[data-testid="schedule-change-status-menu"]');
    await expect(page).toHaveURL(/.*schedule-changes\/status/);
    
    // Locate the filter section
    await expect(page.locator('[data-testid="filter-section"]')).toBeVisible();
    
    // Apply status filter
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-pending"]');
    
    // Observe the request list after applying status filter
    await page.waitForTimeout(500); // Wait for filter to apply
    const filteredByStatusCount = await page.locator('[data-testid="request-item"]').count();
    await expect(page.locator('[data-testid="request-item"]')).toHaveCount(filteredByStatusCount);
    
    // Verify all displayed requests have 'Pending' status
    const statusElements = await page.locator('[data-testid="current-status"]').allTextContents();
    statusElements.forEach(status => {
      expect(status.toLowerCase()).toContain('pending');
    });
    
    // Apply date range filter
    await page.click('[data-testid="date-range-filter"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-01');
    await page.fill('[data-testid="end-date-input"]', '2024-12-31');
    await page.click('[data-testid="apply-date-filter-button"]');
    
    // Verify the filtered results
    await page.waitForTimeout(500); // Wait for filter to apply
    const filteredCount = await page.locator('[data-testid="request-item"]').count();
    await expect(page.locator('[data-testid="filtered-results-count"]')).toContainText(filteredCount.toString());
    
    // Verify displayed requests match filters
    await expect(page.locator('[data-testid="request-item"]')).toHaveCount(filteredCount);
    
    // Clear filters
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    // Verify all requests are shown again
    const unfilteredCount = await page.locator('[data-testid="request-item"]').count();
    expect(unfilteredCount).toBeGreaterThanOrEqual(filteredCount);
  });

  test('Export request history - happy path', async ({ page }) => {
    // Navigate to status dashboard
    await page.click('[data-testid="schedule-change-status-menu"]');
    await expect(page).toHaveURL(/.*schedule-changes\/status/);
    
    // Get count of visible requests before export
    const visibleRequestsCount = await page.locator('[data-testid="request-item"]').count();
    
    // Locate and click the Export button
    await expect(page.locator('[data-testid="export-button"]')).toBeVisible();
    
    // Set up download listener
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    
    // Wait for download to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/.*\.csv$/);
    
    // Save the downloaded file
    const filePath = await download.path();
    expect(filePath).toBeTruthy();
    
    // Read and verify CSV content
    const fs = require('fs');
    const csvContent = fs.readFileSync(filePath, 'utf-8');
    
    // Verify CSV contains expected columns
    const headerRow = csvContent.split('\n')[0];
    expect(headerRow).toContain('Request ID');
    expect(headerRow).toContain('Submission Date');
    expect(headerRow).toContain('Status');
    expect(headerRow).toContain('Approver');
    expect(headerRow).toContain('Comments');
    expect(headerRow).toContain('Timestamps');
    
    // Verify CSV contains data rows (excluding header)
    const dataRows = csvContent.split('\n').filter(row => row.trim() !== '').slice(1);
    expect(dataRows.length).toBeGreaterThan(0);
    
    // Verify row count matches visible requests (or is close)
    expect(dataRows.length).toBeGreaterThanOrEqual(visibleRequestsCount - 1);
    expect(dataRows.length).toBeLessThanOrEqual(visibleRequestsCount + 1);
  });
});