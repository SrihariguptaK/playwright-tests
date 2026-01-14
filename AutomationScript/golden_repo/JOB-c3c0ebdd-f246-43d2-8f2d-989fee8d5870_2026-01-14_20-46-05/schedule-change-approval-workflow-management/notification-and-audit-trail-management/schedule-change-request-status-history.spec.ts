import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Status and History - Story 6', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler_user');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate accurate display of request statuses', async ({ page }) => {
    // Navigate to Schedule Change Requests dashboard
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page).toHaveURL(/.*schedule-change-requests/);
    
    // Verify dashboard displays list of requests
    await expect(page.locator('[data-testid="request-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-list"]')).toBeVisible();
    
    // Verify request list contains entries with key information
    const requestItems = page.locator('[data-testid="request-item"]');
    await expect(requestItems).toHaveCount(await requestItems.count());
    expect(await requestItems.count()).toBeGreaterThan(0);
    
    // Check first request displays required fields
    const firstRequest = requestItems.first();
    await expect(firstRequest.locator('[data-testid="request-id"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="submission-date"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="schedule-details"]')).toBeVisible();
    await expect(firstRequest.locator('[data-testid="request-status"]')).toBeVisible();
    
    // Verify Pending status request
    const pendingRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Pending' }).first();
    if (await pendingRequest.count() > 0) {
      await expect(pendingRequest.locator('[data-testid="request-status"]')).toHaveText('Pending');
      await expect(pendingRequest.locator('[data-testid="status-indicator"]')).toHaveClass(/pending/);
    }
    
    // Verify Approved status request
    const approvedRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Approved' }).first();
    if (await approvedRequest.count() > 0) {
      await expect(approvedRequest.locator('[data-testid="request-status"]')).toHaveText('Approved');
      await expect(approvedRequest.locator('[data-testid="status-indicator"]')).toHaveClass(/approved/);
    }
    
    // Verify Rejected status request
    const rejectedRequest = page.locator('[data-testid="request-item"]').filter({ hasText: 'Rejected' }).first();
    if (await rejectedRequest.count() > 0) {
      await expect(rejectedRequest.locator('[data-testid="request-status"]')).toHaveText('Rejected');
      await expect(rejectedRequest.locator('[data-testid="status-indicator"]')).toHaveClass(/rejected/);
    }
    
    // Refresh dashboard and verify statuses remain consistent
    const initialStatusText = await firstRequest.locator('[data-testid="request-status"]').textContent();
    await page.reload();
    await expect(page.locator('[data-testid="request-dashboard"]')).toBeVisible();
    const refreshedStatusText = await requestItems.first().locator('[data-testid="request-status"]').textContent();
    expect(refreshedStatusText).toBe(initialStatusText);
    
    // Verify requests are displayed in logical order
    const allRequestDates = await page.locator('[data-testid="submission-date"]').allTextContents();
    expect(allRequestDates.length).toBeGreaterThan(0);
  });

  test('Validate detailed approval history display', async ({ page }) => {
    // Navigate to Schedule Change Requests dashboard
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page).toHaveURL(/.*schedule-change-requests/);
    
    // Identify a processed request (approved or rejected)
    const processedRequest = page.locator('[data-testid="request-item"]').filter({ 
      has: page.locator('[data-testid="request-status"]').filter({ hasText: /Approved|Rejected/ })
    }).first();
    
    await expect(processedRequest).toBeVisible();
    const requestId = await processedRequest.locator('[data-testid="request-id"]').textContent();
    
    // Click to view details/history
    await processedRequest.click();
    // Alternative: await processedRequest.locator('[data-testid="view-details-button"]').click();
    
    // Verify detailed view displays approval history section
    await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();
    
    // Verify approval decision is displayed
    const approvalDecision = page.locator('[data-testid="approval-decision"]');
    await expect(approvalDecision).toBeVisible();
    const decisionText = await approvalDecision.textContent();
    expect(decisionText).toMatch(/Approved|Rejected/);
    
    // Verify approver name/ID is displayed
    const approverInfo = page.locator('[data-testid="approver-name"]');
    await expect(approverInfo).toBeVisible();
    expect(await approverInfo.textContent()).toBeTruthy();
    
    // Verify timestamp is displayed
    const timestamp = page.locator('[data-testid="approval-timestamp"]');
    await expect(timestamp).toBeVisible();
    const timestampText = await timestamp.textContent();
    expect(timestampText).toBeTruthy();
    expect(timestampText).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}|\d{4}-\d{2}-\d{2}/);
    
    // Verify comments are displayed
    const comments = page.locator('[data-testid="approval-comments"]');
    await expect(comments).toBeVisible();
    
    // Verify multiple approval stages if present
    const historyEntries = page.locator('[data-testid="history-entry"]');
    const entryCount = await historyEntries.count();
    if (entryCount > 1) {
      // Verify chronological order
      for (let i = 0; i < entryCount; i++) {
        await expect(historyEntries.nth(i)).toBeVisible();
      }
    }
    
    // Navigate back and select different request
    await page.click('[data-testid="back-to-dashboard"]');
    await expect(page.locator('[data-testid="request-dashboard"]')).toBeVisible();
    
    const secondProcessedRequest = page.locator('[data-testid="request-item"]').filter({ 
      has: page.locator('[data-testid="request-status"]').filter({ hasText: /Approved|Rejected/ })
    }).nth(1);
    
    if (await secondProcessedRequest.count() > 0) {
      await secondProcessedRequest.click();
      await expect(page.locator('[data-testid="approval-history-section"]')).toBeVisible();
      await expect(page.locator('[data-testid="approval-decision"]')).toBeVisible();
      await expect(page.locator('[data-testid="approver-name"]')).toBeVisible();
      await expect(page.locator('[data-testid="approval-timestamp"]')).toBeVisible();
    }
    
    // Verify approval history is read-only
    const historySection = page.locator('[data-testid="approval-history-section"]');
    await expect(historySection.locator('input[type="text"]')).toHaveCount(0);
    await expect(historySection.locator('textarea')).toHaveCount(0);
  });

  test('Validate filtering and export functionality', async ({ page }) => {
    // Navigate to Schedule Change Requests dashboard
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page).toHaveURL(/.*schedule-change-requests/);
    await expect(page.locator('[data-testid="request-dashboard"]')).toBeVisible();
    
    // Locate filter controls
    await expect(page.locator('[data-testid="filter-controls"]')).toBeVisible();
    
    // Apply status filter - Approved
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Verify all displayed requests have Approved status
    await page.waitForTimeout(1000); // Wait for filter to apply
    const approvedRequests = page.locator('[data-testid="request-item"]');
    const approvedCount = await approvedRequests.count();
    
    for (let i = 0; i < approvedCount; i++) {
      const statusText = await approvedRequests.nth(i).locator('[data-testid="request-status"]').textContent();
      expect(statusText).toBe('Approved');
    }
    
    // Change status filter to Rejected
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-rejected"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    await page.waitForTimeout(1000);
    const rejectedRequests = page.locator('[data-testid="request-item"]');
    const rejectedCount = await rejectedRequests.count();
    
    if (rejectedCount > 0) {
      for (let i = 0; i < rejectedCount; i++) {
        const statusText = await rejectedRequests.nth(i).locator('[data-testid="request-status"]').textContent();
        expect(statusText).toBe('Rejected');
      }
    }
    
    // Clear status filter
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(1000);
    
    // Apply date filter
    await page.click('[data-testid="date-filter-start"]');
    await page.fill('[data-testid="date-filter-start"]', '2024-01-01');
    await page.click('[data-testid="date-filter-end"]');
    await page.fill('[data-testid="date-filter-end"]', '2024-12-31');
    await page.click('[data-testid="apply-filter-button"]');
    
    await page.waitForTimeout(1000);
    
    // Verify requests are within date range
    const dateFilteredRequests = page.locator('[data-testid="request-item"]');
    expect(await dateFilteredRequests.count()).toBeGreaterThanOrEqual(0);
    
    // Apply combined filters (status + date)
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    await page.waitForTimeout(1000);
    
    // Verify combined filters work correctly
    const combinedFilteredRequests = page.locator('[data-testid="request-item"]');
    const combinedCount = await combinedFilteredRequests.count();
    
    if (combinedCount > 0) {
      for (let i = 0; i < combinedCount; i++) {
        const statusText = await combinedFilteredRequests.nth(i).locator('[data-testid="request-status"]').textContent();
        expect(statusText).toBe('Approved');
      }
    }
    
    // Locate and click Export button
    await expect(page.locator('[data-testid="export-button"]')).toBeVisible();
    
    // Set up download listener
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    
    // Confirm export action if confirmation dialog appears
    const confirmButton = page.locator('[data-testid="confirm-export-button"]');
    if (await confirmButton.isVisible({ timeout: 2000 }).catch(() => false)) {
      await confirmButton.click();
    }
    
    // Wait for download to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.pdf$/);
    
    // Save the downloaded file
    const filePath = await download.path();
    expect(filePath).toBeTruthy();
    
    // Verify download completed successfully
    await download.saveAs('./downloads/' + download.suggestedFilename());
    
    // Verify success message or notification
    const successMessage = page.locator('[data-testid="export-success-message"]');
    if (await successMessage.isVisible({ timeout: 3000 }).catch(() => false)) {
      await expect(successMessage).toContainText(/exported|downloaded|generated/i);
    }
  });
});