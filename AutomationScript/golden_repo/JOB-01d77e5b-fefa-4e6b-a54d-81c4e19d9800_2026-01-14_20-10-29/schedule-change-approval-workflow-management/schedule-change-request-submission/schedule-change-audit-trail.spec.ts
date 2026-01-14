import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Audit Trail', () => {
  test.beforeEach(async ({ page }) => {
    // Login as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate audit trail display for schedule change requests (happy-path)', async ({ page }) => {
    // Employee navigates to the schedule change requests section from the main dashboard
    await page.click('[data-testid="schedule-change-requests-menu"]');
    
    // Expected Result: List of requests is displayed
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-item"]').first()).toBeVisible();
    
    // Employee selects a specific schedule change request from the list by clicking on it
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    await firstRequest.click();
    
    // Expected Result: Request details page is displayed
    await expect(page.locator('[data-testid="request-details-container"]')).toBeVisible();
    
    // Employee views the audit trail section on the request details page
    await page.click('[data-testid="audit-trail-tab"]');
    
    // Expected Result: Complete chronological history with comments and status changes is displayed
    const auditTrailSection = page.locator('[data-testid="audit-trail-section"]');
    await expect(auditTrailSection).toBeVisible();
    
    // Employee verifies the timestamps are in chronological order from oldest to newest
    const auditEntries = page.locator('[data-testid="audit-entry"]');
    const entryCount = await auditEntries.count();
    expect(entryCount).toBeGreaterThan(0);
    
    const timestamps = await auditEntries.locator('[data-testid="audit-timestamp"]').allTextContents();
    for (let i = 0; i < timestamps.length - 1; i++) {
      const currentTime = new Date(timestamps[i]).getTime();
      const nextTime = new Date(timestamps[i + 1]).getTime();
      expect(currentTime).toBeLessThanOrEqual(nextTime);
    }
    
    // Employee checks that all status changes are reflected in the audit trail
    const statusChanges = page.locator('[data-testid="audit-entry"][data-type="status-change"]');
    await expect(statusChanges.first()).toBeVisible();
    await expect(statusChanges.first()).toContainText(/Status changed|Submitted|Approved|Rejected/);
    
    // Employee reviews approver comments in the audit trail
    const approverComments = page.locator('[data-testid="audit-entry"][data-type="comment"]');
    if (await approverComments.count() > 0) {
      await expect(approverComments.first()).toBeVisible();
      await expect(approverComments.first().locator('[data-testid="comment-text"]')).not.toBeEmpty();
    }
    
    // Employee verifies the audit trail loaded within acceptable time (3 seconds)
    const loadTime = await page.evaluate(() => performance.now());
    expect(loadTime).toBeLessThan(3000);
  });

  test('Verify export of audit trail (happy-path)', async ({ page }) => {
    // Employee navigates to their schedule change requests list
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();
    
    // Employee selects a specific request to view its details
    const firstRequest = page.locator('[data-testid="request-item"]').first();
    const requestId = await firstRequest.getAttribute('data-request-id');
    await firstRequest.click();
    
    // Employee views the audit trail section for the selected request
    await page.click('[data-testid="audit-trail-tab"]');
    await expect(page.locator('[data-testid="audit-trail-section"]')).toBeVisible();
    
    // Employee locates and verifies the export option is available in the audit trail section
    const exportButton = page.locator('[data-testid="export-audit-trail-button"]');
    await expect(exportButton).toBeVisible();
    await expect(exportButton).toBeEnabled();
    
    // Employee clicks on the 'Export as PDF' button
    const downloadPromise = page.waitForEvent('download');
    await exportButton.click();
    
    // Employee waits for the PDF file to download to their device
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/audit.*\.pdf/);
    
    // Verify download completed successfully
    const path = await download.path();
    expect(path).toBeTruthy();
    
    // Expected Result: PDF file downloads and contains complete audit information
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 5000 });
  });

  test('Ensure access control for audit trail (error-case)', async ({ page, context }) => {
    // Get Employee A's request ID first
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();
    const employeeARequestId = await page.locator('[data-testid="request-item"]').first().getAttribute('data-request-id');
    
    // Logout current employee
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Employee B logs into the system with their valid credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employeeB@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Employee B verifies they cannot see Employee A's request in their own request list
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();
    const employeeBRequests = page.locator('[data-testid="request-item"]');
    const requestIds = await employeeBRequests.evaluateAll((elements) => 
      elements.map(el => el.getAttribute('data-request-id'))
    );
    expect(requestIds).not.toContain(employeeARequestId);
    
    // Employee B attempts to access the audit trail of Employee A's schedule change request by directly navigating to the URL
    const response = await page.goto(`/api/schedule-change-requests/${employeeARequestId}/audit`);
    
    // Expected Result: Access is denied with error message
    expect(response?.status()).toBe(403);
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/Access denied|Unauthorized|You do not have permission/);
    
    // Employee B attempts to access through UI navigation
    await page.goto(`/schedule-change-requests/${employeeARequestId}`);
    
    // Employee B verifies they are redirected or remain on an error page without access to sensitive information
    await expect(page.locator('[data-testid="access-denied-page"]').or(page.locator('[data-testid="error-page"]'))).toBeVisible();
    await expect(page.locator('[data-testid="audit-trail-section"]')).not.toBeVisible();
    
    // Verify no sensitive information is displayed
    const pageContent = await page.textContent('body');
    expect(pageContent).not.toContain('audit trail');
    expect(pageContent).not.toContain('approver comment');
  });
});