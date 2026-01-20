import { test, expect } from '@playwright/test';

test.describe('Approval History - Viewing and Audit Tracking', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const scheduleChangeRequestId = 'SCR-12345';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${baseURL}/login`);
  });

  test('Validate display of approval history for a schedule change request', async ({ page }) => {
    // Login as authorized approver
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule change requests list
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await expect(page.locator('[data-testid="schedule-requests-list"]')).toBeVisible();

    // Click on a specific schedule change request to open its details page
    await page.click(`[data-testid="request-item-${scheduleChangeRequestId}"]`);
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toContainText(scheduleChangeRequestId);

    // Click on the 'Approval History' tab
    await page.click('[data-testid="approval-history-tab"]');
    await expect(page.locator('[data-testid="approval-history-content"]')).toBeVisible();

    // Verify chronological list of approval actions is displayed
    const approvalHistoryList = page.locator('[data-testid="approval-history-list"]');
    await expect(approvalHistoryList).toBeVisible();

    // Verify approver names, decisions, comments, and timestamps are shown
    const firstApprovalEntry = page.locator('[data-testid="approval-entry-0"]');
    await expect(firstApprovalEntry.locator('[data-testid="approver-name"]')).toBeVisible();
    await expect(firstApprovalEntry.locator('[data-testid="approval-decision"]')).toBeVisible();
    await expect(firstApprovalEntry.locator('[data-testid="approval-comments"]')).toBeVisible();
    await expect(firstApprovalEntry.locator('[data-testid="approval-timestamp"]')).toBeVisible();

    // Verify all approval action details are visible and accurate
    const approverName = await firstApprovalEntry.locator('[data-testid="approver-name"]').textContent();
    const decision = await firstApprovalEntry.locator('[data-testid="approval-decision"]').textContent();
    const timestamp = await firstApprovalEntry.locator('[data-testid="approval-timestamp"]').textContent();

    expect(approverName).toBeTruthy();
    expect(decision).toMatch(/Approved|Rejected|Pending/);
    expect(timestamp).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/);

    // Verify history loads within 2 seconds
    const startTime = Date.now();
    await page.reload();
    await page.click('[data-testid="approval-history-tab"]');
    await expect(approvalHistoryList).toBeVisible();
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);
  });

  test('Test export of approval history report', async ({ page }) => {
    // Login as authorized approver
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule change request details
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await page.click(`[data-testid="request-item-${scheduleChangeRequestId}"]`);
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();

    // Click on the 'Approval History' tab
    await page.click('[data-testid="approval-history-tab"]');
    await expect(page.locator('[data-testid="approval-history-content"]')).toBeVisible();

    // Set up download listener
    const downloadPromise = page.waitForEvent('download');

    // Click the 'Export to PDF' button
    await page.click('[data-testid="export-pdf-button"]');

    // Wait for download to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/approval.*history.*\.pdf/i);

    // Verify PDF is generated and downloaded
    const path = await download.path();
    expect(path).toBeTruthy();

    // Verify download success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('PDF report generated successfully');
  });

  test('Verify access control for approval history - unauthorized user', async ({ page }) => {
    // Login as unauthorized user (without approval history access permissions)
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to navigate to schedule change request's approval history
    await page.goto(`${baseURL}/schedule-requests/${scheduleChangeRequestId}/approval-history`);

    // Verify access denied message is displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access denied|Unauthorized|You do not have permission/i);

    // Verify user is redirected or approval history is not accessible
    await expect(page.locator('[data-testid="approval-history-content"]')).not.toBeVisible();

    // Logout unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
  });

  test('Verify access control for approval history - authorized approver', async ({ page }) => {
    // Login as authorized approver with proper permissions
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule change request details page
    await page.click('[data-testid="schedule-change-requests-menu"]');
    await page.click(`[data-testid="request-item-${scheduleChangeRequestId}"]`);
    await expect(page.locator('[data-testid="request-details-page"]')).toBeVisible();

    // Click on the 'Approval History' tab
    await page.click('[data-testid="approval-history-tab"]');

    // Verify approval history is accessible
    await expect(page.locator('[data-testid="approval-history-content"]')).toBeVisible();
    await expect(page.locator('[data-testid="approval-history-list"]')).toBeVisible();

    // Verify no access denied message
    await expect(page.locator('[data-testid="access-denied-message"]')).not.toBeVisible();

    // Verify approval entries are displayed
    const approvalEntries = page.locator('[data-testid^="approval-entry-"]');
    await expect(approvalEntries.first()).toBeVisible();
  });
});