import { test, expect } from '@playwright/test';

test.describe('Story-16: Audit Schedule Change Approvals', () => {
  const approverCredentials = {
    username: 'approver.user@company.com',
    password: 'ApproverPass123!'
  };

  const adminCredentials = {
    username: 'admin.user@company.com',
    password: 'AdminPass123!'
  };

  const nonAdminCredentials = {
    username: 'regular.employee@company.com',
    password: 'EmployeePass123!'
  };

  test('Verify audit log records approval actions accurately (happy-path)', async ({ page }) => {
    // Log in as an approver user with valid credentials
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', approverCredentials.username);
    await page.fill('[data-testid="password-input"]', approverCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/\/dashboard/);

    // Navigate to the schedule change requests list and select a pending request
    await page.click('[data-testid="schedule-changes-menu"]');
    await page.waitForSelector('[data-testid="schedule-requests-list"]');
    await page.click('[data-testid="pending-request-item"]:first-child');
    await expect(page.locator('[data-testid="request-details"]')).toBeVisible();

    // Add approval comments in the comments field
    const approvalComment = 'Approved for operational requirements';
    await page.fill('[data-testid="approval-comments-field"]', approvalComment);

    // Click the 'Approve' button to perform the approval action
    const approvalTimestamp = new Date().toISOString();
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="approval-success-message"]')).toBeVisible();

    // Log out from the approver account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/\/login/);

    // Log in as an administrator user with audit log access permissions
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/\/dashboard/);

    // Navigate to the audit portal/audit logs section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page).toHaveURL(/\/admin\/audit-logs/);

    // Search for the approval action using the approver username and timestamp
    await page.fill('[data-testid="search-user-input"]', approverCredentials.username);
    await page.fill('[data-testid="search-date-input"]', approvalTimestamp.split('T')[0]);
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]');

    // Click on the audit log entry to view detailed information
    await page.click('[data-testid="audit-log-entry"]:first-child');
    await expect(page.locator('[data-testid="audit-log-details"]')).toBeVisible();

    // Verify all metadata fields are complete and accurate
    await expect(page.locator('[data-testid="audit-user-field"]')).toContainText(approverCredentials.username);
    await expect(page.locator('[data-testid="audit-timestamp-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-comments-field"]')).toContainText(approvalComment);
    await expect(page.locator('[data-testid="audit-action-type-field"]')).toContainText('Approval');

    // Click on 'Export' or 'Generate Report' button and select CSV format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');
    
    // Confirm the CSV export and download the file
    const csvDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const csvDownload = await csvDownloadPromise;
    expect(csvDownload.suggestedFilename()).toContain('.csv');

    // Return to audit logs interface and click 'Export' button, this time selecting PDF format
    await page.click('[data-testid="back-to-audit-logs"]');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Confirm the PDF export and download the file
    const pdfDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const pdfDownload = await pdfDownloadPromise;
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
  });

  test('Restrict audit log access to administrators (error-case)', async ({ page, request }) => {
    // Log in as a non-administrator user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/\/dashboard/);

    // Attempt to navigate to the audit logs section by entering the audit portal URL directly
    await page.goto('/admin/audit-logs');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access.*denied|Unauthorized|Permission/);

    // Check the main navigation menu for any audit log or audit portal links
    await page.goto('/dashboard');
    const adminMenuExists = await page.locator('[data-testid="admin-menu"]').count();
    expect(adminMenuExists).toBe(0);
    const auditLogsLinkExists = await page.locator('[data-testid="audit-logs-link"]').count();
    expect(auditLogsLinkExists).toBe(0);

    // Attempt to access audit logs via API endpoint directly using non-admin user's authentication token
    const cookies = await page.context().cookies();
    const authToken = cookies.find(cookie => cookie.name === 'auth_token')?.value || '';
    
    const apiResponse = await request.get('/api/audit-logs', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error || responseBody.message).toMatch(/Access.*denied|Unauthorized|Forbidden/);

    // Log out from the non-administrator account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/\/login/);

    // Log in as an administrator user with proper audit log access permissions
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/\/dashboard/);

    // Check the main navigation menu for audit log or audit portal links
    await expect(page.locator('[data-testid="admin-menu"]')).toBeVisible();
    await page.click('[data-testid="admin-menu"]');
    await expect(page.locator('[data-testid="audit-logs-link"]')).toBeVisible();

    // Click on the audit logs link to navigate to the audit portal
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page).toHaveURL(/\/admin\/audit-logs/);

    // Verify all audit log features are accessible: search functionality, filter options, and view details
    await expect(page.locator('[data-testid="search-user-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="search-date-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="filter-action-type"]')).toBeVisible();
    await expect(page.locator('[data-testid="search-button"]')).toBeVisible();

    // Perform a search operation on audit logs using date filter
    const searchDate = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="search-date-input"]', searchDate);
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="audit-log-results"]');

    // Click on an audit log entry to view detailed information
    const auditEntryCount = await page.locator('[data-testid="audit-log-entry"]').count();
    if (auditEntryCount > 0) {
      await page.click('[data-testid="audit-log-entry"]:first-child');
      await expect(page.locator('[data-testid="audit-log-details"]')).toBeVisible();
      await expect(page.locator('[data-testid="audit-user-field"]')).toBeVisible();
      await expect(page.locator('[data-testid="audit-timestamp-field"]')).toBeVisible();
    }

    // Test export functionality by clicking 'Export' button and selecting CSV format
    await page.click('[data-testid="back-to-audit-logs"]');
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-csv-option"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-pdf-option"]')).toBeVisible();

    // Verify administrator can access audit logs via API endpoint using admin authentication token
    const adminCookies = await page.context().cookies();
    const adminAuthToken = adminCookies.find(cookie => cookie.name === 'auth_token')?.value || '';
    
    const adminApiResponse = await request.get('/api/audit-logs', {
      headers: {
        'Authorization': `Bearer ${adminAuthToken}`
      }
    });
    expect(adminApiResponse.status()).toBe(200);
    const adminResponseBody = await adminApiResponse.json();
    expect(Array.isArray(adminResponseBody) || adminResponseBody.data).toBeTruthy();
  });
});