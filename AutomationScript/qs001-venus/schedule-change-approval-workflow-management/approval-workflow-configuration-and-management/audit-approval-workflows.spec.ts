import { test, expect } from '@playwright/test';

test.describe('Audit Approval Workflows and Decisions', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
  });

  test('Validate audit logs record workflow configuration changes', async ({ page }) => {
    // Login as Administrator
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Administrator navigates to workflow configuration page
    await page.click('[data-testid="workflow-config-menu"]');
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();

    // Administrator selects an existing workflow 'Schedule Change Approval Process' and clicks 'Edit'
    await page.click('text=Schedule Change Approval Process');
    await page.click('[data-testid="edit-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-editor"]')).toBeVisible();

    // Administrator modifies the workflow by changing step 2 approver from 'Department Head' to 'Senior Manager' role
    await page.click('[data-testid="workflow-step-2"]');
    await page.click('[data-testid="approver-role-dropdown"]');
    await page.click('text=Senior Manager');
    await expect(page.locator('[data-testid="workflow-step-2"]')).toContainText('Senior Manager');

    // Administrator clicks 'Save Changes' button
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');

    // Expected Result: Audit log entry is created with user and timestamp
    // Administrator navigates to the audit log viewer module from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="audit-log-menu-item"]');
    await expect(page.locator('[data-testid="audit-log-viewer"]')).toBeVisible();

    // Administrator applies filter for 'Workflow Configuration' event type and current date
    await page.click('[data-testid="event-type-filter"]');
    await page.click('text=Workflow Configuration');
    await page.click('[data-testid="date-filter"]');
    await page.click('text=Today');
    await page.click('[data-testid="apply-filters-button"]');

    // Administrator locates the most recent audit entry for 'Schedule Change Approval Process' workflow
    const auditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(auditEntry).toContainText('Schedule Change Approval Process');
    await expect(auditEntry).toContainText('Workflow Configuration');
    await expect(auditEntry).toContainText('admin@company.com');

    // Administrator clicks on the audit entry to view full details
    await auditEntry.click();
    const auditDetails = page.locator('[data-testid="audit-details-modal"]');
    await expect(auditDetails).toBeVisible();
    await expect(auditDetails).toContainText('Step 2 approver changed');
    await expect(auditDetails).toContainText('Department Head');
    await expect(auditDetails).toContainText('Senior Manager');
    await expect(auditDetails).toContainText('admin@company.com');

    // Expected Result: Relevant audit entries are displayed
    const timestamp = auditDetails.locator('[data-testid="audit-timestamp"]');
    await expect(timestamp).toBeVisible();
  });

  test('Verify audit logs record approval decisions and comments', async ({ page }) => {
    // Login as Approver
    await page.fill('[data-testid="username-input"]', 'approver@company.com');
    await page.fill('[data-testid="password-input"]', 'ApproverPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Approver navigates to pending approvals queue
    await page.click('[data-testid="pending-approvals-menu"]');
    await expect(page.locator('[data-testid="pending-approvals-queue"]')).toBeVisible();

    // Approver selects a pending schedule change request and clicks 'Review'
    const pendingRequest = page.locator('[data-testid="pending-request"]').first();
    const requestId = await pendingRequest.getAttribute('data-request-id');
    await pendingRequest.click();
    await page.click('[data-testid="review-button"]');
    await expect(page.locator('[data-testid="review-modal"]')).toBeVisible();

    // Approver enters comment in the comments field
    await page.fill('[data-testid="approval-comment-field"]', 'Approved due to business critical requirement. Verified with department head.');

    // Approver clicks 'Approve' button
    await page.click('[data-testid="approve-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Request approved successfully');

    // Expected Result: Audit log entry is created
    // Log out approver and log in with Administrator credentials
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Administrator navigates to audit log viewer module
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="audit-log-menu-item"]');
    await expect(page.locator('[data-testid="audit-log-viewer"]')).toBeVisible();

    // Administrator applies filter for 'Approval Decision' event type and selects the specific request ID
    await page.click('[data-testid="event-type-filter"]');
    await page.click('text=Approval Decision');
    await page.fill('[data-testid="request-id-filter"]', requestId || '');
    await page.click('[data-testid="apply-filters-button"]');

    // Administrator reviews the audit entry for the approval decision
    const approvalAuditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(approvalAuditEntry).toContainText('Approval Decision');
    await expect(approvalAuditEntry).toContainText('approver@company.com');
    await approvalAuditEntry.click();

    const auditDetails = page.locator('[data-testid="audit-details-modal"]');
    await expect(auditDetails).toBeVisible();
    await expect(auditDetails).toContainText('Approved due to business critical requirement. Verified with department head.');
    await page.click('[data-testid="close-modal-button"]');

    // Administrator selects 'Export' option and chooses 'PDF' format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-dropdown"]');
    await page.click('text=PDF');

    // Administrator clicks 'Generate Report' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="generate-report-button"]');
    const download = await downloadPromise;
    await expect(download.suggestedFilename()).toContain('.pdf');

    // Expected Result: Audit report is generated in PDF format
    // Administrator opens the downloaded PDF file (simulated by verifying download)
    await download.saveAs('./downloads/' + download.suggestedFilename());

    // Administrator returns to audit log viewer and selects 'Export' with 'CSV' format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-dropdown"]');
    await page.click('text=CSV');

    const csvDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="generate-report-button"]');
    const csvDownload = await csvDownloadPromise;
    await expect(csvDownload.suggestedFilename()).toContain('.csv');

    // Administrator opens the CSV file in spreadsheet application (simulated by verifying download)
    await csvDownload.saveAs('./downloads/' + csvDownload.suggestedFilename());
  });

  test('Ensure only administrators can access audit logs', async ({ page }) => {
    // Login as Non-admin user
    await page.fill('[data-testid="username-input"]', 'user@company.com');
    await page.fill('[data-testid="password-input"]', 'UserPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Non-admin user attempts to navigate to audit log viewer module by entering URL directly
    await page.goto('/audit-logs');

    // Expected Result: Access is denied
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('You do not have permission to access this resource');

    // System displays error message to the user
    await expect(page.locator('[data-testid="error-page"]')).toBeVisible();

    // Non-admin user attempts to access audit logs API endpoint directly
    const apiResponse = await page.request.get('/api/audit-logs');
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody.error).toContain('Forbidden');

    // Non-admin user attempts to access audit export functionality directly
    const exportResponse = await page.request.post('/api/audit-logs/export', {
      data: { format: 'PDF' }
    });
    expect(exportResponse.status()).toBe(403);

    // Verify the access denial attempt is logged
    // Log out non-admin user and log in with Administrator credentials
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Administrator navigates to audit log viewer module
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="audit-log-menu-item"]');
    await expect(page.locator('[data-testid="audit-log-viewer"]')).toBeVisible();

    // Administrator verifies the unauthorized access attempt is logged in security audit
    await page.click('[data-testid="event-type-filter"]');
    await page.click('text=Security');
    await page.click('[data-testid="date-filter"]');
    await page.click('text=Today');
    await page.click('[data-testid="apply-filters-button"]');

    const securityAuditEntry = page.locator('[data-testid="audit-entry"]').filter({ hasText: 'Unauthorized Access Attempt' }).first();
    await expect(securityAuditEntry).toBeVisible();
    await expect(securityAuditEntry).toContainText('user@company.com');
    await expect(securityAuditEntry).toContainText('audit-logs');

    await securityAuditEntry.click();
    const auditDetails = page.locator('[data-testid="audit-details-modal"]');
    await expect(auditDetails).toBeVisible();
    await expect(auditDetails).toContainText('Access Denied');
    await expect(auditDetails).toContainText('user@company.com');
    await expect(auditDetails).toContainText('/audit-logs');
  });
});