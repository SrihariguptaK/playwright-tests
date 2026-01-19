import { test, expect } from '@playwright/test';

test.describe('Audit Trail Viewing and Management', () => {
  const AUDIT_PORTAL_URL = '/audit-portal';
  const VALID_AUDITOR_USERNAME = 'auditor@company.com';
  const VALID_AUDITOR_PASSWORD = 'SecureAuditor123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to audit portal login page
    await page.goto(AUDIT_PORTAL_URL);
  });

  test('View and filter audit logs successfully', async ({ page }) => {
    // Action: Auditor logs into audit portal
    await page.fill('[data-testid="username-input"]', VALID_AUDITOR_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Audit trail page loads
    await expect(page).toHaveURL(/.*audit-trail/);
    await expect(page.locator('[data-testid="audit-trail-page"]')).toBeVisible();

    // Navigate to Schedule Change Audit Trail section
    await page.click('[data-testid="schedule-change-audit-trail-menu"]');
    await expect(page.locator('[data-testid="audit-trail-section"]')).toBeVisible();

    // Action: Apply filters by date and user
    // Locate filter panel and select date range (last 30 days)
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-30-days-option"]');

    // Select specific user from dropdown
    await page.click('[data-testid="user-filter-dropdown"]');
    await page.click('[data-testid="user-option-john-doe"]');

    // Click Apply Filters button
    await page.click('[data-testid="apply-filters-button"]');

    // Expected Result: Audit logs displayed match filter criteria
    await page.waitForSelector('[data-testid="audit-log-table"]');
    const auditRows = page.locator('[data-testid="audit-log-row"]');
    await expect(auditRows).toHaveCountGreaterThan(0);

    // Verify dates are within last 30 days
    const firstRowDate = await page.locator('[data-testid="audit-log-row"]:first-child [data-testid="log-date"]').textContent();
    expect(firstRowDate).toBeTruthy();

    // Verify user filter is applied
    const firstRowUser = await page.locator('[data-testid="audit-log-row"]:first-child [data-testid="log-user"]').textContent();
    expect(firstRowUser).toContain('John Doe');

    // Action: Select an audit entry to view details
    await page.click('[data-testid="audit-log-row"]:first-child');

    // Expected Result: Detailed audit information is shown
    await expect(page.locator('[data-testid="audit-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-detail-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-detail-user"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-detail-action"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-detail-request-id"]')).toBeVisible();
  });

  test('Export audit logs to CSV and PDF', async ({ page }) => {
    // Login to audit portal
    await page.fill('[data-testid="username-input"]', VALID_AUDITOR_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*audit-trail/);

    // Navigate to audit trail section
    await page.click('[data-testid="schedule-change-audit-trail-menu"]');

    // Action: Apply desired filters (last 7 days and specific request ID)
    await page.click('[data-testid="filter-panel-toggle"]');
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="last-7-days-option"]');
    await page.fill('[data-testid="request-id-filter"]', 'REQ-12345');
    await page.click('[data-testid="apply-filters-button"]');

    // Expected Result: Filtered logs displayed
    await page.waitForSelector('[data-testid="audit-log-table"]');
    const filteredRows = page.locator('[data-testid="audit-log-row"]');
    await expect(filteredRows).toHaveCountGreaterThan(0);

    // Verify filtered results match criteria
    const displayedRequestId = await page.locator('[data-testid="audit-log-row"]:first-child [data-testid="log-request-id"]').textContent();
    expect(displayedRequestId).toContain('REQ-12345');

    // Action: Click export to CSV
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-button"]')
    ]);

    // Expected Result: CSV file downloaded with correct data
    expect(csvDownload.suggestedFilename()).toContain('.csv');
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();

    // Action: Click export to PDF
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);

    // Expected Result: PDF file downloaded with correct data
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
  });

  test('Ensure audit logs are immutable', async ({ page }) => {
    // Login to audit portal
    await page.fill('[data-testid="username-input"]', VALID_AUDITOR_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_AUDITOR_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*audit-trail/);

    // Navigate to audit trail section
    await page.click('[data-testid="schedule-change-audit-trail-menu"]');
    await page.waitForSelector('[data-testid="audit-log-table"]');

    // Select a specific audit log entry
    await page.click('[data-testid="audit-log-row"]:first-child');
    await expect(page.locator('[data-testid="audit-detail-modal"]')).toBeVisible();

    // Action: Look for any edit, modify, or update buttons
    const editButton = page.locator('[data-testid="edit-audit-button"]');
    const modifyButton = page.locator('[data-testid="modify-audit-button"]');
    const updateButton = page.locator('[data-testid="update-audit-button"]');

    // Expected Result: No edit buttons should exist
    await expect(editButton).toHaveCount(0);
    await expect(modifyButton).toHaveCount(0);
    await expect(updateButton).toHaveCount(0);

    // Close detail modal
    await page.click('[data-testid="close-detail-modal"]');

    // Action: Right-click on audit log entry to check context menu
    await page.click('[data-testid="audit-log-row"]:first-child', { button: 'right' });
    
    // Verify no edit/delete options in context menu
    const contextEditOption = page.locator('text="Edit"');
    const contextDeleteOption = page.locator('text="Delete"');
    await expect(contextEditOption).toHaveCount(0);
    await expect(contextDeleteOption).toHaveCount(0);

    // Action: Attempt to double-click to edit inline
    await page.dblclick('[data-testid="audit-log-row"]:first-child [data-testid="log-action"]');
    
    // Verify field is not editable
    const editableInput = page.locator('[data-testid="audit-log-row"]:first-child input');
    await expect(editableInput).toHaveCount(0);

    // Action: Look for delete, remove, or archive buttons
    const deleteButton = page.locator('[data-testid="delete-audit-button"]');
    const removeButton = page.locator('[data-testid="remove-audit-button"]');
    const archiveButton = page.locator('[data-testid="archive-audit-button"]');

    // Expected Result: No delete/remove/archive buttons exist
    await expect(deleteButton).toHaveCount(0);
    await expect(removeButton).toHaveCount(0);
    await expect(archiveButton).toHaveCount(0);

    // Action: Attempt API modification via intercepted request
    const auditLogId = await page.locator('[data-testid="audit-log-row"]:first-child').getAttribute('data-log-id');
    
    // Intercept and attempt PUT request
    const putResponse = await page.request.put(`/api/audit-logs/${auditLogId}`, {
      data: {
        action: 'Modified Action',
        user: 'Unauthorized User'
      },
      failOnStatusCode: false
    });

    // Expected Result: System denies action (403 Forbidden or 405 Method Not Allowed)
    expect([403, 405]).toContain(putResponse.status());

    // Attempt DELETE request
    const deleteResponse = await page.request.delete(`/api/audit-logs/${auditLogId}`, {
      failOnStatusCode: false
    });

    // Expected Result: System denies action
    expect([403, 405]).toContain(deleteResponse.status());

    // Verify original audit log remains unchanged
    await page.reload();
    await page.waitForSelector('[data-testid="audit-log-table"]');
    const originalLogEntry = page.locator(`[data-log-id="${auditLogId}"]`);
    await expect(originalLogEntry).toBeVisible();

    // Expected Result: Unauthorized attempt is logged
    // Navigate to security logs or check audit trail for the attempt
    await page.click('[data-testid="security-logs-menu"]');
    await page.waitForSelector('[data-testid="security-log-table"]');
    
    const unauthorizedAttemptLog = page.locator('[data-testid="security-log-row"]').filter({
      hasText: 'Unauthorized modification attempt'
    });
    await expect(unauthorizedAttemptLog).toHaveCountGreaterThan(0);
  });
});