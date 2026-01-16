import { test, expect } from '@playwright/test';

test.describe('Audit Approval Workflows and Actions', () => {
  test.beforeEach(async ({ page }) => {
    // Administrator logs into audit portal
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate audit logging of workflow configuration changes (happy-path)', async ({ page }) => {
    // Administrator navigates to workflow configuration page
    await page.click('[data-testid="workflow-config-menu"]');
    await expect(page).toHaveURL(/.*workflow-configuration/);

    // Administrator selects an existing workflow to modify
    await page.click('[data-testid="workflow-list-item"]:has-text("Schedule Approval")');
    await expect(page.locator('[data-testid="workflow-name-input"]')).toBeVisible();

    // Administrator modifies workflow name from 'Schedule Approval' to 'Schedule Change Approval'
    await page.fill('[data-testid="workflow-name-input"]', 'Schedule Change Approval');

    // Administrator adds a new approval stage to the workflow
    await page.click('[data-testid="add-approval-stage-button"]');
    await page.fill('[data-testid="stage-name-input"]', 'Final Review Stage');
    await page.selectOption('[data-testid="approver-select"]', 'senior-manager');

    // Administrator clicks 'Save' button to save the modified workflow
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');

    // Expected Result: Audit log entry created with user and timestamp
    await page.waitForTimeout(1000); // Allow time for audit log to be created

    // Administrator navigates to audit logs section from the admin portal menu
    await page.click('[data-testid="admin-portal-menu"]');
    await page.click('[data-testid="audit-logs-menu-item"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Administrator searches audit logs for workflow configuration changes using workflow name 'Schedule Change Approval'
    await page.fill('[data-testid="audit-search-input"]', 'Schedule Change Approval');
    await page.click('[data-testid="search-button"]');

    // Expected Result: Relevant entries are displayed accurately
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Schedule Change Approval');

    // Administrator reviews the most recent audit log entry
    const firstEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(firstEntry).toContainText('Workflow Modified');
    await expect(firstEntry.locator('[data-testid="audit-user"]')).toContainText('admin@example.com');
    await expect(firstEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();

    // Administrator clicks on the audit log entry to view detailed metadata
    await firstEntry.click();
    await expect(page.locator('[data-testid="audit-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-detail-workflow-name"]')).toContainText('Schedule Change Approval');
    await expect(page.locator('[data-testid="audit-detail-action"]')).toContainText('Workflow Modified');
    await expect(page.locator('[data-testid="audit-detail-changes"]')).toContainText('Final Review Stage');
    await page.click('[data-testid="close-detail-modal"]');

    // Administrator filters audit logs by action type 'Workflow Modified' and date range of today
    await page.selectOption('[data-testid="action-type-filter"]', 'Workflow Modified');
    await page.fill('[data-testid="date-from-filter"]', new Date().toISOString().split('T')[0]);
    await page.fill('[data-testid="date-to-filter"]', new Date().toISOString().split('T')[0]);
    await page.click('[data-testid="apply-filters-button"]');

    // Verify filtered results contain the workflow modification
    await expect(page.locator('[data-testid="audit-log-entry"]')).toHaveCount(1, { timeout: 5000 });
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Schedule Change Approval');
  });

  test('Verify audit log immutability (error-case)', async ({ page }) => {
    // Administrator navigates to audit logs section
    await page.click('[data-testid="admin-portal-menu"]');
    await page.click('[data-testid="audit-logs-menu-item"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Administrator selects an existing audit log entry
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
    const firstEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await firstEntry.click();

    // Administrator attempts to access edit functionality for the audit log entry
    // Expected Result: System prevents modification
    await expect(page.locator('[data-testid="edit-audit-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="audit-detail-modal"]')).not.toContainText('Edit');

    // Close detail modal
    await page.click('[data-testid="close-detail-modal"]');

    // Administrator attempts to use browser developer tools or direct API call to modify the audit log entry
    const auditLogId = await firstEntry.getAttribute('data-audit-id');
    const response = await page.request.put(`/api/audit-logs/${auditLogId}`, {
      data: {
        action: 'Modified Action',
        user: 'hacker@example.com'
      }
    });

    // Expected Result: System prevents modification and logs attempt
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Audit logs are immutable');

    // System logs the unauthorized modification attempt
    await page.reload();
    await page.fill('[data-testid="audit-search-input"]', 'unauthorized');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Unauthorized modification attempt');

    // Administrator attempts to delete an audit log entry through the UI
    await page.goto('/audit-logs');
    await firstEntry.click({ button: 'right' });
    await expect(page.locator('[data-testid="delete-option"]')).not.toBeVisible();

    // Administrator attempts to use direct API call to delete the audit log entry
    const deleteResponse = await page.request.delete(`/api/audit-logs/${auditLogId}`);

    // Expected Result: System prevents deletion and logs attempt
    expect(deleteResponse.status()).toBe(403);
    const deleteResponseBody = await deleteResponse.json();
    expect(deleteResponseBody.error).toContain('Audit logs cannot be deleted');

    // Administrator searches audit logs for unauthorized access attempts
    await page.fill('[data-testid="audit-search-input"]', 'unauthorized');
    await page.selectOption('[data-testid="action-type-filter"]', 'Unauthorized Access Attempt');
    await page.click('[data-testid="apply-filters-button"]');

    // Verify unauthorized attempts are logged
    await expect(page.locator('[data-testid="audit-log-entry"]')).toHaveCountGreaterThan(0);
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Unauthorized');
  });

  test('Test audit log export functionality (happy-path)', async ({ page }) => {
    // Administrator navigates to audit logs section
    await page.click('[data-testid="admin-portal-menu"]');
    await page.click('[data-testid="audit-logs-menu-item"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Administrator applies filters to select specific audit logs (e.g., date range: last 7 days, action type: Workflow Modified)
    const today = new Date();
    const sevenDaysAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    await page.fill('[data-testid="date-from-filter"]', sevenDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="date-to-filter"]', today.toISOString().split('T')[0]);
    await page.selectOption('[data-testid="action-type-filter"]', 'Workflow Modified');
    await page.click('[data-testid="apply-filters-button"]');

    // Wait for filtered results
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
    const displayedEntries = await page.locator('[data-testid="audit-log-entry"]').count();
    const sampleEntryText = await page.locator('[data-testid="audit-log-entry"]').first().textContent();

    // Administrator clicks 'Export' button and selects 'CSV' format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-csv-option"]');

    // Administrator confirms CSV export
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;

    // Expected Result: CSV file downloads with correct data
    expect(download.suggestedFilename()).toContain('.csv');
    const csvPath = await download.path();
    expect(csvPath).toBeTruthy();

    // Administrator opens the downloaded CSV file
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');

    // Administrator verifies data integrity in CSV by comparing sample entries with UI display
    expect(csvContent).toContain('Workflow Modified');
    expect(csvContent).toContain('admin@example.com');
    expect(csvContent.split('\n').length).toBeGreaterThan(1);

    // Administrator returns to audit logs page and clicks 'Export' button, then selects 'PDF' format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-pdf-option"]');

    // Administrator confirms PDF export
    const pdfDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const pdfDownload = await pdfDownloadPromise;

    // Expected Result: PDF file downloads with formatted data
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();

    // Administrator opens the downloaded PDF file
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(0);

    // Administrator verifies data completeness in PDF by reviewing entries and comparing with UI display
    // Note: Full PDF parsing would require additional libraries, verifying file exists and has content
    expect(pdfStats.size).toBeGreaterThan(1000); // PDF should have substantial content

    // Administrator checks audit logs for export actions
    await page.reload();
    await page.fill('[data-testid="audit-search-input"]', 'export');
    await page.selectOption('[data-testid="action-type-filter"]', 'Audit Export');
    await page.click('[data-testid="apply-filters-button"]');

    // Verify export actions are logged
    await expect(page.locator('[data-testid="audit-log-entry"]')).toHaveCountGreaterThanOrEqual(2);
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'CSV' })).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').filter({ hasText: 'PDF' })).toBeVisible();
  });
});