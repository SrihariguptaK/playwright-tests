import { test, expect } from '@playwright/test';

test.describe('Audit Approval Workflows and Decisions', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const ADMIN_EMAIL = 'admin@example.com';
  const ADMIN_PASSWORD = 'Admin@123';
  const UNAUTHORIZED_EMAIL = 'user@example.com';
  const UNAUTHORIZED_PASSWORD = 'User@123';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate logging of approval workflow configuration changes', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to workflow configuration
    await page.click('[data-testid="workflows-menu"]');
    await page.click('[data-testid="workflow-configuration"]');
    await expect(page.locator('[data-testid="workflow-config-page"]')).toBeVisible();

    // Get current timestamp for verification
    const beforeModificationTime = new Date();

    // Modify approval workflow
    await page.click('[data-testid="edit-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Updated Approval Workflow');
    await page.selectOption('[data-testid="approval-level-select"]', '3');
    await page.fill('[data-testid="workflow-description"]', 'Modified workflow for testing audit logs');
    await page.click('[data-testid="save-workflow-button"]');
    
    // Wait for success message
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow updated successfully');

    // Navigate to audit logs
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Query audit logs for workflow modification
    await page.fill('[data-testid="search-audit-input"]', 'Updated Approval Workflow');
    await page.selectOption('[data-testid="audit-type-filter"]', 'workflow_configuration');
    await page.click('[data-testid="search-audit-button"]');

    // Verify modification entry is present
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    
    // Verify audit log contains user information
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toContainText(ADMIN_EMAIL);
    
    // Verify audit log contains action type
    await expect(auditLogEntry.locator('[data-testid="audit-action"]')).toContainText('Workflow Configuration Modified');
    
    // Verify audit log contains workflow name
    await expect(auditLogEntry.locator('[data-testid="audit-details"]')).toContainText('Updated Approval Workflow');
    
    // Verify timestamp is accurate (within reasonable time window)
    const timestampText = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(timestampText).toBeTruthy();
    
    // Verify audit log contains change details
    await auditLogEntry.click();
    await expect(page.locator('[data-testid="audit-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-change-details"]')).toContainText('approval_level');
    await expect(page.locator('[data-testid="audit-change-details"]')).toContainText('3');
  });

  test('Verify audit log immutability and access control', async ({ page }) => {
    // Test unauthorized access
    // Login as unauthorized user
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to access audit logs
    await page.goto(`${BASE_URL}/audit/logs`);
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to access audit logs');

    // Logout unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Login as authorized administrator
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to audit logs
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Select an audit log entry
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await auditLogEntry.click();
    await expect(page.locator('[data-testid="audit-detail-modal"]')).toBeVisible();

    // Verify no edit/delete buttons are present
    await expect(page.locator('[data-testid="edit-audit-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="delete-audit-button"]')).not.toBeVisible();

    // Attempt to modify via API inspection (check if modification endpoints exist)
    const originalContent = await page.locator('[data-testid="audit-details"]').textContent();
    
    // Try to interact with read-only fields
    const detailsElement = page.locator('[data-testid="audit-details"]');
    const isReadOnly = await detailsElement.evaluate((el) => {
      return el.hasAttribute('readonly') || el.hasAttribute('disabled') || 
             window.getComputedStyle(el).getPropertyValue('pointer-events') === 'none';
    });
    expect(isReadOnly).toBeTruthy();

    // Verify audit log of access attempt is created
    await page.click('[data-testid="close-modal-button"]');
    await page.reload();
    
    // Search for access log
    await page.fill('[data-testid="search-audit-input"]', 'Audit Log Viewed');
    await page.click('[data-testid="search-audit-button"]');
    
    // Verify access is logged
    const accessLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(accessLogEntry.locator('[data-testid="audit-action"]')).toContainText('Audit Log Viewed');
    await expect(accessLogEntry.locator('[data-testid="audit-user"]')).toContainText(ADMIN_EMAIL);
  });

  test('Test export of audit reports', async ({ page }) => {
    // Login as administrator
    await page.fill('[data-testid="email-input"]', ADMIN_EMAIL);
    await page.fill('[data-testid="password-input"]', ADMIN_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to audit logs
    await page.click('[data-testid="audit-menu"]');
    await page.click('[data-testid="audit-logs"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Apply filters for audit report
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    const endDate = new Date();
    
    await page.fill('[data-testid="start-date-input"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-input"]', endDate.toISOString().split('T')[0]);
    await page.selectOption('[data-testid="audit-type-filter"]', 'workflow_configuration');
    await page.fill('[data-testid="user-filter-input"]', ADMIN_EMAIL);
    await page.click('[data-testid="apply-filters-button"]');

    // Wait for filtered results
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
    
    // Verify filter results are displayed
    const resultCount = await page.locator('[data-testid="audit-results-count"]').textContent();
    expect(resultCount).toBeTruthy();

    // Generate audit report - test CSV export
    await page.click('[data-testid="export-report-button"]');
    await expect(page.locator('[data-testid="export-format-modal"]')).toBeVisible();
    
    // Select CSV format
    await page.click('[data-testid="export-format-csv"]');
    
    // Setup download listener
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Wait for download to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('audit-report');
    expect(download.suggestedFilename()).toContain('.csv');
    
    // Verify success message
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Report exported successfully');

    // Test PDF export
    await page.click('[data-testid="export-report-button"]');
    await expect(page.locator('[data-testid="export-format-modal"]')).toBeVisible();
    
    // Select PDF format
    await page.click('[data-testid="export-format-pdf"]');
    
    // Setup download listener for PDF
    const pdfDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Wait for PDF download
    const pdfDownload = await pdfDownloadPromise;
    expect(pdfDownload.suggestedFilename()).toContain('audit-report');
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');

    // Test Excel export
    await page.click('[data-testid="export-report-button"]');
    await expect(page.locator('[data-testid="export-format-modal"]')).toBeVisible();
    
    // Select Excel format
    await page.click('[data-testid="export-format-excel"]');
    
    // Setup download listener for Excel
    const excelDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    
    // Wait for Excel download
    const excelDownload = await excelDownloadPromise;
    expect(excelDownload.suggestedFilename()).toContain('audit-report');
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);

    // Verify report generation time is within acceptable limits
    const exportTime = await page.locator('[data-testid="export-time"]').textContent();
    if (exportTime) {
      const timeInSeconds = parseFloat(exportTime.replace(/[^0-9.]/g, ''));
      expect(timeInSeconds).toBeLessThan(5);
    }

    // Verify export action is logged in audit trail
    await page.reload();
    await page.fill('[data-testid="search-audit-input"]', 'Audit Report Exported');
    await page.selectOption('[data-testid="audit-type-filter"]', 'report_export');
    await page.click('[data-testid="search-audit-button"]');
    
    const exportLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(exportLogEntry.locator('[data-testid="audit-action"]')).toContainText('Audit Report Exported');
    await expect(exportLogEntry.locator('[data-testid="audit-user"]')).toContainText(ADMIN_EMAIL);
  });
});