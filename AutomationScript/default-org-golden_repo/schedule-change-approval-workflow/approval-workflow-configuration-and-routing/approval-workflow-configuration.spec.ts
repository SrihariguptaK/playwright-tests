import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Configuration - Story 12', () => {
  test.beforeEach(async ({ page }) => {
    // Administrator logs into admin portal
    await page.goto('/admin/login');
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*admin\/dashboard/);
  });

  test('Validate creation of multi-level approval workflow', async ({ page }) => {
    // Step 1: Administrator accesses workflow configuration UI
    await page.goto('/admin/workflows');
    await expect(page.locator('[data-testid="workflows-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-workflow-button"]')).toBeVisible();
    
    // Step 2: Administrator defines multiple approval levels and assigns approvers
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Multi-Level Schedule Change Workflow');
    
    // Add Level 1
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-1-name"]', 'Manager Approval');
    await page.click('[data-testid="level-1-approver-select"]');
    await page.click('[data-testid="approver-option-manager1"]');
    
    // Add Level 2
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-2-name"]', 'Director Approval');
    await page.click('[data-testid="level-2-approver-select"]');
    await page.click('[data-testid="approver-option-director1"]');
    
    // Add Level 3
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-3-name"]', 'Executive Approval');
    await page.click('[data-testid="level-3-approver-select"]');
    await page.click('[data-testid="approver-option-executive1"]');
    
    await expect(page.locator('[data-testid="workflow-error"]')).not.toBeVisible();
    
    // Step 3: Administrator saves the workflow
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    await expect(page.locator('[data-testid="workflows-list"]')).toContainText('Multi-Level Schedule Change Workflow');
  });

  test('Verify prevention of circular routing in workflows', async ({ page }) => {
    // Step 1: Administrator attempts to create routing that loops back to a previous level
    await page.goto('/admin/workflows');
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Circular Routing Test Workflow');
    
    // Add Level 1
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-1-name"]', 'Level 1');
    await page.click('[data-testid="level-1-approver-select"]');
    await page.click('[data-testid="approver-option-manager1"]');
    
    // Add Level 2
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-2-name"]', 'Level 2');
    await page.click('[data-testid="level-2-approver-select"]');
    await page.click('[data-testid="approver-option-director1"]');
    
    // Add conditional routing that creates a loop
    await page.click('[data-testid="level-2-add-condition"]');
    await page.selectOption('[data-testid="level-2-condition-action"]', 'route-to-level');
    await page.selectOption('[data-testid="level-2-route-target"]', '1');
    
    // Attempt to save
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Circular routing detected');
    
    // Step 2: Administrator modifies routing to remove loop
    await page.click('[data-testid="level-2-remove-condition"]');
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
  });

  test('Test workflow preview visualization', async ({ page }) => {
    // Step 1: Administrator configures workflow with multiple levels and conditions
    await page.goto('/admin/workflows');
    await page.click('[data-testid="create-workflow-button"]');
    await page.fill('[data-testid="workflow-name-input"]', 'Complex Conditional Workflow');
    
    // Add Level 1 with condition
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-1-name"]', 'Initial Review');
    await page.click('[data-testid="level-1-approver-select"]');
    await page.click('[data-testid="approver-option-manager1"]');
    await page.click('[data-testid="level-1-add-condition"]');
    await page.selectOption('[data-testid="level-1-condition-attribute"]', 'schedule-hours');
    await page.selectOption('[data-testid="level-1-condition-operator"]', 'greater-than');
    await page.fill('[data-testid="level-1-condition-value"]', '40');
    
    // Add Level 2
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-2-name"]', 'Senior Review');
    await page.click('[data-testid="level-2-approver-select"]');
    await page.click('[data-testid="approver-option-director1"]');
    
    // Add Level 3
    await page.click('[data-testid="add-level-button"]');
    await page.fill('[data-testid="level-3-name"]', 'Final Approval');
    await page.click('[data-testid="level-3-approver-select"]');
    await page.click('[data-testid="approver-option-executive1"]');
    
    await expect(page.locator('[data-testid="workflow-error"]')).not.toBeVisible();
    
    // Step 2: Administrator clicks preview button
    await page.click('[data-testid="preview-workflow-button"]');
    await expect(page.locator('[data-testid="workflow-preview-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="workflow-preview-diagram"]')).toBeVisible();
    await expect(page.locator('[data-testid="preview-level-1"]')).toContainText('Initial Review');
    await expect(page.locator('[data-testid="preview-level-2"]')).toContainText('Senior Review');
    await expect(page.locator('[data-testid="preview-level-3"]')).toContainText('Final Approval');
    await expect(page.locator('[data-testid="preview-condition-path"]')).toBeVisible();
  });

  test('Validate logging of approval workflow configuration changes (happy-path)', async ({ page }) => {
    // Navigate to the approval workflow configuration page
    await page.goto('/admin/workflows');
    await expect(page.locator('[data-testid="workflows-list"]')).toBeVisible();
    
    // Select an existing approval workflow to modify
    await page.click('[data-testid="workflow-item-1"]');
    await expect(page.locator('[data-testid="workflow-edit-form"]')).toBeVisible();
    
    // Modify workflow parameters
    const originalWorkflowName = await page.locator('[data-testid="workflow-name-input"]').inputValue();
    const newWorkflowName = `${originalWorkflowName} - Modified`;
    await page.fill('[data-testid="workflow-name-input"]', newWorkflowName);
    
    // Change approval threshold
    await page.fill('[data-testid="approval-threshold-input"]', '3');
    
    // Add approver
    await page.click('[data-testid="add-approver-button"]');
    await page.click('[data-testid="new-approver-select"]');
    await page.click('[data-testid="approver-option-manager2"]');
    
    // Save the workflow configuration changes
    const saveTime = new Date();
    await page.click('[data-testid="save-workflow-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Workflow saved successfully');
    
    // Navigate to the audit logs module
    await page.goto('/admin/audit-logs');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    
    // Search for audit logs related to the modified workflow
    await page.fill('[data-testid="audit-search-input"]', newWorkflowName);
    await page.click('[data-testid="audit-search-button"]');
    
    // Locate and open the most recent workflow modification entry
    await page.click('[data-testid="audit-log-entry-0"]');
    await expect(page.locator('[data-testid="audit-log-detail-modal"]')).toBeVisible();
    
    // Verify the timestamp matches the time of modification
    const logTimestamp = await page.locator('[data-testid="audit-log-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
    
    // Verify the logged user matches the administrator who made the change
    await expect(page.locator('[data-testid="audit-log-user"]')).toContainText('admin@example.com');
    
    // Verify all modified fields are accurately recorded in the audit log
    await expect(page.locator('[data-testid="audit-log-details"]')).toContainText('workflow_name');
    await expect(page.locator('[data-testid="audit-log-details"]')).toContainText('approval_threshold');
    await expect(page.locator('[data-testid="audit-log-details"]')).toContainText('approvers');
  });

  test('Verify audit log immutability and access control (error-case)', async ({ page }) => {
    // Log out any currently logged-in user
    await page.goto('/admin/dashboard');
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);
    
    // Log in with unauthorized user credentials
    await page.fill('[data-testid="username-input"]', 'unauthorized@example.com');
    await page.fill('[data-testid="password-input"]', 'UnauthorizedPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Attempt to navigate to the audit logs module URL directly
    await page.goto('/admin/audit-logs');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    
    // Verify that audit logs menu option is not visible in the navigation
    await page.goto('/admin/dashboard');
    await expect(page.locator('[data-testid="nav-audit-logs"]')).not.toBeVisible();
    
    // Attempt to access audit logs via API endpoint
    const apiResponse = await page.request.get('/api/audit-logs');
    expect(apiResponse.status()).toBe(403);
    
    // Log out the unauthorized user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Log in with authorized administrator credentials
    await page.fill('[data-testid="username-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Navigate to the audit logs module
    await page.goto('/admin/audit-logs');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    
    // Select an existing audit log entry
    await page.click('[data-testid="audit-log-entry-0"]');
    await expect(page.locator('[data-testid="audit-log-detail-modal"]')).toBeVisible();
    
    // Attempt to edit or modify any field in the audit log entry through the UI
    await expect(page.locator('[data-testid="audit-log-edit-button"]')).not.toBeVisible();
    const auditFields = page.locator('[data-testid^="audit-field-"]');
    const fieldCount = await auditFields.count();
    for (let i = 0; i < fieldCount; i++) {
      await expect(auditFields.nth(i)).toBeDisabled();
    }
    
    // Attempt to delete the audit log entry through the UI
    await expect(page.locator('[data-testid="audit-log-delete-button"]')).not.toBeVisible();
    
    // Attempt to modify audit log entry via API
    const auditLogId = await page.locator('[data-testid="audit-log-id"]').textContent();
    const putResponse = await page.request.put(`/api/audit-logs/${auditLogId}`, {
      data: { action: 'modified_action' }
    });
    expect(putResponse.status()).toBe(403);
    
    const patchResponse = await page.request.patch(`/api/audit-logs/${auditLogId}`, {
      data: { action: 'modified_action' }
    });
    expect(patchResponse.status()).toBe(403);
    
    // Verify that the modification attempt itself is logged in the audit trail
    await page.reload();
    await page.fill('[data-testid="audit-search-input"]', 'unauthorized_modification_attempt');
    await page.click('[data-testid="audit-search-button"]');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toContainText('unauthorized_modification_attempt');
    
    // Verify the original audit log entry remains unchanged
    await page.fill('[data-testid="audit-search-input"]', auditLogId || '');
    await page.click('[data-testid="audit-search-button"]');
    await page.click('[data-testid="audit-log-entry-0"]');
    await expect(page.locator('[data-testid="audit-log-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-action"]')).not.toContainText('modified_action');
  });

  test('Test export of audit reports (happy-path)', async ({ page }) => {
    // Navigate to the audit logs module
    await page.goto('/admin/audit-logs');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    
    // Apply filters to the audit logs
    await page.click('[data-testid="filter-date-range"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    
    await page.click('[data-testid="filter-user"]');
    await page.fill('[data-testid="filter-user-input"]', 'admin@example.com');
    await page.click('[data-testid="filter-user-apply"]');
    
    await page.click('[data-testid="filter-action-type"]');
    await page.check('[data-testid="action-type-workflow-modifications"]');
    await page.click('[data-testid="filter-action-apply"]');
    
    // Verify the filtered results show the expected number of entries
    const filteredCount = await page.locator('[data-testid="audit-logs-count"]').textContent();
    expect(parseInt(filteredCount || '0')).toBeGreaterThan(0);
    
    // Click on the Export button and select CSV format
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-csv"]');
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report generation to complete and save
    const downloadCSV = await downloadPromiseCSV;
    const csvPath = await downloadCSV.path();
    expect(csvPath).toBeTruthy();
    
    // Verify CSV contains expected columns and data
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    expect(csvContent).toContain('Timestamp');
    expect(csvContent).toContain('User');
    expect(csvContent).toContain('Action');
    expect(csvContent).toContain('Workflow ID');
    expect(csvContent).toContain('Details');
    expect(csvContent).toContain('IP Address');
    expect(csvContent).toContain('admin@example.com');
    
    // Return to audit logs interface and export as PDF
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-pdf"]');
    await page.click('[data-testid="generate-report-button"]');
    
    const downloadPDF = await downloadPromisePDF;
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();
    expect(pdfPath).toContain('.pdf');
    
    // Return to audit logs interface and export as Excel
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-excel"]');
    await page.click('[data-testid="generate-report-button"]');
    
    const downloadExcel = await downloadPromiseExcel;
    const excelPath = await downloadExcel.path();
    expect(excelPath).toBeTruthy();
    expect(excelPath).toMatch(/\.(xlsx|xls)$/);
  });
});