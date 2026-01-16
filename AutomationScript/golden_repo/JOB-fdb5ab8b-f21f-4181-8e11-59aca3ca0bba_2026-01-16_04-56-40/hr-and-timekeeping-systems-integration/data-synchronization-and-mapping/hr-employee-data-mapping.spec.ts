import { test, expect } from '@playwright/test';

test.describe('HR Employee Data Mapping to Integration Schema', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'data.engineer@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Verify correct mapping of mandatory employee fields (happy-path)', async ({ page }) => {
    // Navigate to the data synchronization module and select the HR employee data source
    await page.click('[data-testid="data-sync-module"]');
    await expect(page.locator('[data-testid="sync-module-header"]')).toBeVisible();
    await page.click('[data-testid="hr-data-source-select"]');
    await page.selectOption('[data-testid="hr-data-source-select"]', 'hr-employee-data');

    // Provide sample HR employee data containing all mandatory fields
    const sampleEmployeeData = {
      employeeId: 'EMP001',
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@company.com',
      department: 'Engineering',
      hireDate: '01/15/2023',
      employmentStatus: 'Active'
    };

    await page.fill('[data-testid="employee-id-input"]', sampleEmployeeData.employeeId);
    await page.fill('[data-testid="first-name-input"]', sampleEmployeeData.firstName);
    await page.fill('[data-testid="last-name-input"]', sampleEmployeeData.lastName);
    await page.fill('[data-testid="email-input"]', sampleEmployeeData.email);
    await page.fill('[data-testid="department-input"]', sampleEmployeeData.department);
    await page.fill('[data-testid="hire-date-input"]', sampleEmployeeData.hireDate);
    await page.selectOption('[data-testid="employment-status-select"]', sampleEmployeeData.employmentStatus);

    // Initiate the mapping process by clicking 'Apply Mapping' button
    await page.click('[data-testid="apply-mapping-button"]');
    await expect(page.locator('[data-testid="mapping-success-message"]')).toBeVisible();

    // Review the mapped data in the integration schema format
    await expect(page.locator('[data-testid="mapped-employee-id"]')).toHaveText(sampleEmployeeData.employeeId);
    await expect(page.locator('[data-testid="mapped-first-name"]')).toHaveText(sampleEmployeeData.firstName);
    await expect(page.locator('[data-testid="mapped-last-name"]')).toHaveText(sampleEmployeeData.lastName);
    await expect(page.locator('[data-testid="mapped-email"]')).toHaveText(sampleEmployeeData.email);
    await expect(page.locator('[data-testid="mapped-department"]')).toHaveText(sampleEmployeeData.department);
    await expect(page.locator('[data-testid="mapped-hire-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="mapped-employment-status"]')).toHaveText(sampleEmployeeData.employmentStatus);

    // Trigger the synchronization process by clicking 'Sync to Timekeeping System' button
    await page.click('[data-testid="sync-to-timekeeping-button"]');
    await expect(page.locator('[data-testid="sync-in-progress"]')).toBeVisible();

    // Monitor the synchronization status until completion
    await expect(page.locator('[data-testid="sync-completed-status"]')).toBeVisible({ timeout: 30000 });
    await expect(page.locator('[data-testid="sync-success-message"]')).toContainText('Synchronization completed successfully');

    // Access the timekeeping system and navigate to the employee records section
    await page.click('[data-testid="timekeeping-system-link"]');
    await page.click('[data-testid="employee-records-section"]');
    await expect(page.locator('[data-testid="employee-records-table"]')).toBeVisible();

    // Verify data integrity by comparing source HR data with target timekeeping system data
    await page.fill('[data-testid="employee-search-input"]', sampleEmployeeData.employeeId);
    await page.click('[data-testid="search-button"]');
    
    const employeeRow = page.locator(`[data-testid="employee-row-${sampleEmployeeData.employeeId}"]`);
    await expect(employeeRow).toBeVisible();
    await expect(employeeRow.locator('[data-testid="employee-id-cell"]')).toHaveText(sampleEmployeeData.employeeId);
    await expect(employeeRow.locator('[data-testid="first-name-cell"]')).toHaveText(sampleEmployeeData.firstName);
    await expect(employeeRow.locator('[data-testid="last-name-cell"]')).toHaveText(sampleEmployeeData.lastName);
    await expect(employeeRow.locator('[data-testid="email-cell"]')).toHaveText(sampleEmployeeData.email);
    await expect(employeeRow.locator('[data-testid="department-cell"]')).toHaveText(sampleEmployeeData.department);
    await expect(employeeRow.locator('[data-testid="employment-status-cell"]')).toHaveText(sampleEmployeeData.employmentStatus);
  });

  test('Test handling of invalid data during mapping (error-case)', async ({ page }) => {
    // Navigate to the data synchronization module and select the HR employee data source
    await page.click('[data-testid="data-sync-module"]');
    await expect(page.locator('[data-testid="sync-module-header"]')).toBeVisible();
    await page.click('[data-testid="hr-data-source-select"]');
    await page.selectOption('[data-testid="hr-data-source-select"]', 'hr-employee-data');

    // Provide HR employee data containing invalid data types
    await page.fill('[data-testid="employee-id-input"]', 'EMP002');
    await page.fill('[data-testid="first-name-input"]', 'Jane');
    await page.fill('[data-testid="last-name-input"]', 'Smith');
    await page.fill('[data-testid="email-input"]', 'jane.smith@company.com');
    await page.fill('[data-testid="department-input"]', 'Sales');
    await page.fill('[data-testid="hire-date-input"]', 'InvalidDateText'); // Invalid date format
    await page.selectOption('[data-testid="employment-status-select"]', 'Active');

    // Initiate the mapping process by clicking 'Apply Mapping' button
    await page.click('[data-testid="apply-mapping-button"]');

    // Navigate to the error logs section and review the detailed error information
    await expect(page.locator('[data-testid="mapping-error-message"]')).toBeVisible();
    await page.click('[data-testid="view-error-logs-link"]');
    await expect(page.locator('[data-testid="error-logs-section"]')).toBeVisible();
    
    const errorLog = page.locator('[data-testid="error-log-entry"]').first();
    await expect(errorLog).toContainText('Invalid data type');
    await expect(errorLog).toContainText('hire_date');
    await expect(errorLog).toContainText('Expected date format');

    // Go back and provide data with missing mandatory fields
    await page.click('[data-testid="back-to-sync-button"]');
    await page.click('[data-testid="clear-form-button"]');
    
    // Missing employee ID and email address
    await page.fill('[data-testid="first-name-input"]', 'Bob');
    await page.fill('[data-testid="last-name-input"]', 'Johnson');
    await page.fill('[data-testid="department-input"]', 'Marketing');
    await page.fill('[data-testid="hire-date-input"]', '03/20/2023');
    await page.selectOption('[data-testid="employment-status-select"]', 'Active');

    await page.click('[data-testid="apply-mapping-button"]');
    await expect(page.locator('[data-testid="mapping-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="mapping-error-message"]')).toContainText('Missing mandatory fields');

    // Attempt to trigger synchronization with the dataset containing invalid records
    await page.click('[data-testid="sync-to-timekeeping-button"]');
    await expect(page.locator('[data-testid="sync-warning-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="sync-warning-message"]')).toContainText('Invalid records detected');

    // Confirm synchronization to proceed with valid records only
    await page.click('[data-testid="confirm-sync-valid-only-button"]');
    await expect(page.locator('[data-testid="sync-in-progress"]')).toBeVisible();
    await expect(page.locator('[data-testid="sync-completed-status"]')).toBeVisible({ timeout: 30000 });

    // Review the synchronization summary report
    await page.click('[data-testid="view-sync-summary-button"]');
    await expect(page.locator('[data-testid="sync-summary-report"]')).toBeVisible();
    await expect(page.locator('[data-testid="valid-records-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="invalid-records-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="invalid-records-count"]')).not.toHaveText('0');

    // Access the detailed error logs and verify accuracy of field-level error information
    await page.click('[data-testid="view-detailed-errors-link"]');
    await expect(page.locator('[data-testid="error-logs-table"]')).toBeVisible();
    
    const errorRows = page.locator('[data-testid="error-log-row"]');
    await expect(errorRows).not.toHaveCount(0);
    
    const firstError = errorRows.first();
    await expect(firstError.locator('[data-testid="error-field-name"]')).toBeVisible();
    await expect(firstError.locator('[data-testid="error-description"]')).toBeVisible();
    await expect(firstError.locator('[data-testid="error-timestamp"]')).toBeVisible();
  });

  test('Validate mapping configuration update process (happy-path)', async ({ page }) => {
    // Log in to the system with authorized Data Engineer credentials (already done in beforeEach)
    
    // Navigate to the mapping configuration section
    await page.click('[data-testid="configuration-menu"]');
    await page.click('text=Field Mapping');
    await expect(page.locator('[data-testid="field-mapping-config-page"]')).toBeVisible();

    // Verify access permissions by checking available actions
    await expect(page.locator('[data-testid="view-mapping-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="edit-mapping-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-mapping-button"]')).toBeVisible();

    // Review current mapping rules for HR employee fields to integration schema
    await page.click('[data-testid="view-mapping-button"]');
    await expect(page.locator('[data-testid="mapping-rules-table"]')).toBeVisible();
    
    const hireDateRow = page.locator('[data-testid="mapping-rule-hire-date"]');
    await expect(hireDateRow).toBeVisible();
    const currentFormat = await hireDateRow.locator('[data-testid="transformation-format"]').textContent();
    expect(currentFormat).toBe('MM/DD/YYYY');

    // Modify a mapping rule by changing the transformation format for 'hire_date' field
    await page.click('[data-testid="edit-mapping-button"]');
    await expect(page.locator('[data-testid="edit-mode-indicator"]')).toBeVisible();
    
    await hireDateRow.locator('[data-testid="edit-rule-button"]').click();
    await expect(page.locator('[data-testid="edit-rule-dialog"]')).toBeVisible();
    
    await page.selectOption('[data-testid="transformation-format-select"]', 'YYYY-MM-DD');
    
    // Add a comment describing the reason for the mapping change
    await page.fill('[data-testid="change-comment-input"]', 'Updating hire_date format to ISO 8601 standard (YYYY-MM-DD) for better compatibility with timekeeping system API');
    
    await page.click('[data-testid="confirm-rule-change-button"]');
    await expect(page.locator('[data-testid="rule-updated-message"]')).toBeVisible();

    // Click 'Save Changes' button to persist the mapping configuration updates
    await page.click('[data-testid="save-mapping-button"]');
    await expect(page.locator('[data-testid="save-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-save-button"]');
    await expect(page.locator('[data-testid="save-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="save-success-message"]')).toContainText('Mapping configuration saved successfully');

    // Navigate to the audit trail section and search for recent mapping configuration changes
    await page.click('[data-testid="audit-trail-link"]');
    await expect(page.locator('[data-testid="audit-trail-page"]')).toBeVisible();
    
    await page.selectOption('[data-testid="audit-filter-type"]', 'mapping-configuration');
    await page.click('[data-testid="apply-filter-button"]');
    
    const recentAuditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(recentAuditEntry).toBeVisible();
    await expect(recentAuditEntry.locator('[data-testid="audit-action"]')).toContainText('Mapping Configuration Updated');
    await expect(recentAuditEntry.locator('[data-testid="audit-field"]')).toContainText('hire_date');
    await expect(recentAuditEntry.locator('[data-testid="audit-old-value"]')).toContainText('MM/DD/YYYY');
    await expect(recentAuditEntry.locator('[data-testid="audit-new-value"]')).toContainText('YYYY-MM-DD');
    await expect(recentAuditEntry.locator('[data-testid="audit-comment"]')).toContainText('ISO 8601 standard');

    // Return to the data synchronization module and load test employee data
    await page.click('[data-testid="data-sync-module"]');
    await expect(page.locator('[data-testid="sync-module-header"]')).toBeVisible();
    await page.selectOption('[data-testid="hr-data-source-select"]', 'hr-employee-data');

    const testEmployeeData = {
      employeeId: 'EMP003',
      firstName: 'Alice',
      lastName: 'Williams',
      email: 'alice.williams@company.com',
      department: 'Finance',
      hireDate: '05/10/2023',
      employmentStatus: 'Active'
    };

    await page.fill('[data-testid="employee-id-input"]', testEmployeeData.employeeId);
    await page.fill('[data-testid="first-name-input"]', testEmployeeData.firstName);
    await page.fill('[data-testid="last-name-input"]', testEmployeeData.lastName);
    await page.fill('[data-testid="email-input"]', testEmployeeData.email);
    await page.fill('[data-testid="department-input"]', testEmployeeData.department);
    await page.fill('[data-testid="hire-date-input"]', testEmployeeData.hireDate);
    await page.selectOption('[data-testid="employment-status-select"]', testEmployeeData.employmentStatus);

    // Trigger synchronization with the updated mapping configuration
    await page.click('[data-testid="apply-mapping-button"]');
    await expect(page.locator('[data-testid="mapping-success-message"]')).toBeVisible();

    // Verify that the 'hire_date' field is transformed according to the new rule (YYYY-MM-DD format)
    const mappedHireDate = await page.locator('[data-testid="mapped-hire-date"]').textContent();
    expect(mappedHireDate).toMatch(/^\d{4}-\d{2}-\d{2}$/); // YYYY-MM-DD format
    expect(mappedHireDate).toBe('2023-05-10');

    await page.click('[data-testid="sync-to-timekeeping-button"]');
    await expect(page.locator('[data-testid="sync-completed-status"]')).toBeVisible({ timeout: 30000 });

    // Review synchronization logs to confirm successful application of updated mappings
    await page.click('[data-testid="view-sync-logs-button"]');
    await expect(page.locator('[data-testid="sync-logs-section"]')).toBeVisible();
    
    const latestSyncLog = page.locator('[data-testid="sync-log-entry"]').first();
    await expect(latestSyncLog).toBeVisible();
    await expect(latestSyncLog.locator('[data-testid="sync-status"]')).toContainText('Success');
    await expect(latestSyncLog.locator('[data-testid="mapping-version"]')).toBeVisible();
    
    await latestSyncLog.click();
    await expect(page.locator('[data-testid="sync-log-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="transformed-hire-date-log"]')).toContainText('2023-05-10');
    await expect(page.locator('[data-testid="transformation-applied"]')).toContainText('YYYY-MM-DD');
  });
});