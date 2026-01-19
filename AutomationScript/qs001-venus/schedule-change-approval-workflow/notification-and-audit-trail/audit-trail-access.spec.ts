import { test, expect } from '@playwright/test';

test.describe('Audit Trail Access - Story 27', () => {
  const AUDIT_PORTAL_URL = '/audit-portal';
  const AUDIT_TRAIL_URL = '/audit-trail/schedule-changes';
  const LOGIN_URL = '/login';

  test('Verify auditor can view and filter audit trail records (happy-path)', async ({ page }) => {
    // Navigate to the audit portal login page
    await page.goto(LOGIN_URL);
    await expect(page).toHaveURL(LOGIN_URL);

    // Enter valid auditor credentials and click Login
    await page.fill('[data-testid="username-input"]', 'auditor@company.com');
    await page.fill('[data-testid="password-input"]', 'AuditorPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Verify successful login
    await expect(page).toHaveURL(/.*dashboard.*|.*audit-portal.*/);
    await expect(page.locator('[data-testid="user-role"]')).toContainText('Auditor');

    // Navigate to the schedule change approval audit trail page from the main menu
    await page.click('[data-testid="audit-trail-menu"]');
    await page.click('[data-testid="schedule-change-audit-link"]');
    await expect(page).toHaveURL(new RegExp(AUDIT_TRAIL_URL));

    // Verify the audit trail displays key information columns
    await expect(page.locator('[data-testid="audit-trail-table"]')).toBeVisible();
    await expect(page.locator('th:has-text("Timestamp")')).toBeVisible();
    await expect(page.locator('th:has-text("User ID")')).toBeVisible();
    await expect(page.locator('th:has-text("Action Type")')).toBeVisible();
    await expect(page.locator('th:has-text("Request ID")')).toBeVisible();
    await expect(page.locator('th:has-text("Comments")')).toBeVisible();

    // Locate the filter panel and select a specific date range (e.g., last 30 days)
    await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    
    // Apply an additional filter by selecting a specific user from the user dropdown
    await page.click('[data-testid="user-filter-dropdown"]');
    await page.click('[data-testid="user-option-john-doe"]');
    await page.click('[data-testid="apply-filters-button"]');

    // Verify the filtered results match the applied criteria
    await page.waitForSelector('[data-testid="audit-trail-table"] tbody tr');
    const filteredRows = await page.locator('[data-testid="audit-trail-table"] tbody tr').count();
    expect(filteredRows).toBeGreaterThan(0);
    
    // Verify all visible records contain the filtered user
    const userCells = await page.locator('[data-testid="audit-trail-table"] tbody tr td:nth-child(2)').allTextContents();
    userCells.forEach(cell => {
      expect(cell).toContain('john.doe');
    });

    // Click the Export as CSV button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-button"]');
    const download = await downloadPromise;
    
    // Verify CSV file is downloaded
    expect(download.suggestedFilename()).toMatch(/audit.*\.csv/);
    const path = await download.path();
    expect(path).toBeTruthy();

    // Open the downloaded CSV file and verify data
    const fs = require('fs');
    const csvContent = fs.readFileSync(path, 'utf-8');
    expect(csvContent).toContain('Timestamp');
    expect(csvContent).toContain('User ID');
    expect(csvContent).toContain('john.doe');
  });

  test('Ensure access restriction to audit trail for unauthorized users (error-case)', async ({ page }) => {
    // Navigate to the application login page
    await page.goto(LOGIN_URL);
    await expect(page).toHaveURL(LOGIN_URL);

    // Login using credentials of a non-auditor user (employee or manager role)
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    
    // Verify successful login as non-auditor
    await expect(page).toHaveURL(/.*dashboard.*/);
    await expect(page.locator('[data-testid="user-role"]')).not.toContainText('Auditor');

    // Verify that the audit trail menu option is not visible in the navigation menu
    await expect(page.locator('[data-testid="audit-trail-menu"]')).not.toBeVisible();
    const auditMenuCount = await page.locator('[data-testid="audit-trail-menu"]').count();
    expect(auditMenuCount).toBe(0);

    // Attempt to directly access the audit trail page by entering the URL in the browser
    await page.goto(AUDIT_TRAIL_URL);
    
    // Verify the user is redirected to an error page or their dashboard
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    const isAccessDenied = currentUrl.includes('access-denied') || 
                          currentUrl.includes('unauthorized') || 
                          currentUrl.includes('403') ||
                          currentUrl.includes('dashboard');
    expect(isAccessDenied).toBeTruthy();
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"], [data-testid="access-denied-message"], .error-message');
    if (await errorMessage.count() > 0) {
      await expect(errorMessage.first()).toBeVisible();
      const errorText = await errorMessage.first().textContent();
      expect(errorText?.toLowerCase()).toMatch(/access denied|unauthorized|permission/i);
    }

    // Check the security logs for the unauthorized access attempt (via API)
    const response = await page.request.get('/api/security-logs?event=unauthorized_access&limit=1');
    expect(response.ok()).toBeTruthy();
    const logs = await response.json();
    expect(logs.length).toBeGreaterThan(0);
    expect(logs[0].user).toContain('employee@company.com');

    // Attempt to access audit trail API endpoint directly with non-auditor credentials
    const apiResponse = await page.request.get('/api/audit-logs', {
      headers: {
        'Authorization': 'Bearer employee_token'
      }
    });
    expect(apiResponse.status()).toBe(403);
    const apiError = await apiResponse.json();
    expect(apiError.message).toMatch(/unauthorized|forbidden|access denied/i);
  });

  test('Validate immutability of audit trail data (error-case)', async ({ page }) => {
    // Login as auditor and navigate to the audit trail page
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="username-input"]', 'auditor@company.com');
    await page.fill('[data-testid="password-input"]', 'AuditorPass123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(/.*dashboard.*|.*audit-portal.*/);
    
    await page.click('[data-testid="audit-trail-menu"]');
    await page.click('[data-testid="schedule-change-audit-link"]');
    await expect(page).toHaveURL(new RegExp(AUDIT_TRAIL_URL));
    await page.waitForSelector('[data-testid="audit-trail-table"] tbody tr');

    // Select a specific audit log entry and look for edit or delete options in the UI
    const firstRow = page.locator('[data-testid="audit-trail-table"] tbody tr').first();
    await firstRow.click();
    
    // Verify no edit or delete buttons are present
    const editButton = page.locator('[data-testid="edit-audit-button"], button:has-text("Edit")');
    const deleteButton = page.locator('[data-testid="delete-audit-button"], button:has-text("Delete")');
    await expect(editButton).not.toBeVisible();
    await expect(deleteButton).not.toBeVisible();

    // Right-click on an audit record to check for context menu options
    await firstRow.click({ button: 'right' });
    await page.waitForTimeout(500);
    const contextMenu = page.locator('.context-menu, [role="menu"]');
    if (await contextMenu.count() > 0) {
      const editOption = contextMenu.locator('text=/edit/i');
      const deleteOption = contextMenu.locator('text=/delete/i');
      await expect(editOption).not.toBeVisible();
      await expect(deleteOption).not.toBeVisible();
    }

    // Attempt to modify an audit record by inspecting the page elements
    const auditIdCell = await firstRow.locator('td').first().textContent();
    const auditId = auditIdCell?.trim();
    
    // Check if fields are readonly/disabled
    const inputFields = await firstRow.locator('input, textarea').count();
    if (inputFields > 0) {
      const firstInput = firstRow.locator('input, textarea').first();
      const isReadonly = await firstInput.getAttribute('readonly');
      const isDisabled = await firstInput.getAttribute('disabled');
      expect(isReadonly !== null || isDisabled !== null).toBeTruthy();
    }

    // Using API testing tool, send a PUT request to modify an existing audit log entry
    const putResponse = await page.request.put(`/api/audit-logs/${auditId}`, {
      data: {
        comments: 'Modified comment - should be rejected'
      }
    });
    expect(putResponse.status()).toBeGreaterThanOrEqual(400);
    expect(putResponse.status()).toBeLessThan(500);
    const putError = await putResponse.json();
    expect(putError.message).toMatch(/immutable|cannot modify|not allowed|forbidden/i);

    // Using API testing tool, send a DELETE request to remove an audit log entry
    const deleteResponse = await page.request.delete(`/api/audit-logs/${auditId}`);
    expect(deleteResponse.status()).toBeGreaterThanOrEqual(400);
    expect(deleteResponse.status()).toBeLessThan(500);
    const deleteError = await deleteResponse.json();
    expect(deleteError.message).toMatch(/immutable|cannot delete|not allowed|forbidden/i);

    // Check the security logs for the modification attempts
    const securityLogsResponse = await page.request.get('/api/security-logs?event=audit_modification_attempt&limit=5');
    expect(securityLogsResponse.ok()).toBeTruthy();
    const securityLogs = await securityLogsResponse.json();
    expect(securityLogs.length).toBeGreaterThan(0);
    const modificationAttempts = securityLogs.filter((log: any) => 
      log.event_type === 'audit_modification_attempt' || 
      log.event_type === 'unauthorized_modification'
    );
    expect(modificationAttempts.length).toBeGreaterThan(0);

    // Verify the original audit record remains unchanged in the audit trail viewer
    await page.reload();
    await page.waitForSelector('[data-testid="audit-trail-table"] tbody tr');
    const reloadedFirstRow = page.locator('[data-testid="audit-trail-table"] tbody tr').first();
    const reloadedAuditId = await reloadedFirstRow.locator('td').first().textContent();
    expect(reloadedAuditId?.trim()).toBe(auditId);
    
    // Verify comments field has not changed
    const commentsCell = await reloadedFirstRow.locator('td:last-child').textContent();
    expect(commentsCell).not.toContain('Modified comment - should be rejected');

    // Check database logs to confirm no write operations were executed on audit trail tables
    const dbLogsResponse = await page.request.get('/api/database-logs?table=ApprovalAuditLogs&operation=UPDATE,DELETE&limit=10');
    if (dbLogsResponse.ok()) {
      const dbLogs = await dbLogsResponse.json();
      const recentWrites = dbLogs.filter((log: any) => {
        const logTime = new Date(log.timestamp).getTime();
        const now = new Date().getTime();
        return (now - logTime) < 60000; // Last minute
      });
      expect(recentWrites.length).toBe(0);
    }
  });
});