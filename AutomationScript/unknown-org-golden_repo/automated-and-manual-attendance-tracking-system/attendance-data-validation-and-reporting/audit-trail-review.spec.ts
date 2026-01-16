import { test, expect } from '@playwright/test';

test.describe('Audit Trail Review - System Auditor', () => {
  const AUDIT_PORTAL_URL = '/audit/portal';
  const LOGIN_URL = '/login';
  
  test('Review audit logs for attendance data changes', async ({ page }) => {
    // Step 1: Login as system auditor
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="username-input"]', 'auditor@company.com');
    await page.fill('[data-testid="password-input"]', 'AuditorPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to audit log interface
    await expect(page).toHaveURL(new RegExp(AUDIT_PORTAL_URL));
    await expect(page.locator('[data-testid="audit-log-interface"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Audit Log Interface');
    
    // Step 2: Search audit logs by user and date
    await page.fill('[data-testid="search-user-input"]', 'john.doe@company.com');
    await page.fill('[data-testid="search-date-from"]', '2024-01-01');
    await page.fill('[data-testid="search-date-to"]', '2024-01-31');
    await page.click('[data-testid="search-audit-logs-button"]');
    
    // Expected Result: Relevant audit records are displayed
    await expect(page.locator('[data-testid="audit-records-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-record-row"]')).toHaveCount(await page.locator('[data-testid="audit-record-row"]').count());
    
    const firstRecord = page.locator('[data-testid="audit-record-row"]').first();
    await expect(firstRecord.locator('[data-testid="audit-user"]')).toContainText('john.doe@company.com');
    await expect(firstRecord.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="audit-action"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="audit-details"]')).toBeVisible();
    
    // Step 3: Export audit logs
    await page.click('[data-testid="export-audit-logs-button"]');
    
    // Expected Result: Audit logs exported successfully
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    
    expect(download.suggestedFilename()).toMatch(/audit-logs.*\.(csv|xlsx|pdf)/);
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-success-message"]')).toContainText('Audit logs exported successfully');
  });
  
  test('Prevent unauthorized access to audit logs', async ({ page }) => {
    // Step 1: Login as non-auditor user
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access to audit logs is denied
    await expect(page).toHaveURL(/\/dashboard/);
    
    // Attempt to navigate directly to audit portal
    await page.goto(AUDIT_PORTAL_URL);
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access Denied|Unauthorized|403/);
    
    // Verify audit log interface is not accessible
    await expect(page.locator('[data-testid="audit-log-interface"]')).not.toBeVisible();
    
    // Verify user is redirected or shown error page
    const currentUrl = page.url();
    expect(currentUrl).not.toContain(AUDIT_PORTAL_URL);
  });
});