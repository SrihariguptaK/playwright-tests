import { test, expect } from '@playwright/test';

test.describe('Audit Logs Access and Compliance Verification', () => {
  const auditorCredentials = {
    username: 'auditor@company.com',
    password: 'AuditorPass123!'
  };

  const nonAuditorCredentials = {
    username: 'employee@company.com',
    password: 'EmployeePass123!'
  };

  test('Access and filter audit logs successfully (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the system login page and enter valid auditor credentials
    await page.goto('/login');
    await page.fill('input[data-testid="username-input"]', auditorCredentials.username);
    await page.fill('input[data-testid="password-input"]', auditorCredentials.password);
    await page.click('button[data-testid="login-button"]');

    // Expected Result: Audit logs page loads
    await expect(page).toHaveURL(/.*audit-logs/);
    await expect(page.locator('h1')).toContainText('Audit Logs');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();

    // Step 2: Locate the filter section and select a date range
    const startTime = Date.now();
    await page.click('[data-testid="date-range-filter"]');
    await page.click('text=Last 30 days');
    
    // Select a specific user from the user dropdown filter
    await page.click('[data-testid="user-filter-dropdown"]');
    await page.click('[data-testid="user-option-john-doe"]');
    await page.click('button[data-testid="apply-filters-button"]');

    // Expected Result: Filtered audit logs are displayed within 5 seconds
    await expect(page.locator('[data-testid="audit-logs-table"] tbody tr')).toBeVisible({ timeout: 5000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    expect(responseTime).toBeLessThan(5000);
    
    await expect(page.locator('[data-testid="filter-applied-badge"]')).toContainText('Last 30 days');
    await expect(page.locator('[data-testid="user-filter-badge"]')).toContainText('John Doe');

    // Step 3: Click on a specific log entry row to view its detailed information
    await page.click('[data-testid="audit-logs-table"] tbody tr:first-child');

    // Expected Result: Log details including timestamps and actions are visible
    await expect(page.locator('[data-testid="log-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-action"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-user"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-status"]')).toBeVisible();
  });

  test('Export audit logs in PDF and Excel formats (happy-path)', async ({ page }) => {
    // Login as auditor
    await page.goto('/login');
    await page.fill('input[data-testid="username-input"]', auditorCredentials.username);
    await page.fill('input[data-testid="password-input"]', auditorCredentials.password);
    await page.click('button[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*audit-logs/);

    // Step 1: Apply desired filters on audit logs by selecting date range and approval status
    await page.click('[data-testid="date-range-filter"]');
    await page.click('text=Last 7 days');
    await page.click('[data-testid="status-filter-dropdown"]');
    await page.click('[data-testid="status-option-approved"]');
    await page.click('button[data-testid="apply-filters-button"]');

    // Expected Result: Filtered logs displayed
    await expect(page.locator('[data-testid="audit-logs-table"] tbody tr')).toBeVisible();
    await expect(page.locator('[data-testid="filter-applied-badge"]')).toContainText('Last 7 days');
    await expect(page.locator('[data-testid="status-filter-badge"]')).toContainText('Approved');

    // Step 2: Locate and click the 'Export to PDF' button
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('button[data-testid="export-pdf-button"]')
    ]);

    // Expected Result: PDF file is generated and downloaded
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    expect(pdfDownload.suggestedFilename()).toContain('audit-logs');

    // Step 3: Return to the audit logs page and click the 'Export to Excel' button
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('button[data-testid="export-excel-button"]')
    ]);

    // Expected Result: Excel file is generated and downloaded
    expect(excelDownload.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    expect(excelDownload.suggestedFilename()).toContain('audit-logs');
  });

  test('Restrict audit log access to authorized users (error-case)', async ({ page }) => {
    // Step 1: Log into the system using credentials of a non-auditor user
    await page.goto('/login');
    await page.fill('input[data-testid="username-input"]', nonAuditorCredentials.username);
    await page.fill('input[data-testid="password-input"]', nonAuditorCredentials.password);
    await page.click('button[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Step 2: Attempt to navigate to the audit logs page by entering the URL directly
    await page.goto('/audit-logs');

    // Expected Result: Access denied message displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/access denied|unauthorized|forbidden/i);
    await expect(page.locator('[data-testid="audit-logs-table"]')).not.toBeVisible();

    // Step 3: Log out from the non-auditor account
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 4: Log back in using valid auditor credentials
    await page.fill('input[data-testid="username-input"]', auditorCredentials.username);
    await page.fill('input[data-testid="password-input"]', auditorCredentials.password);
    await page.click('button[data-testid="login-button"]');

    // Step 5: Navigate to the audit logs page using the menu or direct URL
    await page.goto('/audit-logs');

    // Expected Result: Access granted and logs displayed
    await expect(page).toHaveURL(/.*audit-logs/);
    await expect(page.locator('h1')).toContainText('Audit Logs');
    await expect(page.locator('[data-testid="audit-logs-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-logs-table"] tbody tr')).toHaveCount({ timeout: 5000 }, (count) => count > 0);
  });
});