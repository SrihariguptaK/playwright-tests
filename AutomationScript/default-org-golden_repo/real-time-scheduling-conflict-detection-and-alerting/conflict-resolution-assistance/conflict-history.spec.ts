import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Conflict History Management', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const authorizedUser = {
    username: 'scheduler@example.com',
    password: 'SecurePass123!'
  };
  const unauthorizedUser = {
    username: 'viewer@example.com',
    password: 'ViewerPass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Verify conflict logging and retrieval (happy-path)', async ({ page }) => {
    // Login as authorized user
    await page.fill('[data-testid="username-input"]', authorizedUser.username);
    await page.fill('[data-testid="password-input"]', authorizedUser.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Create a scheduling conflict by attempting to book two appointments for the same resource at overlapping times
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="create-appointment-button"]');
    
    // First appointment
    await page.fill('[data-testid="appointment-title"]', 'First Appointment');
    await page.selectOption('[data-testid="resource-select"]', 'Resource-001');
    await page.fill('[data-testid="start-time"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time"]', '2024-01-15T11:00');
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment created successfully');

    // Second appointment with overlapping time
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Second Appointment');
    await page.selectOption('[data-testid="resource-select"]', 'Resource-001');
    await page.fill('[data-testid="start-time"]', '2024-01-15T10:30');
    await page.fill('[data-testid="end-time"]', '2024-01-15T11:30');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Verify conflict is detected
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('scheduling conflict detected');

    // Verify the conflict is logged by checking the conflict logs database (via API)
    const response = await page.request.get(`${baseURL}/api/conflicts/history`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    expect(response.ok()).toBeTruthy();
    const conflictData = await response.json();
    expect(conflictData.conflicts.length).toBeGreaterThan(0);

    // Navigate to the conflict history section from the main menu
    await page.click('[data-testid="conflict-history-menu"]');
    await expect(page.locator('[data-testid="conflict-history-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Conflict History');

    // Apply date range filter to show conflicts from the last 7 days
    await page.click('[data-testid="date-filter-button"]');
    const today = new Date();
    const sevenDaysAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    await page.fill('[data-testid="start-date-filter"]', sevenDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="end-date-filter"]', today.toISOString().split('T')[0]);
    await page.click('[data-testid="apply-date-filter"]');
    await page.waitForTimeout(1000);

    // Apply resource filter to show conflicts for a specific resource
    await page.click('[data-testid="resource-filter-dropdown"]');
    await page.selectOption('[data-testid="resource-filter-select"]', 'Resource-001');
    await page.click('[data-testid="apply-resource-filter"]');
    await page.waitForTimeout(1000);

    // Apply conflict type filter to show specific conflict types
    await page.click('[data-testid="conflict-type-filter-dropdown"]');
    await page.selectOption('[data-testid="conflict-type-select"]', 'Time Overlap');
    await page.click('[data-testid="apply-conflict-type-filter"]');
    await page.waitForTimeout(1000);

    // Verify the filtered conflict records display all required information
    const conflictRecords = page.locator('[data-testid="conflict-record"]');
    await expect(conflictRecords.first()).toBeVisible();
    
    const firstRecord = conflictRecords.first();
    await expect(firstRecord.locator('[data-testid="conflict-timestamp"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="involved-appointments"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="resolution-status"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="conflict-details"]')).toContainText('Resource-001');

    // Select export option and choose CSV format
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-csv"]');
    
    // Confirm export and download the conflict history report
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="confirm-export-button"]');
    const download = await downloadPromise;
    
    // Open the downloaded CSV file and verify data integrity
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    
    const csvContent = fs.readFileSync(downloadPath, 'utf-8');
    expect(csvContent).toContain('Conflict ID');
    expect(csvContent).toContain('Timestamp');
    expect(csvContent).toContain('Resource');
    expect(csvContent).toContain('Resolution Status');
    expect(csvContent).toContain('Resource-001');
    
    // Cleanup
    fs.unlinkSync(downloadPath);
  });

  test('Validate access control for conflict history (error-case)', async ({ page }) => {
    // Log into the system using credentials of a user without conflict history access permissions
    await page.fill('[data-testid="username-input"]', unauthorizedUser.username);
    await page.fill('[data-testid="password-input"]', unauthorizedUser.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Verify that the conflict history menu option is either hidden or disabled for this user
    const conflictHistoryMenu = page.locator('[data-testid="conflict-history-menu"]');
    const isVisible = await conflictHistoryMenu.isVisible().catch(() => false);
    
    if (isVisible) {
      const isDisabled = await conflictHistoryMenu.isDisabled();
      expect(isDisabled).toBeTruthy();
    } else {
      expect(isVisible).toBeFalsy();
    }

    // Attempt to access conflict history via direct URL
    await page.goto(`${baseURL}/conflict-history`);
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');

    // Attempt to access conflict history via API endpoint GET /conflicts/history using the unauthorized user's token
    const unauthorizedToken = await page.evaluate(() => localStorage.getItem('authToken'));
    const apiResponse = await page.request.get(`${baseURL}/api/conflicts/history`, {
      headers: {
        'Authorization': `Bearer ${unauthorizedToken}`
      }
    });
    expect(apiResponse.status()).toBe(403);
    const errorData = await apiResponse.json();
    expect(errorData.error).toContain('Access denied');

    // Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Log into the system using credentials of a user with valid conflict history access permissions
    await page.fill('[data-testid="username-input"]', authorizedUser.username);
    await page.fill('[data-testid="password-input"]', authorizedUser.password);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to the conflict history section from the menu
    await page.click('[data-testid="conflict-history-menu"]');
    await expect(page.locator('[data-testid="conflict-history-page"]')).toBeVisible();

    // Verify that conflict data is displayed with all details visible
    await expect(page.locator('[data-testid="conflict-history-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-record"]').first()).toBeVisible();
    
    const conflictRecord = page.locator('[data-testid="conflict-record"]').first();
    await expect(conflictRecord.locator('[data-testid="conflict-timestamp"]')).toBeVisible();
    await expect(conflictRecord.locator('[data-testid="involved-appointments"]')).toBeVisible();
    await expect(conflictRecord.locator('[data-testid="resolution-status"]')).toBeVisible();
    await expect(conflictRecord.locator('[data-testid="conflict-details"]')).toBeVisible();

    // Verify that the access attempt is logged in the audit log
    const auditResponse = await page.request.get(`${baseURL}/api/audit-logs`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      },
      params: {
        action: 'ACCESS_CONFLICT_HISTORY',
        limit: 10
      }
    });
    expect(auditResponse.ok()).toBeTruthy();
    const auditData = await auditResponse.json();
    expect(auditData.logs.length).toBeGreaterThan(0);
    
    const recentLog = auditData.logs.find((log: any) => 
      log.action === 'ACCESS_CONFLICT_HISTORY' && 
      log.username === authorizedUser.username
    );
    expect(recentLog).toBeDefined();
    expect(recentLog.status).toBe('SUCCESS');
  });
});