import { test, expect } from '@playwright/test';

test.describe('Synchronization Job History - Story 19', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULER_EMAIL = 'scheduler@test.com';
  const SCHEDULER_PASSWORD = 'SchedulerPass123!';
  const VIEWER_EMAIL = 'viewer@test.com';
  const VIEWER_PASSWORD = 'ViewerPass123!';
  const NO_ROLE_EMAIL = 'norole@test.com';
  const NO_ROLE_PASSWORD = 'NoRolePass123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test('Verify recording and retrieval of synchronization job history (happy-path)', async ({ page }) => {
    // Login as Scheduler
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Execute a synchronization job of type 'Daily Customer Sync' and wait for completion
    await page.click('[data-testid="sync-jobs-menu"]');
    await page.click('[data-testid="create-sync-job-button"]');
    await page.selectOption('[data-testid="job-type-select"]', 'Daily Customer Sync');
    await page.click('[data-testid="execute-job-button"]');
    await expect(page.locator('[data-testid="job-status"]')).toContainText('Completed', { timeout: 30000 });
    const firstJobId = await page.locator('[data-testid="job-id"]').textContent();

    // Execute a synchronization job of type 'Product Catalog Sync' that completes with errors
    await page.click('[data-testid="create-sync-job-button"]');
    await page.selectOption('[data-testid="job-type-select"]', 'Product Catalog Sync');
    await page.check('[data-testid="simulate-errors-checkbox"]');
    await page.click('[data-testid="execute-job-button"]');
    await expect(page.locator('[data-testid="job-status"]')).toContainText('Completed with Errors', { timeout: 30000 });
    const secondJobId = await page.locator('[data-testid="job-id"]').textContent();

    // Execute a synchronization job of type 'Inventory Sync' and manually stop it mid-execution
    await page.click('[data-testid="create-sync-job-button"]');
    await page.selectOption('[data-testid="job-type-select"]', 'Inventory Sync');
    await page.click('[data-testid="execute-job-button"]');
    await page.waitForTimeout(2000);
    await page.click('[data-testid="stop-job-button"]');
    await expect(page.locator('[data-testid="job-status"]')).toContainText('Stopped');
    const thirdJobId = await page.locator('[data-testid="job-id"]').textContent();

    // Wait 30 seconds to ensure all job metadata is persisted to the database
    await page.waitForTimeout(30000);

    // Navigate to the synchronization job history page
    await page.goto(`${BASE_URL}/sync/jobs/history`);
    await expect(page.locator('[data-testid="job-history-page"]')).toBeVisible();

    // Verify that all three executed jobs appear in the job history list
    const jobHistoryTable = page.locator('[data-testid="job-history-table"]');
    await expect(jobHistoryTable).toBeVisible();
    const jobRows = jobHistoryTable.locator('tbody tr');
    await expect(jobRows).toHaveCount(3, { timeout: 10000 });

    // Apply date range filter to show only jobs from today
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="date-from-filter"]', today);
    await page.fill('[data-testid="date-to-filter"]', today);
    await page.click('[data-testid="apply-filters-button"]');
    await expect(jobRows).toHaveCount(3);

    // Apply status filter to show only jobs with status 'Completed with Errors'
    await page.selectOption('[data-testid="status-filter"]', 'Completed with Errors');
    await page.click('[data-testid="apply-filters-button"]');
    await expect(jobRows).toHaveCount(1);
    await expect(jobRows.first()).toContainText('Product Catalog Sync');

    // Clear filters and apply job type filter to show only 'Daily Customer Sync' jobs
    await page.click('[data-testid="clear-filters-button"]');
    await page.selectOption('[data-testid="job-type-filter"]', 'Daily Customer Sync');
    await page.click('[data-testid="apply-filters-button"]');
    await expect(jobRows).toHaveCount(1);
    await expect(jobRows.first()).toContainText('Daily Customer Sync');

    // Clear all filters and sort job history by start time in descending order
    await page.click('[data-testid="clear-filters-button"]');
    await page.click('[data-testid="sort-start-time-header"]');
    await expect(jobRows).toHaveCount(3);

    // Click on one of the job records to view detailed job execution information
    await jobRows.first().click();
    await expect(page.locator('[data-testid="job-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="job-detail-type"]')).toBeVisible();
    await expect(page.locator('[data-testid="job-detail-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="job-detail-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="job-detail-metadata"]')).toBeVisible();
    await page.click('[data-testid="close-detail-modal"]');

    // Return to job history list and select export option for CSV format
    await page.click('[data-testid="export-button"]');
    await page.selectOption('[data-testid="export-format-select"]', 'CSV');
    await page.fill('[data-testid="export-date-from"]', today);
    await page.fill('[data-testid="export-date-to"]', today);
    
    // Configure export to include all jobs from today and initiate export
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="initiate-export-button"]');
    const download = await downloadPromise;
    const csvPath = await download.path();
    expect(csvPath).toBeTruthy();

    // Open the exported CSV file and verify its contents
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    expect(csvContent).toContain('Daily Customer Sync');
    expect(csvContent).toContain('Product Catalog Sync');
    expect(csvContent).toContain('Inventory Sync');
    expect(csvContent).toContain('Completed');
    expect(csvContent).toContain('Completed with Errors');
    expect(csvContent).toContain('Stopped');

    // Return to job history UI and select export option for JSON format
    await page.click('[data-testid="export-button"]');
    await page.selectOption('[data-testid="export-format-select"]', 'JSON');
    
    // Configure export to include all jobs and initiate JSON export
    const jsonDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="initiate-export-button"]');
    const jsonDownload = await jsonDownloadPromise;
    const jsonPath = await jsonDownload.path();
    expect(jsonPath).toBeTruthy();

    // Open the exported JSON file and validate its structure and content
    const jsonContent = fs.readFileSync(jsonPath, 'utf-8');
    const jsonData = JSON.parse(jsonContent);
    expect(Array.isArray(jsonData)).toBeTruthy();
    expect(jsonData.length).toBe(3);
    expect(jsonData.some(job => job.type === 'Daily Customer Sync')).toBeTruthy();
    expect(jsonData.some(job => job.type === 'Product Catalog Sync')).toBeTruthy();
    expect(jsonData.some(job => job.type === 'Inventory Sync')).toBeTruthy();
    expect(jsonData.some(job => job.status === 'Completed')).toBeTruthy();
    expect(jsonData.some(job => job.status === 'Completed with Errors')).toBeTruthy();
    expect(jsonData.some(job => job.status === 'Stopped')).toBeTruthy();
    jsonData.forEach(job => {
      expect(job).toHaveProperty('id');
      expect(job).toHaveProperty('type');
      expect(job).toHaveProperty('status');
      expect(job).toHaveProperty('startTime');
      expect(job).toHaveProperty('metadata');
    });
  });

  test('Test access control for job history feature (error-case)', async ({ page }) => {
    // Log out any currently authenticated user to start with clean session
    await page.goto(`${BASE_URL}/logout`);
    await page.waitForTimeout(1000);

    // Attempt to access job history page URL without authentication
    await page.goto(`${BASE_URL}/sync/jobs/history`);
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Authentication required');

    // Log in using test account with 'Viewer' role (unauthorized for job history)
    await page.fill('[data-testid="email-input"]', VIEWER_EMAIL);
    await page.fill('[data-testid="password-input"]', VIEWER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to navigate to job history page via UI menu or direct URL
    const jobHistoryMenuItem = page.locator('[data-testid="job-history-menu-item"]');
    if (await jobHistoryMenuItem.isVisible()) {
      await jobHistoryMenuItem.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    }

    // Attempt direct URL access
    await page.goto(`${BASE_URL}/sync/jobs/history`);
    await expect(page.locator('[data-testid="access-denied-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('insufficient permissions');

    // Attempt to access job history API endpoint directly
    const apiResponse = await page.request.get(`${BASE_URL}/sync/jobs/history`);
    expect(apiResponse.status()).toBe(403);
    const responseBody = await apiResponse.json();
    expect(responseBody).toHaveProperty('error');
    expect(responseBody.error).toContain('Access denied');

    // Verify that no job history data is exposed in the error response
    expect(responseBody).not.toHaveProperty('jobs');
    expect(responseBody).not.toHaveProperty('data');
    expect(JSON.stringify(responseBody)).not.toContain('Daily Customer Sync');
    expect(JSON.stringify(responseBody)).not.toContain('Product Catalog Sync');

    // Log out the 'Viewer' user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    // Log in using test account with no assigned role
    await page.fill('[data-testid="email-input"]', NO_ROLE_EMAIL);
    await page.fill('[data-testid="password-input"]', NO_ROLE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Attempt to access job history page
    await page.goto(`${BASE_URL}/sync/jobs/history`);
    await expect(page.locator('[data-testid="access-denied-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Access denied');

    // Log out the user with no role
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    // Log in using test account with 'Scheduler' role (authorized)
    await page.fill('[data-testid="email-input"]', SCHEDULER_EMAIL);
    await page.fill('[data-testid="password-input"]', SCHEDULER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();

    // Navigate to job history page via UI menu
    await page.click('[data-testid="job-history-menu-item"]');

    // Access job history page
    await expect(page.locator('[data-testid="job-history-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="job-history-table"]')).toBeVisible();

    // Verify all job history features are accessible: filtering, sorting, pagination, detailed view, and export
    await expect(page.locator('[data-testid="status-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="job-type-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-from-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-to-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="apply-filters-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="clear-filters-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="sort-start-time-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-button"]')).toBeVisible();

    // Apply various filters and access detailed job information
    await page.selectOption('[data-testid="status-filter"]', 'Completed');
    await page.click('[data-testid="apply-filters-button"]');
    await page.waitForTimeout(1000);
    
    const jobRows = page.locator('[data-testid="job-history-table"] tbody tr');
    if (await jobRows.count() > 0) {
      await jobRows.first().click();
      await expect(page.locator('[data-testid="job-detail-modal"]')).toBeVisible();
      await page.click('[data-testid="close-detail-modal"]');
    }

    // Export job history in CSV format
    await page.click('[data-testid="export-button"]');
    await page.selectOption('[data-testid="export-format-select"]', 'CSV');
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="initiate-export-button"]');
    const download = await downloadPromise;
    expect(await download.path()).toBeTruthy();

    // Verify access control is logged in system audit logs
    await page.goto(`${BASE_URL}/admin/audit-logs`);
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();
    await page.fill('[data-testid="search-audit-logs"]', 'job history access');
    await page.click('[data-testid="search-button"]');
    const auditLogEntries = page.locator('[data-testid="audit-log-entry"]');
    await expect(auditLogEntries.first()).toContainText('Access denied');
  });
});