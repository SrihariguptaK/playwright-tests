import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

test.describe('Employee Performance Dashboard - Story 18', () => {
  const employeeACredentials = {
    username: 'employee.a@company.com',
    password: 'SecurePass123!'
  };

  const employeeBCredentials = {
    username: 'employee.b@company.com',
    password: 'SecurePass456!'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate dashboard displays assigned metrics and review cycles (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the system login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 2: Enter valid employee credentials and click Login button
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');

    // Step 3: Verify the Performance Dashboard loads completely
    await page.waitForURL(/.*dashboard/, { timeout: 3000 });
    await expect(page.locator('[data-testid="performance-dashboard"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('h1')).toContainText('Performance Dashboard');

    // Step 4: Review the list of assigned performance metrics displayed on the dashboard
    const metricsSection = page.locator('[data-testid="assigned-metrics-section"]');
    await expect(metricsSection).toBeVisible();
    const metricsList = page.locator('[data-testid="metric-item"]');
    const metricsCount = await metricsList.count();
    expect(metricsCount).toBeGreaterThan(0);

    // Step 5: Review the list of review cycles displayed on the dashboard
    const reviewCyclesSection = page.locator('[data-testid="review-cycles-section"]');
    await expect(reviewCyclesSection).toBeVisible();
    const reviewCyclesList = page.locator('[data-testid="review-cycle-item"]');
    const reviewCyclesCount = await reviewCyclesList.count();
    expect(reviewCyclesCount).toBeGreaterThan(0);

    // Step 6: Verify the accuracy of displayed metrics against expected assignments
    const firstMetric = metricsList.first();
    await expect(firstMetric.locator('[data-testid="metric-name"]')).toBeVisible();
    await expect(firstMetric.locator('[data-testid="metric-target"]')).toBeVisible();
    await expect(firstMetric.locator('[data-testid="metric-current-value"]')).toBeVisible();

    // Step 7: Verify the accuracy of review cycle dates and status
    const firstReviewCycle = reviewCyclesList.first();
    await expect(firstReviewCycle.locator('[data-testid="cycle-name"]')).toBeVisible();
    await expect(firstReviewCycle.locator('[data-testid="cycle-date"]')).toBeVisible();
    await expect(firstReviewCycle.locator('[data-testid="cycle-status"]')).toBeVisible();
    
    const cycleStatus = await firstReviewCycle.locator('[data-testid="cycle-status"]').textContent();
    expect(['Active', 'Upcoming', 'Completed']).toContain(cycleStatus?.trim());

    // Step 8: Locate and click the Export to PDF button
    const exportButton = page.locator('[data-testid="export-pdf-button"]');
    await expect(exportButton).toBeVisible();
    
    // Step 9: Confirm the export action and wait for download
    const downloadPromise = page.waitForEvent('download');
    await exportButton.click();
    const download = await downloadPromise;

    // Step 10: Open the downloaded PDF file and verify
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    // Verify file exists and has content
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    const stats = fs.statSync(downloadPath);
    expect(stats.size).toBeGreaterThan(0);
    
    // Verify filename contains expected pattern
    expect(download.suggestedFilename()).toMatch(/performance.*\.pdf/i);
    
    // Cleanup
    if (fs.existsSync(downloadPath)) {
      fs.unlinkSync(downloadPath);
    }
  });

  test('Ensure dashboard access is restricted to logged-in employee (error-case)', async ({ page }) => {
    // Step 1: Log in as Employee A with valid credentials
    await page.fill('[data-testid="username-input"]', employeeACredentials.username);
    await page.fill('[data-testid="password-input"]', employeeACredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard to load
    await page.waitForURL(/.*dashboard/);
    await expect(page.locator('[data-testid="performance-dashboard"]')).toBeVisible();

    // Step 2: Note the current dashboard URL for Employee A
    const employeeADashboardUrl = page.url();
    expect(employeeADashboardUrl).toContain('dashboard');
    
    // Verify Employee A's data is displayed
    await expect(page.locator('[data-testid="employee-name"]')).toContainText('Employee A');
    const employeeAMetrics = await page.locator('[data-testid="metric-item"]').count();
    expect(employeeAMetrics).toBeGreaterThan(0);

    // Step 3: Manually modify the URL in the browser address bar to Employee B's dashboard URL
    const employeeBDashboardUrl = employeeADashboardUrl.replace(/user\/[^/]+/, 'user/employee-b');
    
    // Step 4: Press Enter to navigate to Employee B's dashboard URL
    await page.goto(employeeBDashboardUrl);
    
    // Wait for response
    await page.waitForLoadState('networkidle');

    // Step 5: Verify that no data from Employee B's dashboard is displayed
    const employeeBName = page.locator('[data-testid="employee-name"]');
    if (await employeeBName.isVisible()) {
      await expect(employeeBName).not.toContainText('Employee B');
    }
    
    // Step 6: Verify the user is redirected back to Employee A's dashboard or an error page
    const currentUrl = page.url();
    const isRedirectedToEmployeeA = currentUrl === employeeADashboardUrl || currentUrl.includes('employee-a');
    const isErrorPage = await page.locator('[data-testid="error-message"]').isVisible() || 
                        await page.locator('[data-testid="access-denied"]').isVisible() ||
                        await page.locator('text=Access Denied').isVisible() ||
                        await page.locator('text=Unauthorized').isVisible();
    
    expect(isRedirectedToEmployeeA || isErrorPage).toBeTruthy();
    
    // If error page is shown, verify error message
    if (isErrorPage) {
      const errorMessage = page.locator('[data-testid="error-message"], [data-testid="access-denied"]');
      await expect(errorMessage).toBeVisible();
      const errorText = await errorMessage.textContent();
      expect(errorText?.toLowerCase()).toMatch(/access denied|unauthorized|permission/i);
    }
    
    // If redirected back, verify Employee A's data is still shown
    if (isRedirectedToEmployeeA) {
      await expect(page.locator('[data-testid="employee-name"]')).toContainText('Employee A');
      const currentMetrics = await page.locator('[data-testid="metric-item"]').count();
      expect(currentMetrics).toBe(employeeAMetrics);
    }
  });
});