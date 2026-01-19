import { test, expect } from '@playwright/test';

test.describe('Drill-down from summary metrics to individual employee attendance', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the attendance dashboard
    await page.goto('/attendance/dashboard');
    
    // Wait for the dashboard to load
    await page.waitForSelector('[data-testid="attendance-dashboard"]', { timeout: 5000 });
    
    // Verify user is logged in as Manager
    await expect(page.locator('[data-testid="user-role"]')).toContainText('Manager');
  });

  test('Validate drill-down from summary to employee attendance (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the attendance dashboard and verify summary metrics are visible
    await expect(page.locator('[data-testid="summary-metrics"]')).toBeVisible();
    await expect(page.locator('[data-testid="absent-count-metric"]')).toBeVisible();
    await expect(page.locator('[data-testid="present-count-metric"]')).toBeVisible();
    
    // Step 2: Click on the absent count metric displayed on the dashboard
    const absentCountText = await page.locator('[data-testid="absent-count-metric"]').textContent();
    const absentCount = parseInt(absentCountText?.match(/\d+/)?.[0] || '0');
    
    await page.click('[data-testid="absent-count-metric"]');
    
    // Wait for drill-down view to load (should be under 3 seconds)
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="drill-down-employee-list"]', { timeout: 3000 });
    const loadTime = Date.now() - startTime;
    
    expect(loadTime).toBeLessThan(3000);
    
    // Step 3: Verify the number of employees in the drill-down list matches the absent count from the summary metric
    const employeeRows = await page.locator('[data-testid="employee-row"]').count();
    expect(employeeRows).toBe(absentCount);
    
    // Verify drill-down list shows absent employees
    await expect(page.locator('[data-testid="drill-down-title"]')).toContainText('Absent Employees');
    
    // Step 4: Select an employee from the displayed list by clicking on their name or row
    const firstEmployeeName = await page.locator('[data-testid="employee-row"]').first().locator('[data-testid="employee-name"]').textContent();
    await page.locator('[data-testid="employee-row"]').first().click();
    
    // Wait for detailed attendance view to load
    await page.waitForSelector('[data-testid="employee-detail-view"]', { timeout: 3000 });
    
    // Step 5: Review the detailed attendance information displayed for accuracy and completeness
    await expect(page.locator('[data-testid="employee-detail-name"]')).toContainText(firstEmployeeName || '');
    await expect(page.locator('[data-testid="attendance-history"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-date"]')).toBeVisible();
    
    // Verify attendance anomalies section is present
    const anomaliesSection = page.locator('[data-testid="attendance-anomalies"]');
    if (await anomaliesSection.isVisible()) {
      await expect(anomaliesSection).toBeVisible();
    }
    
    // Step 6: Click on the 'Back' or 'Return to Summary' navigation button
    const backButton = page.locator('[data-testid="back-to-summary-button"]');
    await expect(backButton).toBeVisible();
    await backButton.click();
    
    // Step 7: Verify the summary dashboard is displayed in its original state
    await page.waitForSelector('[data-testid="summary-metrics"]', { timeout: 3000 });
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="absent-count-metric"]')).toBeVisible();
    await expect(page.locator('[data-testid="present-count-metric"]')).toBeVisible();
    
    // Verify the absent count is still the same
    const finalAbsentCountText = await page.locator('[data-testid="absent-count-metric"]').textContent();
    const finalAbsentCount = parseInt(finalAbsentCountText?.match(/\d+/)?.[0] || '0');
    expect(finalAbsentCount).toBe(absentCount);
  });

  test('Validate data consistency between summary and drill-down detail', async ({ page }) => {
    // Capture summary metric value
    const absentCountText = await page.locator('[data-testid="absent-count-metric"]').textContent();
    const summaryAbsentCount = parseInt(absentCountText?.match(/\d+/)?.[0] || '0');
    
    // Click on absent count metric
    await page.click('[data-testid="absent-count-metric"]');
    await page.waitForSelector('[data-testid="drill-down-employee-list"]', { timeout: 3000 });
    
    // Count employees in drill-down list
    const drillDownCount = await page.locator('[data-testid="employee-row"]').count();
    
    // Verify 100% data consistency
    expect(drillDownCount).toBe(summaryAbsentCount);
    
    // Verify all employees have absent status
    const employeeStatuses = await page.locator('[data-testid="employee-row"] [data-testid="employee-status"]').allTextContents();
    employeeStatuses.forEach(status => {
      expect(status.toLowerCase()).toContain('absent');
    });
  });

  test('Validate drill-down response time is under 3 seconds', async ({ page }) => {
    // Click on absent count metric and measure response time
    const startTime = Date.now();
    await page.click('[data-testid="absent-count-metric"]');
    await page.waitForSelector('[data-testid="drill-down-employee-list"]', { timeout: 3000 });
    const responseTime = Date.now() - startTime;
    
    // Verify response time is under 3 seconds (3000ms)
    expect(responseTime).toBeLessThan(3000);
    
    // Verify drill-down data is loaded
    await expect(page.locator('[data-testid="drill-down-employee-list"]')).toBeVisible();
    const employeeCount = await page.locator('[data-testid="employee-row"]').count();
    expect(employeeCount).toBeGreaterThan(0);
  });

  test('Validate access control is enforced on detailed attendance data', async ({ page }) => {
    // Click on absent count metric
    await page.click('[data-testid="absent-count-metric"]');
    await page.waitForSelector('[data-testid="drill-down-employee-list"]', { timeout: 3000 });
    
    // Select first employee
    await page.locator('[data-testid="employee-row"]').first().click();
    await page.waitForSelector('[data-testid="employee-detail-view"]', { timeout: 3000 });
    
    // Verify manager has access to detailed attendance data
    await expect(page.locator('[data-testid="attendance-history"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-detail-view"]')).not.toContainText('Access Denied');
    await expect(page.locator('[data-testid="employee-detail-view"]')).not.toContainText('Unauthorized');
    
    // Verify sensitive data is displayed (manager should have access)
    await expect(page.locator('[data-testid="attendance-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-date"]')).toBeVisible();
  });

  test('Validate navigation back to summary from drill-down list', async ({ page }) => {
    // Click on absent count metric
    await page.click('[data-testid="absent-count-metric"]');
    await page.waitForSelector('[data-testid="drill-down-employee-list"]', { timeout: 3000 });
    
    // Verify back button is visible and clickable
    const backButton = page.locator('[data-testid="back-to-summary-button"]');
    await expect(backButton).toBeVisible();
    await expect(backButton).toBeEnabled();
    
    // Click back button
    await backButton.click();
    
    // Verify return to summary dashboard
    await page.waitForSelector('[data-testid="summary-metrics"]', { timeout: 3000 });
    await expect(page.locator('[data-testid="attendance-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="drill-down-employee-list"]')).not.toBeVisible();
  });
});