import { test, expect } from '@playwright/test';

test.describe('Approval Workflow Performance Monitoring', () => {
  test.beforeEach(async ({ page }) => {
    // Administrator login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate display of approval workflow KPIs', async ({ page }) => {
    // Step 1: Administrator accesses monitoring dashboard
    await page.goto('/admin/approval-metrics');
    
    // Expected Result: Dashboard displays average approval times and request counts
    await expect(page.locator('[data-testid="approval-metrics-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="average-approval-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="approved-requests-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejected-requests-count"]')).toBeVisible();
    
    // Verify metrics display actual values
    const avgApprovalTime = await page.locator('[data-testid="average-approval-time"]').textContent();
    expect(avgApprovalTime).toBeTruthy();
    expect(avgApprovalTime).toMatch(/\d+/);
    
    const pendingCount = await page.locator('[data-testid="pending-requests-count"]').textContent();
    expect(pendingCount).toMatch(/\d+/);
    
    // Step 2: Administrator applies date range and workflow filters
    await page.click('[data-testid="date-range-filter"]');
    await page.click('[data-testid="date-range-last-30-days"]');
    
    await page.click('[data-testid="workflow-filter-dropdown"]');
    await page.click('[data-testid="workflow-option-purchase-order"]');
    
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Dashboard updates metrics accordingly
    await page.waitForResponse(response => 
      response.url().includes('/api/approval-metrics') && response.status() === 200
    );
    
    await expect(page.locator('[data-testid="applied-filters-display"]')).toContainText('Last 30 Days');
    await expect(page.locator('[data-testid="applied-filters-display"]')).toContainText('Purchase Order');
    
    // Verify metrics have updated
    const updatedAvgTime = await page.locator('[data-testid="average-approval-time"]').textContent();
    expect(updatedAvgTime).toBeTruthy();
  });

  test('Verify export of metrics reports', async ({ page }) => {
    // Navigate to monitoring dashboard
    await page.goto('/admin/approval-metrics');
    await expect(page.locator('[data-testid="approval-metrics-dashboard"]')).toBeVisible();
    
    // Step 1: Administrator clicks export button for CSV
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-csv"]');
    
    // Expected Result: Report is generated and downloaded in CSV format
    const downloadCSV = await downloadPromiseCSV;
    expect(downloadCSV.suggestedFilename()).toContain('.csv');
    expect(downloadCSV.suggestedFilename()).toContain('approval-metrics');
    
    // Wait for download to complete
    await downloadCSV.saveAs('/tmp/' + downloadCSV.suggestedFilename());
    
    // Step 1 (PDF): Administrator clicks export button for PDF
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    await page.click('[data-testid="export-format-pdf"]');
    
    // Expected Result: Report is generated and downloaded in PDF format
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    expect(downloadPDF.suggestedFilename()).toContain('approval-metrics');
    
    await downloadPDF.saveAs('/tmp/' + downloadPDF.suggestedFilename());
  });

  test('Test dashboard load performance', async ({ page }) => {
    // Step 1: Administrator opens dashboard under normal load
    const startTime = Date.now();
    
    await page.goto('/admin/approval-metrics');
    
    // Wait for all key metrics to be visible
    await expect(page.locator('[data-testid="approval-metrics-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="average-approval-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-requests-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="approved-requests-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="rejected-requests-count"]')).toBeVisible();
    
    // Wait for charts to load
    await expect(page.locator('[data-testid="approval-trends-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="workflow-breakdown-chart"]')).toBeVisible();
    
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;
    
    // Expected Result: Dashboard loads within 3 seconds
    expect(loadTime).toBeLessThan(3);
    
    // Verify all critical dashboard elements are present
    await expect(page.locator('[data-testid="overdue-approvals-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="date-range-filter"]')).toBeVisible();
    await expect(page.locator('[data-testid="workflow-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-button"]')).toBeVisible();
  });
});