import { test, expect } from '@playwright/test';

test.describe('Performance Report Scheduling', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Team Lead
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'teamlead@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Create and save performance report schedule', async ({ page }) => {
    // Step 1: Navigate to the performance reports section from the main dashboard
    await page.click('[data-testid="performance-reports-menu"]');
    await expect(page.locator('[data-testid="performance-reports-section"]')).toBeVisible();
    
    // Step 2: Click on 'Schedule Report' or 'Automated Delivery' button
    await page.click('[data-testid="schedule-report-button"]');
    await expect(page.locator('[data-testid="scheduling-interface"]')).toBeVisible();
    
    // Step 3: Select report type as 'Performance Report' from the dropdown menu
    await page.click('[data-testid="report-type-dropdown"]');
    await page.click('[data-testid="report-type-option-performance"]');
    await expect(page.locator('[data-testid="report-type-dropdown"]')).toContainText('Performance Report');
    
    // Step 4: Define schedule frequency and select specific time
    await page.click('[data-testid="schedule-frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-daily"]');
    await page.fill('[data-testid="schedule-time-input"]', '09:00');
    
    // Step 5: Enter or select recipient email addresses
    await page.fill('[data-testid="recipients-input"]', 'stakeholder1@company.com');
    await page.press('[data-testid="recipients-input"]', 'Enter');
    await page.fill('[data-testid="recipients-input"]', 'stakeholder2@company.com');
    await page.press('[data-testid="recipients-input"]', 'Enter');
    await expect(page.locator('[data-testid="recipient-tag"]').first()).toContainText('stakeholder1@company.com');
    await expect(page.locator('[data-testid="recipient-tag"]').nth(1)).toContainText('stakeholder2@company.com');
    
    // Step 6: Configure additional report parameters
    await page.click('[data-testid="date-range-dropdown"]');
    await page.click('[data-testid="date-range-option-last-7-days"]');
    await page.click('[data-testid="metrics-dropdown"]');
    await page.click('[data-testid="metric-option-response-time"]');
    await page.click('[data-testid="metric-option-throughput"]');
    await page.click('[data-testid="report-format-dropdown"]');
    await page.click('[data-testid="format-option-pdf"]');
    
    // Step 7: Click 'Save Schedule' button
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');
    
    // Step 8: Verify the newly created schedule appears in the list
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    const scheduleRow = page.locator('[data-testid="schedule-row"]').first();
    await expect(scheduleRow).toContainText('Performance Report');
    await expect(scheduleRow).toContainText('Daily');
    await expect(scheduleRow).toContainText('09:00');
  });

  test('Verify automated performance report delivery', async ({ page }) => {
    // Step 1: Note the scheduled report generation time from the scheduled reports list
    await page.click('[data-testid="performance-reports-menu"]');
    await page.click('[data-testid="scheduled-reports-tab"]');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toBeVisible();
    
    const scheduleRow = page.locator('[data-testid="schedule-row"]').first();
    const scheduledTime = await scheduleRow.locator('[data-testid="schedule-time"]').textContent();
    const nextExecution = await scheduleRow.locator('[data-testid="next-execution-time"]').textContent();
    
    // Step 2: Wait for scheduled report generation time (simulated by triggering manual execution for testing)
    await page.click('[data-testid="trigger-now-button"]');
    await expect(page.locator('[data-testid="execution-triggered-message"]')).toBeVisible();
    
    // Allow processing time
    await page.waitForTimeout(3000);
    
    // Step 3: Navigate to the scheduled reports execution logs or history section
    await page.click('[data-testid="execution-logs-tab"]');
    await expect(page.locator('[data-testid="execution-logs-section"]')).toBeVisible();
    
    const latestExecution = page.locator('[data-testid="execution-log-row"]').first();
    await expect(latestExecution.locator('[data-testid="execution-status"]')).toContainText('Success');
    await expect(latestExecution.locator('[data-testid="report-type"]')).toContainText('Performance Report');
    
    // Step 4-6: Access recipient email inbox and verify email (simulated through system verification)
    const recipientsList = await latestExecution.locator('[data-testid="recipients-delivered"]').textContent();
    expect(recipientsList).toContain('stakeholder1@company.com');
    expect(recipientsList).toContain('stakeholder2@company.com');
    
    // Step 7: Review report content by downloading from execution log
    await latestExecution.click();
    await expect(page.locator('[data-testid="execution-details-panel"]')).toBeVisible();
    
    const reportPreview = page.locator('[data-testid="report-preview"]');
    await expect(reportPreview).toBeVisible();
    await expect(reportPreview.locator('[data-testid="report-title"]')).toContainText('Performance Report');
    await expect(reportPreview.locator('[data-testid="report-date-range"]')).toBeVisible();
    await expect(reportPreview.locator('[data-testid="report-metrics"]')).toBeVisible();
    
    // Verify metrics are present
    await expect(reportPreview.locator('[data-testid="metric-response-time"]')).toBeVisible();
    await expect(reportPreview.locator('[data-testid="metric-throughput"]')).toBeVisible();
    
    // Step 8: Verify all configured recipients received the report
    const deliveryStatus = page.locator('[data-testid="delivery-status-list"]');
    await expect(deliveryStatus.locator('[data-testid="recipient-status"]').filter({ hasText: 'stakeholder1@company.com' })).toContainText('Delivered');
    await expect(deliveryStatus.locator('[data-testid="recipient-status"]').filter({ hasText: 'stakeholder2@company.com' })).toContainText('Delivered');
    
    // Step 9: Return to system and verify execution log shows successful delivery
    await page.click('[data-testid="close-details-button"]');
    await expect(latestExecution.locator('[data-testid="delivery-count"]')).toContainText('2/2');
    await expect(latestExecution.locator('[data-testid="execution-status"]')).toContainText('Success');
  });
});