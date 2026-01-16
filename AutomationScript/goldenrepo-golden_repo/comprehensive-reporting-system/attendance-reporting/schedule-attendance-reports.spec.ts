import { test, expect } from '@playwright/test';

test.describe('Schedule Automated Attendance Report Generation', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Specialist
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hr.specialist@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Create and save attendance report schedule', async ({ page }) => {
    // Step 1: Access attendance report scheduling UI
    await page.goto('/reports/attendance/schedule');
    await expect(page.locator('[data-testid="scheduling-interface"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Schedule Attendance Reports');

    // Step 2: Define schedule parameters and recipients
    await page.selectOption('[data-testid="schedule-frequency-select"]', 'weekly');
    await page.selectOption('[data-testid="schedule-day-select"]', 'monday');
    await page.fill('[data-testid="schedule-time-input"]', '09:00');
    
    // Select report type
    await page.selectOption('[data-testid="report-type-select"]', 'full-attendance');
    
    // Add recipients
    await page.fill('[data-testid="recipient-email-input"]', 'manager1@company.com');
    await page.click('[data-testid="add-recipient-button"]');
    await expect(page.locator('[data-testid="recipient-list"]')).toContainText('manager1@company.com');
    
    await page.fill('[data-testid="recipient-email-input"]', 'manager2@company.com');
    await page.click('[data-testid="add-recipient-button"]');
    await expect(page.locator('[data-testid="recipient-list"]')).toContainText('manager2@company.com');
    
    // Add schedule name
    await page.fill('[data-testid="schedule-name-input"]', 'Weekly Attendance Report - Management');
    
    // Verify parameters are accepted
    await expect(page.locator('[data-testid="schedule-frequency-select"]')).toHaveValue('weekly');
    await expect(page.locator('[data-testid="schedule-time-input"]')).toHaveValue('09:00');
    
    // Step 3: Save schedule
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify schedule saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');
    
    // Verify schedule appears in the list
    await page.goto('/reports/attendance/schedule');
    await expect(page.locator('[data-testid="scheduled-reports-list"]')).toContainText('Weekly Attendance Report - Management');
    await expect(page.locator('[data-testid="schedule-status"]').first()).toContainText('Active');
  });

  test('Verify automated report delivery', async ({ page }) => {
    // Setup: Create a schedule for immediate execution (for testing purposes)
    await page.goto('/reports/attendance/schedule');
    await expect(page.locator('[data-testid="scheduling-interface"]')).toBeVisible();
    
    // Configure immediate schedule for testing
    await page.selectOption('[data-testid="schedule-frequency-select"]', 'immediate');
    await page.selectOption('[data-testid="report-type-select"]', 'daily-attendance');
    
    // Add test recipient
    await page.fill('[data-testid="recipient-email-input"]', 'test.recipient@company.com');
    await page.click('[data-testid="add-recipient-button"]');
    
    await page.fill('[data-testid="schedule-name-input"]', 'Test Immediate Delivery');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule saved successfully');
    
    // Step 1: Wait for scheduled report generation time
    await page.goto('/reports/attendance/schedule/logs');
    
    // Wait for report generation to complete (poll for status)
    await page.waitForTimeout(5000); // Allow time for background job
    await page.reload();
    
    // Verify report was generated and emailed
    const latestLog = page.locator('[data-testid="report-log-entry"]').first();
    await expect(latestLog).toBeVisible();
    await expect(latestLog.locator('[data-testid="log-status"]')).toContainText('Success');
    await expect(latestLog.locator('[data-testid="log-report-name"]')).toContainText('Test Immediate Delivery');
    
    // Step 2: Check recipient inbox (simulated via email log)
    await page.click(latestLog.locator('[data-testid="view-details-button"]'));
    await expect(page.locator('[data-testid="email-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-recipient"]')).toContainText('test.recipient@company.com');
    await expect(page.locator('[data-testid="email-status"]')).toContainText('Delivered');
    await expect(page.locator('[data-testid="email-subject"]')).toContainText('Attendance Report');
    
    // Step 3: Review report content
    await page.click('[data-testid="view-report-button"]');
    await expect(page.locator('[data-testid="report-viewer"]')).toBeVisible();
    
    // Verify report data is accurate and complete
    await expect(page.locator('[data-testid="report-title"]')).toContainText('Daily Attendance Report');
    await expect(page.locator('[data-testid="report-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-data-table"]')).toBeVisible();
    
    // Verify report contains expected columns
    await expect(page.locator('[data-testid="report-header-employee"]')).toContainText('Employee');
    await expect(page.locator('[data-testid="report-header-date"]')).toContainText('Date');
    await expect(page.locator('[data-testid="report-header-status"]')).toContainText('Status');
    await expect(page.locator('[data-testid="report-header-hours"]')).toContainText('Hours');
    
    // Verify report contains data rows
    const dataRows = page.locator('[data-testid="report-data-row"]');
    await expect(dataRows).not.toHaveCount(0);
    
    // Verify report summary section
    await expect(page.locator('[data-testid="report-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-employees"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-present"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-absent"]')).toBeVisible();
  });
});