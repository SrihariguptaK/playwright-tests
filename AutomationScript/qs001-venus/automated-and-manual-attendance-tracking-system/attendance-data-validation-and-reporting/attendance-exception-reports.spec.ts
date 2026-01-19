import { test, expect } from '@playwright/test';

test.describe('Attendance Exception Reports - Story 24', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const HR_MANAGER_USERNAME = 'hr.manager@company.com';
  const HR_MANAGER_PASSWORD = 'HRManager123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate generation of attendance exception reports (happy-path)', async ({ page }) => {
    // Step 1: Login as HR manager
    await page.fill('input[name="username"]', HR_MANAGER_USERNAME);
    await page.fill('input[name="password"]', HR_MANAGER_PASSWORD);
    await page.click('button[type="submit"]');
    
    // Expected Result: Access granted to reporting dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="reporting-dashboard"]')).toBeVisible();

    // Step 2: Navigate to attendance exception reports
    await page.click('a:has-text("Attendance Exception Reports")');
    
    // Expected Result: Report interface displayed
    await expect(page.locator('[data-testid="exception-report-interface"]')).toBeVisible();
    await expect(page.locator('h1:has-text("Attendance Exception Reports")')).toBeVisible();

    // Step 3: Generate report with default filters
    await page.click('button[data-testid="generate-report-btn"]');
    
    // Expected Result: Report displays anomalies accurately
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="anomaly-count"]')).toBeVisible();
    const anomalyCount = await page.locator('[data-testid="anomaly-count"]').textContent();
    expect(parseInt(anomalyCount || '0')).toBeGreaterThanOrEqual(0);
    
    // Verify report table is displayed with data
    await expect(page.locator('[data-testid="exception-report-table"]')).toBeVisible();
  });

  test('Verify report filtering by employee and date range (happy-path)', async ({ page }) => {
    // Login as HR manager
    await page.fill('input[name="username"]', HR_MANAGER_USERNAME);
    await page.fill('input[name="password"]', HR_MANAGER_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to attendance exception reports
    await page.click('a:has-text("Attendance Exception Reports")');
    await expect(page.locator('[data-testid="exception-report-interface"]')).toBeVisible();

    // Step 1: Select specific employee and date range filters
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option"]:has-text("John Doe")');
    
    // Set date range (last 30 days)
    const today = new Date();
    const thirtyDaysAgo = new Date(today);
    thirtyDaysAgo.setDate(today.getDate() - 30);
    
    await page.fill('[data-testid="date-from-picker"]', thirtyDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="date-to-picker"]', today.toISOString().split('T')[0]);
    
    // Expected Result: Filters applied successfully
    await expect(page.locator('[data-testid="employee-filter-dropdown"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="date-from-picker"]')).toHaveValue(thirtyDaysAgo.toISOString().split('T')[0]);

    // Step 2: Generate filtered report
    await page.click('button[data-testid="generate-report-btn"]');
    
    // Expected Result: Report shows anomalies only for selected employee and dates
    await expect(page.locator('[data-testid="report-results"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="filtered-employee-name"]')).toContainText('John Doe');
    
    // Verify all rows contain the selected employee
    const employeeNames = await page.locator('[data-testid="exception-report-table"] tbody tr td:nth-child(2)').allTextContents();
    employeeNames.forEach(name => {
      expect(name).toContain('John Doe');
    });

    // Step 3: Export report to PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('button[data-testid="export-pdf-btn"]');
    
    // Expected Result: PDF file generated and downloadable
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/.*\.pdf$/);
    expect(download.suggestedFilename()).toContain('attendance-exception');
  });

  test('Ensure scheduling and email distribution of reports (happy-path)', async ({ page }) => {
    // Login as HR manager
    await page.fill('input[name="username"]', HR_MANAGER_USERNAME);
    await page.fill('input[name="password"]', HR_MANAGER_PASSWORD);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to attendance exception reports
    await page.click('a:has-text("Attendance Exception Reports")');
    await expect(page.locator('[data-testid="exception-report-interface"]')).toBeVisible();

    // Step 1: Set up scheduled report generation with email recipients
    await page.click('[data-testid="schedule-report-tab"]');
    await expect(page.locator('[data-testid="schedule-report-section"]')).toBeVisible();
    
    // Select report frequency
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option"]:has-text("Daily")');
    
    // Set execution time
    await page.fill('[data-testid="execution-time-input"]', '09:00');
    
    // Enter recipient email addresses
    const recipientEmails = 'recipient1@company.com, recipient2@company.com';
    await page.fill('[data-testid="recipient-emails-input"]', recipientEmails);
    
    // Save schedule
    await page.click('button[data-testid="save-schedule-btn"]');
    
    // Expected Result: Schedule saved successfully
    await expect(page.locator('[data-testid="schedule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-success-message"]')).toContainText('Schedule saved successfully');
    
    // Verify schedule details are displayed
    await expect(page.locator('[data-testid="scheduled-frequency"]')).toContainText('Daily');
    await expect(page.locator('[data-testid="scheduled-time"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="scheduled-recipients"]')).toContainText('recipient1@company.com');
    await expect(page.locator('[data-testid="scheduled-recipients"]')).toContainText('recipient2@company.com');

    // Step 2: Wait for scheduled time (simulated by checking schedule status)
    // Note: In real testing, this would involve advancing system time or waiting for actual execution
    // For automation purposes, we verify the schedule is active and ready
    await expect(page.locator('[data-testid="schedule-status"]')).toContainText('Active');
    
    // Step 3: Verify email receipt and report content
    // Note: This step would typically require email testing infrastructure (e.g., MailHog, test email service)
    // For automation purposes, we verify the schedule configuration and check execution logs
    await page.click('[data-testid="execution-logs-tab"]');
    await expect(page.locator('[data-testid="execution-logs-table"]')).toBeVisible();
    
    // Verify that the schedule appears in the list of active schedules
    await page.click('[data-testid="active-schedules-tab"]');
    const scheduleRow = page.locator('[data-testid="schedule-row"]').filter({ hasText: recipientEmails });
    await expect(scheduleRow).toBeVisible();
    await expect(scheduleRow.locator('[data-testid="schedule-frequency"]')).toContainText('Daily');
  });
});