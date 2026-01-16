import { test, expect } from '@playwright/test';

test.describe('Monthly Schedule View - Story 13', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_EMAIL = 'employee@company.com';
  const EMPLOYEE_PASSWORD = 'Password123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate display of monthly schedule', async ({ page }) => {
    // Step 1: Employee logs into the portal
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 2: Employee selects monthly schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="monthly-view-button"]');
    
    // Expected Result: Monthly calendar with shifts is displayed
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-shifts"]')).toBeVisible();
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible();

    // Step 3: Employee hovers or clicks on a shift
    await shifts.first().hover();
    
    // Expected Result: Shift details are displayed
    await expect(page.locator('[data-testid="shift-details-tooltip"]')).toBeVisible({ timeout: 3000 });
    
    // Alternative: Click to show details
    await shifts.first().click();
    await expect(page.locator('[data-testid="shift-details-modal"]')).toBeVisible();
    const shiftTime = page.locator('[data-testid="shift-time"]');
    const shiftLocation = page.locator('[data-testid="shift-location"]');
    const shiftRole = page.locator('[data-testid="shift-role"]');
    await expect(shiftTime).toBeVisible();
    await expect(shiftLocation).toBeVisible();
    await expect(shiftRole).toBeVisible();
  });

  test('Verify navigation between months', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to monthly schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="monthly-view-button"]');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Get current month displayed
    const currentMonth = await page.locator('[data-testid="calendar-month-title"]').textContent();
    
    // Step 1: Employee clicks 'Next Month' button
    await page.click('[data-testid="next-month-button"]');
    
    // Expected Result: Schedule for next month is displayed
    await page.waitForLoadState('networkidle');
    const nextMonth = await page.locator('[data-testid="calendar-month-title"]').textContent();
    expect(nextMonth).not.toBe(currentMonth);
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Step 2: Employee clicks 'Previous Month' button
    await page.click('[data-testid="previous-month-button"]');
    
    // Expected Result: Schedule for previous month is displayed
    await page.waitForLoadState('networkidle');
    const previousMonth = await page.locator('[data-testid="calendar-month-title"]').textContent();
    expect(previousMonth).toBe(currentMonth);
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
  });

  test('Ensure access control for monthly schedule', async ({ page }) => {
    // Step 1: Unauthenticated user attempts to access monthly schedule
    await page.goto(`${BASE_URL}/schedule/monthly`);
    
    // Expected Result: Access denied message is shown
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page).toHaveURL(/.*login/);
    const errorMessage = page.locator('text=/access denied|unauthorized|please log in/i');
    await expect(errorMessage).toBeVisible();
    
    // Step 2: Authenticated employee accesses monthly schedule
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="monthly-view-button"]');
    
    // Expected Result: Schedule is displayed successfully
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-shifts"]')).toBeVisible();
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/api/schedules/monthly') && response.status() === 200
    );
    await responsePromise;
  });

  test('Validate successful PDF export of schedule (happy-path)', async ({ page }) => {
    // Login
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to the schedule page and select daily view
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="daily-view-button"]');
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();
    
    // Click the 'Export to PDF' button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Wait for PDF generation to complete
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');
    
    // Verify download was successful
    const path = await download.path();
    expect(path).toBeTruthy();
    
    // Return to schedule page and switch to weekly view
    await page.click('[data-testid="weekly-view-button"]');
    await expect(page.locator('[data-testid="weekly-schedule"]')).toBeVisible();
    
    // Click the 'Export to PDF' button for weekly view
    const weeklyDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Download and verify weekly view PDF
    const weeklyDownload = await weeklyDownloadPromise;
    expect(weeklyDownload.suggestedFilename()).toContain('.pdf');
    const weeklyPath = await weeklyDownload.path();
    expect(weeklyPath).toBeTruthy();
    
    // Return to schedule page and switch to monthly view
    await page.click('[data-testid="monthly-view-button"]');
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Click the 'Export to PDF' button for monthly view
    const monthlyDownloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    // Download and verify monthly view PDF
    const monthlyDownload = await monthlyDownloadPromise;
    expect(monthlyDownload.suggestedFilename()).toContain('.pdf');
    const monthlyPath = await monthlyDownload.path();
    expect(monthlyPath).toBeTruthy();
  });

  test('Verify error handling during export (error-case)', async ({ page }) => {
    // Login
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    
    // Navigate to the schedule page and verify schedule is displayed
    await page.click('[data-testid="schedule-nav-link"]');
    await page.click('[data-testid="daily-view-button"]');
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();
    
    // Configure test environment to simulate PDF generation service failure
    await page.route('**/api/schedules/export/pdf', route => {
      route.abort('failed');
    });
    
    // Click the 'Export to PDF' button
    await page.click('[data-testid="export-pdf-button"]');
    
    // Observe the system response after backend failure
    // Verify that the error message does not expose technical details or stack traces
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 5000 });
    const errorText = await errorMessage.textContent();
    expect(errorText).not.toMatch(/stack trace|exception|error code 500|internal server error/i);
    expect(errorText).toMatch(/unable to export|export failed|please try again/i);
    
    // Verify that the schedule page remains functional after the error
    await expect(page.locator('[data-testid="daily-schedule"]')).toBeVisible();
    const shifts = page.locator('[data-testid="shift-item"]');
    await expect(shifts.first()).toBeVisible();
    
    // Check that no partial or corrupted PDF file was downloaded
    let downloadOccurred = false;
    page.on('download', () => {
      downloadOccurred = true;
    });
    await page.waitForTimeout(2000);
    expect(downloadOccurred).toBe(false);
    
    // Restore PDF generation service to normal operation
    await page.unroute('**/api/schedules/export/pdf');
    
    // Click the 'Export to PDF' button again
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');
    const path = await download.path();
    expect(path).toBeTruthy();
  });
});