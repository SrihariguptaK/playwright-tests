import { test, expect } from '@playwright/test';

test.describe('Schedule Calendar Management', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate calendar displays correct employee schedules', async ({ page }) => {
    // Step 1: Navigate to schedule calendar page
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="calendar-view-link"]');
    
    // Expected Result: Calendar view is displayed
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-header"]')).toBeVisible();
    
    // Step 2: Apply filters for specific employee and date range
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    
    await page.click('[data-testid="date-range-filter"]');
    await page.fill('[data-testid="start-date-input"]', '2024-01-15');
    await page.fill('[data-testid="end-date-input"]', '2024-01-21');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Calendar updates to show filtered schedules
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="calendar-loading"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="filtered-employee-name"]')).toContainText('John Doe');
    
    // Step 3: Verify shifts are displayed correctly on calendar dates
    const shiftElement = page.locator('[data-testid="shift-2024-01-15"]').first();
    await expect(shiftElement).toBeVisible();
    
    await shiftElement.click();
    const shiftDetails = page.locator('[data-testid="shift-details-modal"]');
    await expect(shiftDetails).toBeVisible();
    
    // Expected Result: Shift details match assigned schedules
    await expect(shiftDetails.locator('[data-testid="shift-employee-name"]')).toContainText('John Doe');
    await expect(shiftDetails.locator('[data-testid="shift-date"]')).toContainText('2024-01-15');
    await expect(shiftDetails.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(shiftDetails.locator('[data-testid="shift-type"]')).toBeVisible();
  });

  test('Verify calendar navigation between weeks and months', async ({ page }) => {
    // Step 1: Open calendar view
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="calendar-view-link"]');
    
    // Expected Result: Current week/month displayed
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    const currentPeriodIndicator = page.locator('[data-testid="current-period-indicator"]');
    await expect(currentPeriodIndicator).toBeVisible();
    
    const initialPeriodText = await currentPeriodIndicator.textContent();
    expect(initialPeriodText).toBeTruthy();
    
    // Step 2: Click next and previous navigation buttons
    await page.click('[data-testid="calendar-next-button"]');
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Calendar updates to respective periods
    const nextPeriodText = await currentPeriodIndicator.textContent();
    expect(nextPeriodText).not.toBe(initialPeriodText);
    
    // Step 3: Verify schedule data loads for new periods
    await expect(page.locator('[data-testid="calendar-loading"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    
    // Expected Result: Schedules displayed correctly without errors
    const calendarDates = page.locator('[data-testid^="calendar-date-"]');
    await expect(calendarDates.first()).toBeVisible();
    
    // Navigate to previous period
    await page.click('[data-testid="calendar-previous-button"]');
    await page.waitForLoadState('networkidle');
    
    const previousPeriodText = await currentPeriodIndicator.textContent();
    expect(previousPeriodText).toBe(initialPeriodText);
    
    await expect(page.locator('[data-testid="calendar-loading"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    
    // Test view toggle if available
    const viewToggle = page.locator('[data-testid="calendar-view-toggle"]');
    if (await viewToggle.isVisible()) {
      await viewToggle.click();
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    }
    
    // Navigate forward and backward multiple times
    for (let i = 0; i < 3; i++) {
      await page.click('[data-testid="calendar-next-button"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    }
    
    for (let i = 0; i < 3; i++) {
      await page.click('[data-testid="calendar-previous-button"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    }
  });

  test('Validate export functionality of calendar view', async ({ page }) => {
    // Step 1: Open calendar with schedules displayed
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="calendar-view-link"]');
    
    // Expected Result: Calendar view is visible
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    
    // Verify multiple shifts are visible
    const shifts = page.locator('[data-testid^="shift-"]');
    const shiftCount = await shifts.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Capture calendar data for comparison
    const calendarData = await page.locator('[data-testid="schedule-calendar"]').textContent();
    
    // Step 2: Click export button and select PDF
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Expected Result: Export file is generated and downloaded
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toContain('.pdf');
    
    const pdfPath = await downloadPDF.path();
    expect(pdfPath).toBeTruthy();
    
    // Step 3: Verify Excel export
    await page.click('[data-testid="export-button"]');
    await expect(page.locator('[data-testid="export-menu"]')).toBeVisible();
    
    const downloadPromiseExcel = page.waitForEvent('download');
    await page.click('[data-testid="export-excel-option"]');
    
    // Expected Result: Excel file is generated and downloaded
    const downloadExcel = await downloadPromiseExcel;
    expect(downloadExcel.suggestedFilename()).toMatch(/\.(xlsx|xls)$/);
    
    const excelPath = await downloadExcel.path();
    expect(excelPath).toBeTruthy();
    
    // Verify success notification
    const successMessage = page.locator('[data-testid="export-success-message"]');
    if (await successMessage.isVisible()) {
      await expect(successMessage).toContainText(/exported|downloaded/i);
    }
  });
});