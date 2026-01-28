import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Management - Story 4', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'managerPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful viewing of employee schedules', async ({ page }) => {
    // Step 1: Navigate to the employee schedule view
    await page.click('[data-testid="employee-schedule-menu"]');
    await expect(page.locator('[data-testid="schedule-interface"]')).toBeVisible();
    await expect(page).toHaveURL(/.*employee-schedules/);

    // Step 2: Select a date range
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="start-date-input"]');
    const today = new Date();
    const startDate = today.toISOString().split('T')[0];
    await page.fill('[data-testid="start-date-input"]', startDate);
    
    const endDate = new Date(today.setDate(today.getDate() + 7));
    const endDateStr = endDate.toISOString().split('T')[0];
    await page.fill('[data-testid="end-date-input"]', endDateStr);
    await page.click('[data-testid="apply-date-range-button"]');
    
    // Verify schedule for the selected period is displayed
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-date-range-display"]')).toContainText(startDate);
    
    // Step 3: Identify unfilled shifts
    const unfilledShifts = page.locator('[data-testid="unfilled-shift"]');
    await expect(unfilledShifts.first()).toBeVisible({ timeout: 5000 });
    
    // Verify unfilled shifts are highlighted with specific styling
    const unfilledShiftElement = unfilledShifts.first();
    await expect(unfilledShiftElement).toHaveClass(/highlighted|unfilled|warning/);
    
    // Verify schedule data is loaded
    const scheduleItems = page.locator('[data-testid="schedule-item"]');
    await expect(scheduleItems).toHaveCount(await scheduleItems.count());
    expect(await scheduleItems.count()).toBeGreaterThan(0);
  });

  test('Verify filtering of schedules by employee', async ({ page }) => {
    // Step 1: Navigate to the employee schedule view
    await page.click('[data-testid="employee-schedule-menu"]');
    await expect(page.locator('[data-testid="schedule-interface"]')).toBeVisible();
    await expect(page).toHaveURL(/.*employee-schedules/);

    // Step 2: Select a specific employee to filter by
    await page.click('[data-testid="employee-filter-dropdown"]');
    await expect(page.locator('[data-testid="employee-filter-list"]')).toBeVisible();
    
    // Select a specific employee from the dropdown
    const employeeName = 'John Doe';
    await page.click(`[data-testid="employee-option-${employeeName.toLowerCase().replace(' ', '-')}"]`);
    
    // Wait for filter to be applied
    await page.waitForResponse(response => 
      response.url().includes('/api/employeeSchedules') && response.status() === 200
    );
    
    // Verify schedule is filtered to show only that employee's shifts
    await expect(page.locator('[data-testid="active-filter-badge"]')).toContainText(employeeName);
    
    // Step 3: Verify displayed shifts
    const displayedShifts = page.locator('[data-testid="schedule-item"]');
    await expect(displayedShifts.first()).toBeVisible();
    
    // Verify each shift belongs to the selected employee
    const shiftCount = await displayedShifts.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    for (let i = 0; i < shiftCount; i++) {
      const shift = displayedShifts.nth(i);
      await expect(shift.locator('[data-testid="employee-name"]')).toContainText(employeeName);
    }
    
    // Verify no other employees' shifts are visible
    const allEmployeeNames = await displayedShifts.locator('[data-testid="employee-name"]').allTextContents();
    const allMatchSelectedEmployee = allEmployeeNames.every(name => name.includes(employeeName));
    expect(allMatchSelectedEmployee).toBeTruthy();
  });

  test('Verify filtering of schedules by shift type', async ({ page }) => {
    // Navigate to the employee schedule view
    await page.click('[data-testid="employee-schedule-menu"]');
    await expect(page.locator('[data-testid="schedule-interface"]')).toBeVisible();

    // Select shift type filter
    await page.click('[data-testid="shift-type-filter-dropdown"]');
    await expect(page.locator('[data-testid="shift-type-filter-list"]')).toBeVisible();
    
    const shiftType = 'Morning';
    await page.click(`[data-testid="shift-type-option-${shiftType.toLowerCase()}"]`);
    
    // Wait for filter to be applied
    await page.waitForResponse(response => 
      response.url().includes('/api/employeeSchedules') && response.status() === 200
    );
    
    // Verify schedule is filtered by shift type
    await expect(page.locator('[data-testid="active-filter-badge"]')).toContainText(shiftType);
    
    const displayedShifts = page.locator('[data-testid="schedule-item"]');
    const shiftCount = await displayedShifts.count();
    
    for (let i = 0; i < shiftCount; i++) {
      const shift = displayedShifts.nth(i);
      await expect(shift.locator('[data-testid="shift-type"]')).toContainText(shiftType);
    }
  });

  test('Verify export schedules functionality', async ({ page }) => {
    // Navigate to the employee schedule view
    await page.click('[data-testid="employee-schedule-menu"]');
    await expect(page.locator('[data-testid="schedule-interface"]')).toBeVisible();

    // Select a date range
    await page.click('[data-testid="date-range-picker"]');
    const today = new Date();
    const startDate = today.toISOString().split('T')[0];
    await page.fill('[data-testid="start-date-input"]', startDate);
    
    const endDate = new Date(today.setDate(today.getDate() + 7));
    const endDateStr = endDate.toISOString().split('T')[0];
    await page.fill('[data-testid="end-date-input"]', endDateStr);
    await page.click('[data-testid="apply-date-range-button"]');
    
    // Wait for schedule to load
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    
    // Click export button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-schedule-button"]');
    
    // Verify download is initiated
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/schedule.*\.(csv|xlsx|pdf)/);
  });
});