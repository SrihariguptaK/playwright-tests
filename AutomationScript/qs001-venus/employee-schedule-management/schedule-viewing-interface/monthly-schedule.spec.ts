import { test, expect } from '@playwright/test';

test.describe('Story-13: Monthly Schedule View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Login with valid credentials
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate monthly schedule display and navigation', async ({ page }) => {
    // Employee navigates to the schedule section from the main menu
    await page.click('[data-testid="schedule-menu-item"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Employee selects monthly view option
    await page.click('[data-testid="monthly-view-button"]');
    
    // Employee verifies that all shifts for the current month are visible on the calendar
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    const currentMonthHeader = page.locator('[data-testid="current-month-header"]');
    await expect(currentMonthHeader).toBeVisible();
    
    // Verify shifts are displayed
    const shifts = page.locator('[data-testid="shift-entry"]');
    await expect(shifts.first()).toBeVisible();
    const shiftCount = await shifts.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Employee clicks the next month navigation button
    const currentMonthText = await currentMonthHeader.textContent();
    await page.click('[data-testid="next-month-button"]');
    
    // Verify schedule for next month is displayed
    await page.waitForTimeout(500);
    const nextMonthText = await currentMonthHeader.textContent();
    expect(nextMonthText).not.toBe(currentMonthText);
    await expect(page.locator('[data-testid="monthly-calendar"]')).toBeVisible();
    
    // Employee clicks the previous month navigation button to return to current month
    await page.click('[data-testid="previous-month-button"]');
    await page.waitForTimeout(500);
    const returnedMonthText = await currentMonthHeader.textContent();
    expect(returnedMonthText).toBe(currentMonthText);
    
    // Employee hovers mouse cursor over a shift entry on the calendar
    const firstShift = shifts.first();
    await firstShift.hover();
    
    // Verify shift details are displayed on hover
    const shiftTooltip = page.locator('[data-testid="shift-details-tooltip"]');
    await expect(shiftTooltip).toBeVisible();
    await expect(shiftTooltip).toContainText(/\d{1,2}:\d{2}/);
    
    // Employee moves cursor away from the shift entry
    await page.mouse.move(0, 0);
    await page.waitForTimeout(300);
    
    // Employee clicks on a different shift entry
    const secondShift = shifts.nth(1);
    await secondShift.click();
    
    // Verify shift details are displayed on click
    const shiftDetailsModal = page.locator('[data-testid="shift-details-modal"]');
    await expect(shiftDetailsModal).toBeVisible();
    await expect(shiftDetailsModal).toContainText(/Shift Details/);
  });

  test('Verify responsiveness on desktop and mobile', async ({ page, context }) => {
    // Set desktop viewport
    await page.setViewportSize({ width: 1920, height: 1080 });
    
    // Employee navigates to the schedule section and selects monthly view on desktop
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="monthly-view-button"]');
    
    // Employee verifies that the calendar grid displays properly on desktop with adequate spacing and readability
    const desktopCalendar = page.locator('[data-testid="monthly-calendar"]');
    await expect(desktopCalendar).toBeVisible();
    
    const calendarBoundingBox = await desktopCalendar.boundingBox();
    expect(calendarBoundingBox?.width).toBeGreaterThan(800);
    
    // Verify calendar cells are properly sized for desktop
    const calendarCells = page.locator('[data-testid="calendar-day-cell"]');
    const firstCellBox = await calendarCells.first().boundingBox();
    expect(firstCellBox?.width).toBeGreaterThan(80);
    
    // Employee tests navigation between months using desktop interface
    await page.click('[data-testid="next-month-button"]');
    await expect(desktopCalendar).toBeVisible();
    await page.click('[data-testid="previous-month-button"]');
    await expect(desktopCalendar).toBeVisible();
    
    // Employee hovers over shifts and clicks on shifts to view details on desktop
    const shifts = page.locator('[data-testid="shift-entry"]');
    await shifts.first().hover();
    await expect(page.locator('[data-testid="shift-details-tooltip"]')).toBeVisible();
    
    await shifts.first().click();
    const shiftDetailsModal = page.locator('[data-testid="shift-details-modal"]');
    await expect(shiftDetailsModal).toBeVisible();
    
    // Close modal if present
    const closeButton = page.locator('[data-testid="close-modal-button"]');
    if (await closeButton.isVisible()) {
      await closeButton.click();
    }
    
    // Switch to mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Employee navigates to the schedule section and selects monthly view on mobile
    await page.reload();
    await page.click('[data-testid="schedule-menu-item"]');
    await page.click('[data-testid="monthly-view-button"]');
    
    // Employee verifies that the calendar grid adapts properly to mobile screen size
    const mobileCalendar = page.locator('[data-testid="monthly-calendar"]');
    await expect(mobileCalendar).toBeVisible();
    
    const mobileCalendarBox = await mobileCalendar.boundingBox();
    expect(mobileCalendarBox?.width).toBeLessThanOrEqual(375);
    
    // Verify calendar is responsive and fits mobile screen
    const mobileCells = page.locator('[data-testid="calendar-day-cell"]');
    const mobileCellBox = await mobileCells.first().boundingBox();
    expect(mobileCellBox?.width).toBeLessThan(80);
    expect(mobileCellBox?.width).toBeGreaterThan(30);
    
    // Employee tests navigation between months using mobile touch interface
    await page.click('[data-testid="next-month-button"]');
    await expect(mobileCalendar).toBeVisible();
    await page.waitForTimeout(300);
    
    await page.click('[data-testid="previous-month-button"]');
    await expect(mobileCalendar).toBeVisible();
    await page.waitForTimeout(300);
    
    // Employee taps on shifts to view details on mobile
    const mobileShifts = page.locator('[data-testid="shift-entry"]');
    await mobileShifts.first().click();
    
    const mobileShiftDetails = page.locator('[data-testid="shift-details-modal"]');
    await expect(mobileShiftDetails).toBeVisible();
    
    // Verify modal is properly sized for mobile
    const mobileModalBox = await mobileShiftDetails.boundingBox();
    expect(mobileModalBox?.width).toBeLessThanOrEqual(375);
  });
});