import { test, expect } from '@playwright/test';

test.describe('Schedule Calendar View - Story 6', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Display schedules in weekly calendar view (happy-path)', async ({ page }) => {
    // Step 1: Navigate to schedule calendar page
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-calendar-link"]');
    
    // Expected Result: Calendar loads with current week view
    await expect(page.locator('[data-testid="calendar-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-view-mode"]')).toHaveText(/week/i);
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    // Step 2: Locate and click on the employee filter dropdown
    await page.click('[data-testid="employee-filter-dropdown"]');
    await expect(page.locator('[data-testid="employee-filter-options"]')).toBeVisible();
    
    // Step 3: Select a specific employee from the filter dropdown
    await page.click('[data-testid="employee-option-john-doe"]');
    
    // Expected Result: Calendar updates to show only selected employee's shifts
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-filter-selected"]')).toHaveText('John Doe');
    const shifts = page.locator('[data-testid^="shift-"]');
    await expect(shifts.first()).toBeVisible();
    
    // Verify all visible shifts belong to selected employee
    const shiftCount = await shifts.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Step 4: Click on one of the displayed shifts in the calendar
    await page.click('[data-testid="shift-monday-morning"]');
    
    // Expected Result: Shift details popup is displayed
    await expect(page.locator('[data-testid="shift-details-popup"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-employee-name"]')).toHaveText('John Doe');
    await expect(page.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-template"]')).toBeVisible();
    
    // Step 5: Close the shift details popup
    await page.click('[data-testid="shift-details-close-button"]');
    await expect(page.locator('[data-testid="shift-details-popup"]')).not.toBeVisible();
  });

  test('Highlight scheduling conflicts in calendar (error-case)', async ({ page }) => {
    // Step 1: Navigate to the schedule calendar page
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-calendar-link"]');
    
    // Expected Result: Calendar loads successfully
    await expect(page.locator('[data-testid="calendar-container"]')).toBeVisible();
    
    // Step 2: Locate the employee with overlapping shifts in the calendar view
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');
    
    // Wait for calendar to update
    await expect(page.locator('[data-testid="employee-filter-selected"]')).toHaveText('Jane Smith');
    
    // Expected Result: Conflicts are visually highlighted
    const conflictingShift = page.locator('[data-testid="shift-conflict-tuesday"]');
    await expect(conflictingShift).toBeVisible();
    await expect(conflictingShift).toHaveClass(/conflict|highlighted|error/);
    
    // Verify conflict indicator is present
    await expect(page.locator('[data-testid="conflict-indicator"]')).toBeVisible();
    
    // Step 3: Hover over or click on one of the conflicting shifts
    await conflictingShift.hover();
    
    // Verify conflict tooltip or details appear
    await expect(page.locator('[data-testid="conflict-tooltip"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText(/overlap|conflict/i);
    
    // Click on the conflicting shift for more details
    await conflictingShift.click();
    await expect(page.locator('[data-testid="shift-details-popup"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText(/overlapping|conflict/i);
    
    // Step 4: Verify that non-conflicting shifts are displayed normally without highlighting
    await page.click('[data-testid="shift-details-close-button"]');
    
    const normalShift = page.locator('[data-testid="shift-wednesday-morning"]');
    await expect(normalShift).toBeVisible();
    await expect(normalShift).not.toHaveClass(/conflict|highlighted|error/);
    
    // Verify normal shift does not have conflict indicator
    const normalShiftConflictIndicator = normalShift.locator('[data-testid="conflict-indicator"]');
    await expect(normalShiftConflictIndicator).not.toBeVisible();
  });

  test('Filter schedules by employee', async ({ page }) => {
    // Navigate to schedule calendar page
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-calendar-link"]');
    await expect(page.locator('[data-testid="calendar-container"]')).toBeVisible();
    
    // Action: Filter by specific employee
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    
    // Expected Result: Calendar updates to show only selected employee's shifts
    await expect(page.locator('[data-testid="employee-filter-selected"]')).toHaveText('John Doe');
    const shifts = page.locator('[data-testid^="shift-"]');
    const shiftCount = await shifts.count();
    expect(shiftCount).toBeGreaterThan(0);
  });

  test('Click on shift to view details', async ({ page }) => {
    // Navigate to schedule calendar page
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="schedule-calendar-link"]');
    await expect(page.locator('[data-testid="calendar-container"]')).toBeVisible();
    
    // Action: Click on a shift
    await page.click('[data-testid="shift-monday-morning"]');
    
    // Expected Result: Shift details popup is displayed
    await expect(page.locator('[data-testid="shift-details-popup"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-employee-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-template"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
  });
});