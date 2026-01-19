import { test, expect } from '@playwright/test';

test.describe('Schedule Calendar - Manager View', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'ManagerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate calendar displays employee schedules correctly', async ({ page }) => {
    // Step 1: Navigate to schedule calendar page
    await page.click('text=Schedule Calendar');
    await expect(page).toHaveURL(/.*schedule-calendar/);
    
    // Expected Result: Calendar is displayed with current month
    await expect(page.locator('[data-testid="calendar-container"]')).toBeVisible();
    const currentMonth = new Date().toLocaleString('default', { month: 'long', year: 'numeric' });
    await expect(page.locator('[data-testid="calendar-month-header"]')).toContainText(currentMonth.split(' ')[0]);
    
    // Step 2: Apply filter for specific employee
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    
    // Expected Result: Calendar updates to show only selected employee's shifts
    await expect(page.locator('[data-testid="calendar-container"]')).toBeVisible();
    const employeeShifts = page.locator('[data-testid="shift-card"]');
    await expect(employeeShifts.first()).toBeVisible();
    await expect(employeeShifts.first()).toContainText('John Doe');
    
    // Step 3: Navigate to next month
    await page.click('[data-testid="next-month-button"]');
    
    // Expected Result: Calendar updates to next month without delay
    await page.waitForLoadState('networkidle', { timeout: 3000 });
    const nextMonth = new Date();
    nextMonth.setMonth(nextMonth.getMonth() + 1);
    const expectedMonth = nextMonth.toLocaleString('default', { month: 'long' });
    await expect(page.locator('[data-testid="calendar-month-header"]')).toContainText(expectedMonth);
  });

  test('Verify shift types and statuses are highlighted distinctly', async ({ page }) => {
    // Step 1: Navigate to schedule calendar page and view calendar with multiple shift types
    await page.click('text=Schedule Calendar');
    await expect(page).toHaveURL(/.*schedule-calendar/);
    await expect(page.locator('[data-testid="calendar-container"]')).toBeVisible();
    
    // Expected Result: Different shift types are visually distinct
    const morningShift = page.locator('[data-testid="shift-card"][data-shift-type="morning"]').first();
    const eveningShift = page.locator('[data-testid="shift-card"][data-shift-type="evening"]').first();
    const nightShift = page.locator('[data-testid="shift-card"][data-shift-type="night"]').first();
    
    // Verify shifts are visible
    await expect(morningShift).toBeVisible();
    await expect(eveningShift).toBeVisible();
    await expect(nightShift).toBeVisible();
    
    // Verify distinct visual styling (background colors)
    const morningColor = await morningShift.evaluate((el) => window.getComputedStyle(el).backgroundColor);
    const eveningColor = await eveningShift.evaluate((el) => window.getComputedStyle(el).backgroundColor);
    const nightColor = await nightShift.evaluate((el) => window.getComputedStyle(el).backgroundColor);
    
    expect(morningColor).not.toBe(eveningColor);
    expect(eveningColor).not.toBe(nightColor);
    expect(morningColor).not.toBe(nightColor);
    
    // Verify shift statuses are also distinct
    const confirmedShift = page.locator('[data-testid="shift-card"][data-status="confirmed"]').first();
    const pendingShift = page.locator('[data-testid="shift-card"][data-status="pending"]').first();
    
    await expect(confirmedShift).toBeVisible();
    await expect(pendingShift).toBeVisible();
    
    const confirmedBorder = await confirmedShift.evaluate((el) => window.getComputedStyle(el).borderColor);
    const pendingBorder = await pendingShift.evaluate((el) => window.getComputedStyle(el).borderColor);
    
    expect(confirmedBorder).not.toBe(pendingBorder);
  });

  test('Ensure unauthorized users cannot access calendar view', async ({ page }) => {
    // Logout from manager account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 1: Login as non-Manager user (Employee role)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Attempt to access schedule calendar page via navigation menu
    const scheduleCalendarLink = page.locator('text=Schedule Calendar');
    
    // Expected Result: Access to calendar page is denied (menu option not visible or access blocked)
    const isMenuVisible = await scheduleCalendarLink.isVisible().catch(() => false);
    
    if (isMenuVisible) {
      // If menu is visible, clicking should result in access denied
      await scheduleCalendarLink.click();
      await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    } else {
      // Menu option should not be visible for non-Manager users
      expect(isMenuVisible).toBe(false);
    }
    
    // Step 3: Attempt direct URL access
    await page.goto('/schedule-calendar');
    
    // Expected Result: Redirected to unauthorized page or access denied message
    const currentUrl = page.url();
    const hasAccessDenied = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);
    const isUnauthorized = currentUrl.includes('unauthorized') || currentUrl.includes('403') || hasAccessDenied;
    
    expect(isUnauthorized).toBe(true);
    
    if (hasAccessDenied) {
      await expect(page.locator('[data-testid="access-denied-message"]')).toContainText(/Access Denied|Unauthorized|Permission/);
    }
  });
});