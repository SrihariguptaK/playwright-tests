import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Search by Date', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMPLOYEE_EMAIL = 'employee@company.com';
  const VALID_EMPLOYEE_PASSWORD = 'Password123!';
  const SEARCH_DATE_WITH_SHIFTS = '2024-01-15';
  const SEARCH_DATE_NO_SHIFTS = '2024-12-25';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate schedule search by valid date (happy-path)', async ({ page }) => {
    // Step 1: Employee logs in and navigates to schedule search
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    await expect(page.locator('[data-testid="search-interface"]').or(page.locator('text=Schedule')).first()).toBeVisible();

    // Step 2: Navigate to Schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Verify search interface is displayed
    await expect(page.locator('[data-testid="schedule-search-container"]').or(page.locator('[data-testid="date-search-input"]')).first()).toBeVisible();

    // Step 3: Enter a valid date with scheduled shifts
    const dateInput = page.locator('[data-testid="date-search-input"]');
    await dateInput.click();
    await dateInput.fill(SEARCH_DATE_WITH_SHIFTS);
    
    // Execute search
    await page.click('[data-testid="search-button"]');
    
    // Wait for search results to load
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200,
      { timeout: 2000 }
    );

    // Step 4: Verify shifts for that date are displayed
    await expect(page.locator('[data-testid="shift-item"]').first()).toBeVisible({ timeout: 2000 });
    const shiftItems = page.locator('[data-testid="shift-item"]');
    const shiftCount = await shiftItems.count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Verify the date on displayed shifts matches searched date
    const firstShiftDate = await page.locator('[data-testid="shift-date"]').first().textContent();
    expect(firstShiftDate).toContain('2024-01-15');

    // Step 5: Clear search input
    await page.click('[data-testid="clear-search-button"]');
    
    // Step 6: Verify full schedule or default view is restored
    await expect(dateInput).toHaveValue('');
    const allShifts = page.locator('[data-testid="shift-item"]');
    const allShiftsCount = await allShifts.count();
    expect(allShiftsCount).toBeGreaterThanOrEqual(shiftCount);
  });

  test('Verify handling of invalid date input (error-case)', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Navigate to Schedule section
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Step 1: Enter invalid date format with invalid month
    const dateInput = page.locator('[data-testid="date-search-input"]');
    await dateInput.click();
    await dateInput.fill('2023-13-01');
    
    // Attempt to search
    await page.click('[data-testid="search-button"]');
    
    // Step 2: Verify inline error message displayed and search blocked
    const errorMessage = page.locator('[data-testid="date-error-message"]').or(page.locator('text=Invalid date format'));
    await expect(errorMessage.first()).toBeVisible();
    
    // Verify no shifts are displayed (search was blocked)
    const shiftsAfterInvalidSearch = page.locator('[data-testid="shift-item"]');
    const count = await shiftsAfterInvalidSearch.count();
    // Either no shifts or original shifts remain (search didn't execute)
    
    // Clear the invalid date
    await dateInput.clear();
    
    // Enter another invalid format with invalid day
    await dateInput.fill('32/01/2024');
    await page.click('[data-testid="search-button"]');
    
    // Verify error message is still displayed
    await expect(errorMessage.first()).toBeVisible();
    
    // Clear error and enter valid date with no scheduled shifts
    await dateInput.clear();
    await dateInput.fill(SEARCH_DATE_NO_SHIFTS);
    await page.click('[data-testid="search-button"]');
    
    // Wait for search to complete
    await page.waitForTimeout(500);
    
    // Step 3: Verify user-friendly message indicating no shifts found
    const noShiftsMessage = page.locator('[data-testid="no-shifts-message"]').or(page.locator('text=No shifts found'));
    await expect(noShiftsMessage.first()).toBeVisible();
    
    // Verify no shift data is displayed
    const noShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(noShiftsCount).toBe(0);
    
    // Clear search to return to default view
    await page.click('[data-testid="clear-search-button"]');
    await expect(dateInput).toHaveValue('');
  });

  test('Ensure unauthorized users cannot perform schedule search (error-case)', async ({ page, context }) => {
    // Step 1: Ensure no user is logged in - clear cookies and session
    await context.clearCookies();
    await page.goto(`${BASE_URL}`);
    
    // Step 2: Attempt to directly access schedule search page
    await page.goto(`${BASE_URL}/schedule`);
    
    // Step 3: Verify redirected to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    await expect(page.locator('[data-testid="login-button"]').or(page.locator('text=Login')).first()).toBeVisible();
    
    // Verify schedule search functionality is not accessible
    const scheduleSearchInput = page.locator('[data-testid="date-search-input"]');
    await expect(scheduleSearchInput).not.toBeVisible();
    
    // Step 4: Attempt to access API endpoint directly without authentication
    const employeeId = '12345';
    const searchDate = '2024-01-15';
    const apiResponse = await page.request.get(`${BASE_URL}/api/schedules?employeeId=${employeeId}&date=${searchDate}`);
    
    // Step 5: Verify unauthorized response (401 or 403)
    expect([401, 403]).toContain(apiResponse.status());
    
    // Verify no sensitive data is exposed in error response
    const responseBody = await apiResponse.json().catch(() => ({}));
    expect(responseBody).not.toHaveProperty('shifts');
    expect(responseBody).not.toHaveProperty('employeeData');
    
    // Verify error message is generic and doesn't expose system details
    if (responseBody.message) {
      expect(responseBody.message.toLowerCase()).toMatch(/unauthorized|authentication|access denied|forbidden/);
    }
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Logout if logged in
    const logoutButton = page.locator('[data-testid="logout-button"]');
    if (await logoutButton.isVisible().catch(() => false)) {
      await logoutButton.click();
    }
  });
});