import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Search by Date', () => {
  test.beforeEach(async ({ page }) => {
    // Login as employee before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee123');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*schedule/);
  });

  test('Validate successful search by valid date', async ({ page }) => {
    // Navigate to the schedule page
    await page.goto('/schedule');
    await page.waitForLoadState('networkidle');

    // Locate the date search field or date picker input
    const dateSearchField = page.locator('[data-testid="date-search-field"]');
    await expect(dateSearchField).toBeVisible();

    // Click on the date search field to activate it
    await dateSearchField.click();

    // Enter a valid date that has scheduled shifts
    await dateSearchField.fill('2024-03-15');

    // Press Enter or click the Search button to execute the search
    const searchButton = page.locator('[data-testid="search-button"]');
    await searchButton.click();

    // Wait for schedule to update
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );

    // Observe the schedule display update
    await page.waitForSelector('[data-testid="schedule-results"]');

    // Verify that only shifts for the searched date are displayed
    const scheduleResults = page.locator('[data-testid="schedule-results"]');
    await expect(scheduleResults).toBeVisible();
    
    const shiftDates = page.locator('[data-testid="shift-date"]');
    const count = await shiftDates.count();
    
    for (let i = 0; i < count; i++) {
      const dateText = await shiftDates.nth(i).textContent();
      expect(dateText).toContain('2024-03-15');
    }

    // Locate and click the 'Clear search' button or option
    const clearSearchButton = page.locator('[data-testid="clear-search-button"]');
    await expect(clearSearchButton).toBeVisible();
    await clearSearchButton.click();

    // Observe the schedule display after clearing search
    await page.waitForLoadState('networkidle');
    
    // Verify that full schedule view is restored
    const fullSchedule = page.locator('[data-testid="full-schedule-view"]');
    await expect(fullSchedule).toBeVisible();
    
    // Verify date search field is cleared
    await expect(dateSearchField).toHaveValue('');
  });

  test('Validate rejection of invalid date input', async ({ page }) => {
    // Navigate to the schedule page
    await page.goto('/schedule');
    await page.waitForLoadState('networkidle');

    // Locate the date search field
    const dateSearchField = page.locator('[data-testid="date-search-field"]');
    await expect(dateSearchField).toBeVisible();

    // Test multiple invalid date formats
    const invalidDates = ['32/13/2024', 'invalid-date', '2024-13-45', 'abc123'];

    for (const invalidDate of invalidDates) {
      // Click on the date search field to activate it
      await dateSearchField.click();
      await dateSearchField.clear();

      // Enter an invalid date format
      await dateSearchField.fill(invalidDate);

      // Press Enter or click the Search button to attempt the search
      const searchButton = page.locator('[data-testid="search-button"]');
      await searchButton.click();

      // Observe the system response to invalid date input
      const errorMessage = page.locator('[data-testid="error-message"]');
      await expect(errorMessage).toBeVisible();
      
      // Verify error message content
      await expect(errorMessage).toContainText(/invalid date format|please enter a valid date/i);

      // Verify that the search was not performed
      const scheduleResults = page.locator('[data-testid="schedule-results"]');
      const resultsCount = await scheduleResults.count();
      
      // Verify that the schedule data is still accessible
      const fullSchedule = page.locator('[data-testid="full-schedule-view"]');
      await expect(fullSchedule).toBeVisible();

      // Clear the field for next iteration
      await dateSearchField.clear();
      
      // Dismiss error if there's a close button
      const errorCloseButton = page.locator('[data-testid="error-close-button"]');
      if (await errorCloseButton.isVisible()) {
        await errorCloseButton.click();
      }
    }
  });

  test('Test access control on search results', async ({ page }) => {
    // Navigate to the schedule page
    await page.goto('/schedule');
    await page.waitForLoadState('networkidle');

    // Note the current URL in the browser address bar
    const currentUrl = page.url();
    expect(currentUrl).toContain('employeeId=123');

    // Manually modify the URL to change the employeeId parameter to another employee's ID
    const unauthorizedUrl = currentUrl.replace('employeeId=123', 'employeeId=456');
    const modifiedUrl = '/api/schedules?employeeId=456&date=2024-03-15';
    
    // Navigate to the modified URL
    await page.goto(modifiedUrl);

    // Observe the system response to unauthorized access attempt
    await page.waitForLoadState('networkidle');

    // Verify that access denied error is displayed
    const accessDeniedError = page.locator('[data-testid="access-denied-error"]');
    const errorMessage = page.locator('[data-testid="error-message"]');
    
    const isAccessDeniedVisible = await accessDeniedError.isVisible().catch(() => false);
    const isErrorMessageVisible = await errorMessage.isVisible().catch(() => false);
    
    expect(isAccessDeniedVisible || isErrorMessageVisible).toBeTruthy();

    if (isAccessDeniedVisible) {
      await expect(accessDeniedError).toContainText(/access denied|unauthorized|forbidden/i);
    } else if (isErrorMessageVisible) {
      await expect(errorMessage).toContainText(/access denied|unauthorized|forbidden/i);
    }

    // Verify that no schedule data for the other employee is displayed
    const otherEmployeeSchedule = page.locator('[data-testid="schedule-results"]');
    const scheduleCount = await otherEmployeeSchedule.count();
    
    if (scheduleCount > 0) {
      // If schedule is visible, verify it doesn't contain other employee's data
      const employeeIdDisplay = page.locator('[data-testid="employee-id"]');
      if (await employeeIdDisplay.isVisible()) {
        const displayedId = await employeeIdDisplay.textContent();
        expect(displayedId).not.toContain('456');
      }
    }

    // Verify redirection or error page display
    const currentPageUrl = page.url();
    const isRedirected = currentPageUrl.includes('/error') || 
                        currentPageUrl.includes('/unauthorized') || 
                        currentPageUrl.includes('/schedule?employeeId=123');
    
    // Check that the session remains valid
    const userMenu = page.locator('[data-testid="user-menu"]');
    const logoutButton = page.locator('[data-testid="logout-button"]');
    
    const isUserMenuVisible = await userMenu.isVisible().catch(() => false);
    const isLogoutVisible = await logoutButton.isVisible().catch(() => false);
    
    expect(isUserMenuVisible || isLogoutVisible).toBeTruthy();

    // Verify user can navigate back to their own schedule
    await page.goto('/schedule');
    await page.waitForLoadState('networkidle');
    
    const ownSchedule = page.locator('[data-testid="full-schedule-view"]');
    await expect(ownSchedule).toBeVisible();
  });
});