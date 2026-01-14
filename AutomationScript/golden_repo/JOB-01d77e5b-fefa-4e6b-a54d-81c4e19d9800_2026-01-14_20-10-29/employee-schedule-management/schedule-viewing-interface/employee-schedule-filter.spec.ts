import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Shift Type Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate shift type filtering functionality (happy-path)', async ({ page }) => {
    // Navigate to schedule view section from the dashboard or main navigation menu
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Expected Result: Full schedule displayed
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    const allShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(allShiftsCount).toBeGreaterThan(0);
    
    // Locate the shift type filter control and select 'Evening' from the available shift type filter options
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    // Wait for filtered results to load
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Expected Result: Only evening shifts displayed
    await page.waitForTimeout(500); // Allow UI to update
    const eveningShifts = await page.locator('[data-testid="shift-item"]').all();
    expect(eveningShifts.length).toBeGreaterThan(0);
    expect(eveningShifts.length).toBeLessThanOrEqual(allShiftsCount);
    
    // Verify that all displayed shifts are indeed evening shifts by checking shift times and shift type labels
    for (const shift of eveningShifts) {
      const shiftType = await shift.locator('[data-testid="shift-type-label"]').textContent();
      expect(shiftType?.toLowerCase()).toContain('evening');
    }
    
    // Click the 'Clear Filter' button or remove the active filter selection
    await page.click('[data-testid="clear-filter-button"]');
    
    // Expected Result: Full schedule restored
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    await page.waitForTimeout(500);
    const restoredShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(restoredShiftsCount).toBe(allShiftsCount);
  });

  test('Ensure filtering respects employee identity (error-case)', async ({ page, request }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Get current employee's authentication token from cookies or local storage
    const cookies = await page.context().cookies();
    const authToken = cookies.find(cookie => cookie.name === 'auth_token')?.value || 
                      await page.evaluate(() => localStorage.getItem('authToken'));
    
    // Using API testing tools, construct a GET request to /api/schedules endpoint
    // with filter parameters for shift type, but modify the employee ID parameter
    // to target another employee's shifts while using the current employee's authentication token
    const unauthorizedResponse = await request.get('/api/schedules', {
      params: {
        employeeId: '99999', // Different employee ID
        shiftType: 'evening'
      },
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    // Observe and verify the API response status code and response body
    // Expected Result: No data returned or access denied
    expect([401, 403, 404]).toContain(unauthorizedResponse.status());
    
    if (unauthorizedResponse.status() === 200) {
      const responseData = await unauthorizedResponse.json();
      expect(responseData.length).toBe(0);
    }
    
    // Attempt the same unauthorized access through the UI by manipulating
    // browser session storage, cookies, or URL parameters
    await page.evaluate(() => {
      sessionStorage.setItem('currentEmployeeId', '99999');
    });
    
    // Try to navigate with manipulated employee ID parameter
    await page.goto('/schedule?employeeId=99999&shiftType=evening');
    
    // Expected Result: Access denied or redirected, or no data displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    const noDataMessage = page.locator('[data-testid="no-data-message"]');
    const accessDenied = page.locator('text=/access denied|unauthorized|forbidden/i');
    
    const hasError = await errorMessage.isVisible().catch(() => false) ||
                     await noDataMessage.isVisible().catch(() => false) ||
                     await accessDenied.isVisible().catch(() => false);
    
    if (!hasError) {
      // If no explicit error, verify no shifts are displayed
      const shiftsCount = await page.locator('[data-testid="shift-item"]').count();
      expect(shiftsCount).toBe(0);
    }
    
    // Verify that the current employee can still successfully filter their own schedule
    // after the failed unauthorized access attempt
    await page.evaluate(() => {
      sessionStorage.removeItem('currentEmployeeId');
    });
    
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Apply filter for own schedule
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    // Verify filtered results are displayed successfully
    const validShiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(validShiftsCount).toBeGreaterThan(0);
  });

  test('Filtered schedule loads within 2 seconds', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    
    // Measure time for filter application
    const startTime = Date.now();
    
    await page.click('[data-testid="shift-type-filter"]');
    await page.click('[data-testid="filter-option-evening"]');
    
    await page.waitForResponse(response => 
      response.url().includes('/api/schedules') && response.status() === 200
    );
    
    await expect(page.locator('[data-testid="shift-item"]').first()).toBeVisible();
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Expected Result: Filtered results load within 2 seconds
    expect(loadTime).toBeLessThan(2000);
  });
});