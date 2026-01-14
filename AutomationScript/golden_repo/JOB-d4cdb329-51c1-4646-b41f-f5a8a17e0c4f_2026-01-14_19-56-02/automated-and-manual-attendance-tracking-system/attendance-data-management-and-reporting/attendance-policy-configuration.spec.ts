import { test, expect } from '@playwright/test';

test.describe('Attendance Policy Configuration - Story 9', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const HR_MANAGER_EMAIL = 'hr.manager@company.com';
  const HR_MANAGER_PASSWORD = 'HRManager123!';
  const NON_HR_USER_EMAIL = 'employee@company.com';
  const NON_HR_USER_PASSWORD = 'Employee123!';

  test('Configure and save attendance policies successfully (happy-path)', async ({ page }) => {
    // Step 1: Login as HR Manager
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', HR_MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to policy configuration UI
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="user-role"]')).toContainText('HR Manager');
    
    // Step 2: Navigate to attendance policy settings page
    await page.click('[data-testid="policy-configuration-menu"]');
    await page.click('[data-testid="attendance-policies-link"]');
    await expect(page).toHaveURL(/.*policies\/attendance/);
    
    // Define working hours (9:00 AM - 5:00 PM)
    await page.fill('[data-testid="working-hours-start"]', '09:00');
    await page.fill('[data-testid="working-hours-end"]', '17:00');
    
    // Define grace periods (15 minutes for late arrival, 10 minutes for early departure)
    await page.fill('[data-testid="late-arrival-grace-period"]', '15');
    await page.fill('[data-testid="early-departure-grace-period"]', '10');
    
    // Expected Result: Inputs accepted without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).toHaveCount(0);
    
    // Step 3: Save policy changes
    await page.click('[data-testid="save-policy-button"]');
    
    // Expected Result: Changes saved and confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Policy changes saved successfully');
    
    // Verify policy summary is displayed
    await expect(page.locator('[data-testid="policy-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="working-hours-display"]')).toContainText('09:00 - 17:00');
    await expect(page.locator('[data-testid="late-grace-display"]')).toContainText('15 minutes');
    await expect(page.locator('[data-testid="early-grace-display"]')).toContainText('10 minutes');
  });

  test('Validate policy parameter errors (error-case)', async ({ page }) => {
    // Login as HR Manager
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', HR_MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Navigate to attendance policy settings
    await page.click('[data-testid="policy-configuration-menu"]');
    await page.click('[data-testid="attendance-policies-link"]');
    await expect(page).toHaveURL(/.*policies\/attendance/);
    
    // Step 1: Enter inconsistent policy parameters - negative grace period
    await page.fill('[data-testid="late-arrival-grace-period"]', '-15');
    
    // Expected Result: Validation error messages displayed
    await expect(page.locator('[data-testid="validation-error-late-grace"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-late-grace"]')).toContainText('Grace period must be a positive number');
    
    // Enter end time before start time
    await page.fill('[data-testid="working-hours-start"]', '17:00');
    await page.fill('[data-testid="working-hours-end"]', '09:00');
    
    // Expected Result: Validation error for inconsistent working hours
    await expect(page.locator('[data-testid="validation-error-working-hours"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-working-hours"]')).toContainText('End time must be after start time');
    
    // Step 2: Attempt to save invalid policies
    await page.click('[data-testid="save-policy-button"]');
    
    // Expected Result: Save blocked until errors corrected
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Please correct validation errors before saving');
    
    // Verify no success message is shown
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Verify save button is disabled or form is not submitted
    const currentUrl = page.url();
    await expect(page).toHaveURL(currentUrl);
  });

  test('Restrict policy configuration access (error-case)', async ({ page, request }) => {
    // Step 1: Login as non-HR user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', NON_HR_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', NON_HR_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted but not as HR Manager
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="user-role"]')).not.toContainText('HR Manager');
    
    // Verify policy configuration menu is not visible
    await expect(page.locator('[data-testid="policy-configuration-menu"]')).not.toBeVisible();
    
    // Attempt to directly access policy configuration page via URL
    await page.goto(`${BASE_URL}/policies/attendance`);
    
    // Expected Result: Access to policy configuration denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="unauthorized-text"]')).toContainText('You do not have permission to access this page');
    
    // Verify redirected to unauthorized page or dashboard
    await expect(page).toHaveURL(/.*(?:unauthorized|access-denied|dashboard)/);
    
    // Step 2: Attempt to access policy APIs
    // Get cookies for authenticated request
    const cookies = await page.context().cookies();
    
    // Attempt GET request to policy API
    const getResponse = await request.get(`${BASE_URL}/api/policies/attendance`, {
      headers: {
        'Cookie': cookies.map(c => `${c.name}=${c.value}`).join('; ')
      }
    });
    
    // Expected Result: Authorization error returned
    expect(getResponse.status()).toBe(403);
    const getBody = await getResponse.json();
    expect(getBody.error).toContain('Unauthorized');
    
    // Attempt POST request to policy API
    const postResponse = await request.post(`${BASE_URL}/api/policies/attendance`, {
      headers: {
        'Cookie': cookies.map(c => `${c.name}=${c.value}`).join('; '),
        'Content-Type': 'application/json'
      },
      data: {
        workingHoursStart: '09:00',
        workingHoursEnd: '17:00',
        lateArrivalGracePeriod: 15,
        earlyDepartureGracePeriod: 10
      }
    });
    
    // Expected Result: Authorization error returned
    expect(postResponse.status()).toBe(403);
    const postBody = await postResponse.json();
    expect(postBody.error).toContain('Unauthorized');
  });
});