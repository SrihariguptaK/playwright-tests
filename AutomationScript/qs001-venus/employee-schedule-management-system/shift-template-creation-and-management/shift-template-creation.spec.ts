import { test, expect } from '@playwright/test';

test.describe('Shift Template Creation', () => {
  test.beforeEach(async ({ page }) => {
    // Login as HR Manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'hrmanager01');
    await page.fill('[data-testid="password-input"]', 'HRPassword123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful shift template creation with valid input', async ({ page }) => {
    // Step 1: Navigate to shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Step 2: Enter valid start time, end time, break periods, and shift type
    await page.fill('[data-testid="start-time-input"]', '09:00 AM');
    await page.fill('[data-testid="end-time-input"]', '05:00 PM');
    
    // Add break period
    await page.fill('[data-testid="break-start-time-input"]', '12:00 PM');
    await page.fill('[data-testid="break-end-time-input"]', '01:00 PM');
    await page.fill('[data-testid="break-duration-input"]', '60');
    await page.fill('[data-testid="break-description-input"]', 'Lunch break');
    
    // Select shift type
    await page.selectOption('[data-testid="shift-type-dropdown"]', 'Morning Shift');
    
    // Enter shift category
    await page.fill('[data-testid="shift-category-input"]', 'Standard Office Hours');
    
    // Expected Result: All inputs accept data without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Step 3: Submit the form
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Shift template is created and confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template created successfully');
  });

  test('Reject shift template creation with invalid time ranges', async ({ page }) => {
    // Step 1: Navigate to shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template-button"]');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Step 2: Enter end time earlier than start time
    await page.fill('[data-testid="start-time-input"]', '05:00 PM');
    await page.fill('[data-testid="end-time-input"]', '09:00 AM');
    
    // Expected Result: Validation error message is displayed
    await expect(page.locator('[data-testid="time-validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="time-validation-error"]')).toContainText('End time must be after start time');
    
    // Step 3: Attempt to submit the form
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Form submission is blocked until errors are corrected
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Correct the end time to a valid time
    await page.fill('[data-testid="end-time-input"]', '11:00 PM');
    
    // Verify error message is cleared
    await expect(page.locator('[data-testid="time-validation-error"]')).not.toBeVisible();
  });

  test('Ensure unauthorized users cannot create shift templates', async ({ page, request }) => {
    // Logout HR Manager
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 1: Login as non-HR user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee01');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Expected Result: Access to shift template creation page is denied
    await page.goto('/shift-templates/create');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    
    // Verify shift template form is not displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).not.toBeVisible();
    
    // Step 2: Attempt to access API endpoint POST /api/shifttemplates
    const response = await request.post('/api/shifttemplates', {
      data: {
        startTime: '09:00 AM',
        endTime: '05:00 PM',
        shiftType: 'Morning Shift',
        category: 'Standard Office Hours',
        breakPeriods: [
          {
            startTime: '12:00 PM',
            endTime: '01:00 PM',
            duration: 60,
            description: 'Lunch break'
          }
        ]
      },
      headers: {
        'Authorization': 'Bearer employee_token'
      }
    });
    
    // Expected Result: API returns authorization error
    expect(response.status()).toBe(403);
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Unauthorized');
  });
});