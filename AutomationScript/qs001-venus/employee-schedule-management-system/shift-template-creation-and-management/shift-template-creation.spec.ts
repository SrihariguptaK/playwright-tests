import { test, expect } from '@playwright/test';

test.describe('Shift Template Creation', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const managerCredentials = {
    username: 'manager01',
    password: 'managerPass123'
  };
  const nonManagerCredentials = {
    username: 'employee01',
    password: 'password123'
  };

  test.beforeEach(async ({ page }) => {
    // Login as manager for most tests
    await page.goto(`${baseURL}/login`);
  });

  test('Validate successful creation of shift template with valid input', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template"]');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="template-name-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="start-time-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="end-time-input"]')).toBeVisible();

    // Enter valid start time, end time, and break periods
    await page.fill('[data-testid="template-name-input"]', 'Morning Shift');
    await page.fill('[data-testid="start-time-input"]', '08:00 AM');
    await page.fill('[data-testid="end-time-input"]', '04:00 PM');
    await page.fill('[data-testid="break-start-input"]', '12:00 PM');
    await page.fill('[data-testid="break-end-input"]', '12:30 PM');
    
    // Expected Result: No validation errors are shown
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    await expect(page.locator('.error-message')).toHaveCount(0);

    // Submit the form
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Shift template is saved and confirmation message is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift template created successfully');
    
    // Verify template appears in the list
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="view-templates"]');
    await expect(page.locator('[data-testid="template-list"]')).toContainText('Morning Shift');
  });

  test('Reject creation of shift template with invalid time ranges', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="username-input"]', managerCredentials.username);
    await page.fill('[data-testid="password-input"]', managerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to shift template creation page
    await page.click('[data-testid="shift-templates-menu"]');
    await page.click('[data-testid="create-new-template"]');
    
    // Expected Result: Shift template form is displayed
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();

    // Enter end time before start time
    await page.fill('[data-testid="template-name-input"]', 'Invalid Shift');
    await page.fill('[data-testid="start-time-input"]', '05:00 PM');
    await page.fill('[data-testid="end-time-input"]', '09:00 AM');
    
    // Trigger validation by moving focus or clicking elsewhere
    await page.click('[data-testid="template-name-input"]');
    
    // Expected Result: Validation error message is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('End time must be after start time');

    // Attempt to submit the form
    await page.click('[data-testid="save-template-button"]');
    
    // Expected Result: Form submission is blocked with error messages
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Please correct the errors before submitting');
    
    // Verify we're still on the creation page (not navigated away)
    await expect(page.locator('[data-testid="shift-template-form"]')).toBeVisible();
    
    // Verify template was not created
    const saveButton = page.locator('[data-testid="save-template-button"]');
    await expect(saveButton).toBeEnabled();
  });

  test('Restrict template creation to authorized scheduling managers', async ({ page, request }) => {
    // Login as a non-manager user
    await page.fill('[data-testid="username-input"]', nonManagerCredentials.username);
    await page.fill('[data-testid="password-input"]', nonManagerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to access shift template creation page
    const shiftTemplatesMenu = page.locator('[data-testid="shift-templates-menu"]');
    
    // Expected Result: Access to shift template creation page is denied
    // Check if menu is not visible or disabled for non-manager
    const isMenuVisible = await shiftTemplatesMenu.isVisible().catch(() => false);
    if (isMenuVisible) {
      await shiftTemplatesMenu.click();
      const createTemplateOption = page.locator('[data-testid="create-new-template"]');
      await expect(createTemplateOption).not.toBeVisible();
    }
    
    // Attempt direct URL navigation
    await page.goto(`${baseURL}/shift-templates/create`);
    
    // Verify access denied message or redirect
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('text=Unauthorized');
    const forbiddenMessage = page.locator('text=Access Denied');
    
    const isAccessDenied = await Promise.race([
      accessDeniedMessage.isVisible().catch(() => false),
      unauthorizedMessage.isVisible().catch(() => false),
      forbiddenMessage.isVisible().catch(() => false)
    ]);
    
    expect(isAccessDenied || page.url().includes('unauthorized') || page.url().includes('dashboard')).toBeTruthy();

    // Attempt to access API endpoint directly
    const cookies = await page.context().cookies();
    const authToken = cookies.find(cookie => cookie.name === 'auth_token')?.value || '';
    
    const apiResponse = await request.post(`${baseURL}/api/shifttemplates`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        name: 'Unauthorized Shift',
        startTime: '08:00 AM',
        endTime: '04:00 PM',
        breakStart: '12:00 PM',
        breakEnd: '12:30 PM'
      }
    });
    
    // Expected Result: API returns unauthorized error
    expect(apiResponse.status()).toBe(401);
    const responseBody = await apiResponse.json();
    expect(responseBody.error || responseBody.message).toMatch(/unauthorized|forbidden|access denied/i);
  });
});