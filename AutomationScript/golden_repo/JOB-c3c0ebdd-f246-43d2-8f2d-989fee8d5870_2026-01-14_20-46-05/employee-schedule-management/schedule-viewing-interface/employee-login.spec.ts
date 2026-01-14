import { test, expect } from '@playwright/test';

test.describe('Employee Login - Secure Authentication', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee.test@company.com';
  const VALID_PASSWORD = 'SecurePass123!';
  const INVALID_PASSWORD = 'WrongPassword123';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful login with valid credentials', async ({ page }) => {
    // Step 1: Navigate to login page and verify login form is displayed
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Step 2: Enter valid username and password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);

    // Verify no validation errors are shown
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();

    // Step 3: Submit login form
    await page.click('[data-testid="login-button"]');

    // Wait for navigation to complete
    await page.waitForURL('**/dashboard', { timeout: 5000 });

    // Verify user is authenticated and redirected to schedule dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();
    await expect(page.locator('[data-testid="logout-button"]')).toBeVisible();
  });

  test('Verify rejection of invalid login attempts', async ({ page }) => {
    // Step 1: Navigate to login page and verify login form is displayed
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 2: Enter invalid username or password and verify validation error
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Verify validation error message is shown
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/invalid credentials|incorrect username or password/i);

    // Step 3: Attempt login with invalid credentials 5 times
    // Attempt 2
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Attempt 3
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Attempt 4
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Attempt 5 - Account should be locked after this
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Verify account is locked and user is notified
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/account locked|account has been locked|too many failed attempts/i);

    // Verify that even with correct credentials, login is blocked
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/account locked|account has been locked/i);
  });

  test('Test password recovery workflow', async ({ page }) => {
    // Step 1: Navigate to login page and verify login form is displayed
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 2: Click on 'Forgot Password' link
    await page.click('[data-testid="forgot-password-link"]');

    // Verify password recovery form is displayed
    await expect(page.locator('[data-testid="password-recovery-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="email-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="submit-reset-button"]')).toBeVisible();

    // Step 3: Submit valid email for password reset
    await page.fill('[data-testid="email-input"]', VALID_USERNAME);
    await page.click('[data-testid="submit-reset-button"]');

    // Verify password reset instructions confirmation is displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/password reset instructions|reset link sent|check your email/i);

    // Verify confirmation message contains email reference
    const successMessage = await page.locator('[data-testid="success-message"]').textContent();
    expect(successMessage).toBeTruthy();
  });

  test('Validate successful login with valid credentials - detailed workflow', async ({ page }) => {
    // Open web browser and navigate to the login page URL
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Enter valid username in the username field
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await expect(page.locator('[data-testid="username-input"]')).toHaveValue(VALID_USERNAME);

    // Enter valid password in the password field
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await expect(page.locator('[data-testid="password-input"]')).toHaveValue(VALID_PASSWORD);

    // Click the 'Login' button to submit the login form
    await page.click('[data-testid="login-button"]');

    // Wait for navigation and verify the schedule dashboard displays correctly
    await page.waitForURL('**/dashboard', { timeout: 5000 });
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-content"]')).toBeVisible();
  });

  test('Verify rejection of invalid login attempts - detailed workflow', async ({ page }) => {
    // Navigate to the login page URL
    await page.goto(`${BASE_URL}/login`);

    // Attempt 1: Enter valid username and incorrect password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Attempt 2: Enter valid username and incorrect password again
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Attempt 3: Repeat login attempt with valid username and incorrect password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Attempt 4: Repeat login attempt with valid username and incorrect password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();

    // Attempt 5: Repeat login attempt with valid username and incorrect password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/account locked|account has been locked/i);

    // Attempt to login with correct credentials for the locked account
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/account locked|account has been locked/i);
    await expect(page).toHaveURL(/.*login/);
  });

  test('Test password recovery workflow - detailed steps', async ({ page }) => {
    // Navigate to the login page URL
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Click on the 'Forgot Password' link
    await page.click('[data-testid="forgot-password-link"]');
    await expect(page.locator('[data-testid="password-recovery-form"]')).toBeVisible();

    // Enter valid registered email address in the email field
    await page.fill('[data-testid="email-input"]', VALID_USERNAME);
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue(VALID_USERNAME);

    // Click the 'Submit' or 'Send Reset Link' button
    await page.click('[data-testid="submit-reset-button"]');

    // Verify success message indicating password reset email has been sent
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/password reset|check your email|reset link/i);

    // Note: Actual email verification and clicking reset link would require email testing infrastructure
    // This would typically be tested separately with email testing tools or mocked in integration tests
  });
});