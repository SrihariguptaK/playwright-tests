import { test, expect } from '@playwright/test';

test.describe('Employee Login Authentication', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee.test@company.com';
  const VALID_PASSWORD = 'SecurePass123!';
  const INVALID_USERNAME = 'nonexistent.user@company.com';
  const INVALID_PASSWORD = 'WrongPassword123';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful login with valid credentials', async ({ page }) => {
    // Step 1: Employee navigates to login page
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();

    // Step 2: Employee enters valid username and password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Credentials accepted, employee is logged in
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/(dashboard|home|schedule)`));
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 3: Employee accesses schedule page
    await page.click('[data-testid="schedule-menu"]');
    
    // Expected Result: Schedule is displayed
    await expect(page).toHaveURL(`${BASE_URL}/schedule`);
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
  });

  test('Verify rejection of invalid credentials - invalid username', async ({ page }) => {
    // Step 1: Employee enters invalid username or password
    await page.fill('[data-testid="username-input"]', INVALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Error message 'Invalid credentials' is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid credentials');

    // Step 2: Employee attempts to access schedule page
    await page.goto(`${BASE_URL}/schedule`);

    // Expected Result: Access denied
    await expect(page).toHaveURL(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
  });

  test('Verify rejection of invalid credentials - invalid password', async ({ page }) => {
    // Employee enters valid username but incorrect password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Error message 'Invalid credentials' is displayed
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid credentials');

    // Verify user remains on login page
    await expect(page).toHaveURL(`${BASE_URL}/login`);
  });

  test('Ensure session termination on logout', async ({ page }) => {
    // First, login with valid credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 1: Employee clicks logout button
    await page.click('[data-testid="logout-button"]');

    // Expected Result: Session is terminated, redirected to login page
    await expect(page).toHaveURL(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Step 2: Employee attempts to access schedule page after logout
    await page.goto(`${BASE_URL}/schedule`);

    // Expected Result: Access denied, login required
    await expect(page).toHaveURL(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
  });

  test('Verify session termination prevents back button access', async ({ page }) => {
    // Login with valid credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Navigate to schedule page
    await page.click('[data-testid="schedule-menu"]');
    await expect(page).toHaveURL(`${BASE_URL}/schedule`);

    // Logout
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(`${BASE_URL}/login`);

    // Attempt to use browser back button
    await page.goBack();

    // Expected Result: Should be redirected to login page
    await expect(page).toHaveURL(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
  });

  test('Verify direct URL access to protected pages requires authentication', async ({ page }) => {
    // Attempt to directly access schedule page without logging in
    await page.goto(`${BASE_URL}/schedule`);

    // Expected Result: Redirected to login page
    await expect(page).toHaveURL(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
  });
});