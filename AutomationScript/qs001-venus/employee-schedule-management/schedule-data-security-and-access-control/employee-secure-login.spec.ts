import { test, expect } from '@playwright/test';

test.describe('Employee Secure Login', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'SecurePass123!';
  const INVALID_USERNAME = 'nonexistent@company.com';
  const INVALID_PASSWORD = 'WrongPassword123';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful login with valid credentials', async ({ page }) => {
    // Step 1: Navigate to login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('form')).toBeVisible();
    await expect(page.getByRole('textbox', { name: /username|email/i })).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();

    // Step 2: Enter valid username and password
    await page.getByRole('textbox', { name: /username|email/i }).fill(VALID_USERNAME);
    await page.getByLabel(/password/i).fill(VALID_PASSWORD);
    await page.getByRole('button', { name: /login|sign in/i }).click();

    // Verify login successful and dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 10000 });
    await expect(page.getByText(/dashboard|welcome/i)).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"], .employee-name, .user-profile')).toBeVisible();

    // Step 3: Log out
    await page.getByRole('button', { name: /logout|sign out/i }).click();

    // Verify session terminated and login page displayed
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    await expect(page.locator('form')).toBeVisible();
    await expect(page.getByRole('textbox', { name: /username|email/i })).toHaveValue('');
  });

  test('Verify login failure with invalid credentials', async ({ page }) => {
    // Step 1: Navigate to login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('form')).toBeVisible();

    // Step 2: Enter invalid username or password (non-existent user)
    await page.getByRole('textbox', { name: /username|email/i }).fill(INVALID_USERNAME);
    await page.getByLabel(/password/i).fill(VALID_PASSWORD);
    await page.getByRole('button', { name: /login|sign in/i }).click();

    // Verify error message displayed and access denied
    await expect(page.locator('[data-testid="error-message"], .error-message, .alert-error, [role="alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="error-message"], .error-message, .alert-error, [role="alert"]')).toContainText(/invalid|incorrect|failed|denied/i);
    await expect(page).toHaveURL(/.*login/);

    // Clear fields and try with valid username but incorrect password
    await page.getByRole('textbox', { name: /username|email/i }).clear();
    await page.getByLabel(/password/i).clear();
    await page.getByRole('textbox', { name: /username|email/i }).fill(VALID_USERNAME);
    await page.getByLabel(/password/i).fill(INVALID_PASSWORD);
    await page.getByRole('button', { name: /login|sign in/i }).click();

    // Verify error message displayed and access denied
    await expect(page.locator('[data-testid="error-message"], .error-message, .alert-error, [role="alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="error-message"], .error-message, .alert-error, [role="alert"]')).toContainText(/invalid|incorrect|failed|denied/i);
    await expect(page).toHaveURL(/.*login/);

    // Verify no session token is created
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(cookie => cookie.name.toLowerCase().includes('session') || cookie.name.toLowerCase().includes('token'));
    expect(sessionCookie).toBeUndefined();
  });

  test('Test session invalidation on logout', async ({ page }) => {
    // Step 1: Login successfully
    await page.getByRole('textbox', { name: /username|email/i }).fill(VALID_USERNAME);
    await page.getByLabel(/password/i).fill(VALID_PASSWORD);
    await page.getByRole('button', { name: /login|sign in/i }).click();

    // Verify dashboard displayed
    await expect(page).toHaveURL(/.*dashboard/, { timeout: 10000 });
    await expect(page.getByText(/dashboard|welcome/i)).toBeVisible();

    // Step 2: Click logout
    await page.getByRole('button', { name: /logout|sign out/i }).click();

    // Verify session invalidated and login page displayed
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    await expect(page.locator('form')).toBeVisible();

    // Step 3: Attempt to access schedule page without login
    await page.goto(`${BASE_URL}/schedule`);

    // Verify access denied and redirected to login
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    await expect(page.locator('form')).toBeVisible();

    // Verify session token is no longer valid
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(cookie => cookie.name.toLowerCase().includes('session') || cookie.name.toLowerCase().includes('token'));
    if (sessionCookie) {
      expect(sessionCookie.value).toBe('');
    }

    // Attempt to use browser back button
    await page.goBack();
    await expect(page).toHaveURL(/.*login/);

    // Verify cannot access protected routes
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
  });
});