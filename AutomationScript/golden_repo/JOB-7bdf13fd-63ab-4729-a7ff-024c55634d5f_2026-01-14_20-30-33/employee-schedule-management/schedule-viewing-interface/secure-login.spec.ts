import { test, expect } from '@playwright/test';

test.describe('Secure Login Authentication', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'SecurePass123!';
  const INVALID_USERNAME = 'invalid@company.com';
  const INVALID_PASSWORD = 'wrongpassword';
  const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

  test('Validate successful login with valid credentials', async ({ page }) => {
    // Step 1: Navigate to login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();

    // Step 2: Enter valid username and password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: User authenticated and redirected to dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-info"]')).toContainText(VALID_USERNAME);

    // Step 3: Access schedule section
    await page.click('[data-testid="schedule-nav-link"]');

    // Expected Result: Schedule data displayed
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="schedule-data"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-table"]')).toBeVisible();
  });

  test('Verify login failure with invalid credentials', async ({ page }) => {
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Test with invalid username
    await page.fill('[data-testid="username-input"]', INVALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Error message displayed and access denied
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/invalid.*credentials|login failed|authentication failed/i);
    await expect(page).toHaveURL(/.*login/);

    // Clear fields and test with invalid password
    await page.fill('[data-testid="username-input"]', '');
    await page.fill('[data-testid="password-input"]', '');
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-button"]');

    // Expected Result: Error message displayed and access denied
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page).toHaveURL(/.*login/);

    // Attempt to access schedule page directly without authentication
    await page.goto(`${BASE_URL}/schedule`);
    await expect(page).toHaveURL(/.*login/);
  });

  test('Ensure session timeout after inactivity', async ({ page }) => {
    // Login with valid credentials
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to schedule page
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="schedule-data"]')).toBeVisible();

    // Note: In real test, wait for actual timeout. For automation, we simulate timeout
    // by manipulating session storage or waiting reduced time in test environment
    const startTime = Date.now();

    // Wait for configured inactivity timeout period
    // For testing purposes, using a shorter timeout or mocking
    await page.waitForTimeout(SESSION_TIMEOUT_MS);

    // After timeout period, attempt to interact with the page
    await page.click('[data-testid="schedule-refresh-button"]').catch(() => {});

    // Expected Result: Session timeout message displayed
    await expect(page.locator('[data-testid="session-timeout-message"]').or(page.locator('text=/session.*expired|timeout/i'))).toBeVisible({ timeout: 5000 });

    // Verify redirect to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 10000 });

    // Attempt to access schedule page directly via URL
    await page.goto(`${BASE_URL}/schedule`);
    await expect(page).toHaveURL(/.*login/);

    // Enter valid credentials and log in again
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
  });

  test('Verify HTTPS secure transmission', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    
    // Verify page is served over HTTPS in production
    const url = page.url();
    if (!url.includes('localhost')) {
      expect(url).toMatch(/^https:/);
    }

    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    
    // Monitor network request to ensure secure transmission
    const [request] = await Promise.all([
      page.waitForRequest(request => request.url().includes('/login') || request.url().includes('/auth')),
      page.click('[data-testid="login-button"]')
    ]);

    // Verify request uses secure protocol
    if (!request.url().includes('localhost')) {
      expect(request.url()).toMatch(/^https:/);
    }
  });

  test('Verify access denied without authentication', async ({ page }) => {
    // Attempt to access schedule page without login
    await page.goto(`${BASE_URL}/schedule`);
    
    // Expected Result: Redirected to login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();

    // Attempt to access dashboard without login
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page).toHaveURL(/.*login/);
  });
});