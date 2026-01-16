import { test, expect } from '@playwright/test';

test.describe('Story-15: Secure Schedule Access', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULE_URL = `${BASE_URL}/schedule`;
  const LOGIN_URL = `${BASE_URL}/login`;
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'SecurePass123!';
  const OTHER_EMPLOYEE_ID = '12345';
  const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes in milliseconds

  test.beforeEach(async ({ page }) => {
    // Clear any existing sessions
    await page.context().clearCookies();
  });

  test('TC#1: Validate authentication requirement for schedule access - Attempt access without login', async ({ page }) => {
    // Action: Attempt to access schedule page without login
    await page.goto(SCHEDULE_URL);

    // Expected Result: Redirected to login page
    await expect(page).toHaveURL(new RegExp(LOGIN_URL));
    await expect(page.locator('[data-testid="login-form"]').or(page.getByRole('heading', { name: /login|sign in/i }))).toBeVisible();
  });

  test('TC#1: Validate authentication requirement for schedule access - Login with valid credentials', async ({ page }) => {
    // Navigate to login page
    await page.goto(LOGIN_URL);

    // Action: Login with valid credentials
    await page.locator('[data-testid="username-input"]').or(page.getByLabel(/username|email/i)).fill(VALID_USERNAME);
    await page.locator('[data-testid="password-input"]').or(page.getByLabel(/password/i)).fill(VALID_PASSWORD);
    await page.locator('[data-testid="login-button"]').or(page.getByRole('button', { name: /login|sign in/i })).click();

    // Expected Result: Access granted to own schedule
    await expect(page).toHaveURL(new RegExp('/schedule'));
    await expect(page.locator('[data-testid="schedule-container"]').or(page.getByRole('heading', { name: /schedule|my schedule/i }))).toBeVisible();
    await expect(page.locator('[data-testid="employee-schedule"]').or(page.locator('.schedule-content'))).toBeVisible();
  });

  test('TC#2: Verify session timeout after inactivity', async ({ page }) => {
    // Login first
    await page.goto(LOGIN_URL);
    await page.locator('[data-testid="username-input"]').or(page.getByLabel(/username|email/i)).fill(VALID_USERNAME);
    await page.locator('[data-testid="password-input"]').or(page.getByLabel(/password/i)).fill(VALID_PASSWORD);
    await page.locator('[data-testid="login-button"]').or(page.getByRole('button', { name: /login|sign in/i })).click();

    // Wait for successful login
    await expect(page).toHaveURL(new RegExp('/schedule'));

    // Action: Remain inactive for 15 minutes
    // Note: For testing purposes, we can manipulate the session timeout or use a shorter timeout in test environment
    // This simulates waiting for the inactivity period
    await page.waitForTimeout(INACTIVITY_TIMEOUT);

    // Try to interact with the page after timeout
    await page.locator('[data-testid="schedule-container"]').or(page.locator('body')).click();

    // Expected Result: Session expires and user is logged out
    // User should be redirected to login page or see session expired message
    await page.waitForURL(new RegExp(LOGIN_URL), { timeout: 10000 }).catch(() => {});
    
    const isOnLoginPage = page.url().includes('/login');
    const hasSessionExpiredMessage = await page.locator('[data-testid="session-expired-message"]').or(page.getByText(/session expired|logged out|timeout/i)).isVisible().catch(() => false);

    expect(isOnLoginPage || hasSessionExpiredMessage).toBeTruthy();
  });

  test('TC#3: Test access control prevents viewing other employees schedules', async ({ page }) => {
    // Login first
    await page.goto(LOGIN_URL);
    await page.locator('[data-testid="username-input"]').or(page.getByLabel(/username|email/i)).fill(VALID_USERNAME);
    await page.locator('[data-testid="password-input"]').or(page.getByLabel(/password/i)).fill(VALID_PASSWORD);
    await page.locator('[data-testid="login-button"]').or(page.getByRole('button', { name: /login|sign in/i })).click();

    // Wait for successful login
    await expect(page).toHaveURL(new RegExp('/schedule'));

    // Action: Attempt to access another employee's schedule URL
    const otherEmployeeScheduleUrl = `${BASE_URL}/schedule/${OTHER_EMPLOYEE_ID}`;
    await page.goto(otherEmployeeScheduleUrl);

    // Expected Result: Access denied with authorization error
    const hasAccessDeniedMessage = await page.locator('[data-testid="access-denied-message"]').or(page.getByText(/access denied|unauthorized|forbidden|not authorized/i)).isVisible({ timeout: 5000 }).catch(() => false);
    const isRedirectedToOwnSchedule = page.url().includes('/schedule') && !page.url().includes(OTHER_EMPLOYEE_ID);
    const hasErrorStatus = page.url().includes('/403') || page.url().includes('/error');

    // Verify that access is denied through one of the expected mechanisms
    expect(hasAccessDeniedMessage || isRedirectedToOwnSchedule || hasErrorStatus).toBeTruthy();

    // Additional assertion: Ensure other employee's data is not visible
    const otherEmployeeData = await page.locator(`[data-testid="employee-${OTHER_EMPLOYEE_ID}"]`).isVisible().catch(() => false);
    expect(otherEmployeeData).toBeFalsy();
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Logout if still logged in
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout|sign out/i }));
    if (await logoutButton.isVisible().catch(() => false)) {
      await logoutButton.click();
    }
  });
});