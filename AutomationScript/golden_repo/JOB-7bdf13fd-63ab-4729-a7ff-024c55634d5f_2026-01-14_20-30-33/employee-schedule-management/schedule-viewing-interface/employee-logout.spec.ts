import { test, expect } from '@playwright/test';

test.describe('Employee Secure Logout', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'SecurePass123!';

  test('Validate successful logout and session termination', async ({ page, context }) => {
    // Step 1: Navigate to the login page
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Enter valid username and password
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);

    // Step 3: Click the login button
    await page.click('[data-testid="login-button"]');
    await page.waitForLoadState('networkidle');

    // Step 4: Navigate to the schedule page from the dashboard
    await page.click('[data-testid="schedule-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Expected Result: Schedule displayed
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Step 5: Verify the logout button is visible on the schedule page
    const logoutButton = page.locator('[data-testid="logout-button"]');
    await expect(logoutButton).toBeVisible();

    // Step 6: Click the logout button
    await logoutButton.click();
    await page.waitForLoadState('networkidle');

    // Step 7: Verify a logout confirmation message is displayed
    const confirmationMessage = page.locator('[data-testid="logout-confirmation"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 5000 });
    await expect(confirmationMessage).toContainText(/logged out|successfully/i);

    // Expected Result: User is logged out and redirected to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 10000 });

    // Step 8: Check browser cookies and session storage
    const cookies = await context.cookies();
    const sessionCookie = cookies.find(cookie => cookie.name.toLowerCase().includes('session') || cookie.name.toLowerCase().includes('auth'));
    expect(sessionCookie).toBeUndefined();

    const sessionStorage = await page.evaluate(() => {
      return window.sessionStorage.length;
    });
    expect(sessionStorage).toBe(0);

    const localStorage = await page.evaluate(() => {
      const authToken = window.localStorage.getItem('authToken');
      const sessionId = window.localStorage.getItem('sessionId');
      return { authToken, sessionId };
    });
    expect(localStorage.authToken).toBeNull();
    expect(localStorage.sessionId).toBeNull();

    // Step 9: Click the browser back button
    await page.goBack();
    await page.waitForLoadState('networkidle');

    // Expected Result: Access denied and redirected to login
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="schedule-container"]')).not.toBeVisible();

    // Step 10: Attempt to access the schedule page directly by entering the URL
    await page.goto(`${BASE_URL}/schedule`);
    await page.waitForLoadState('networkidle');

    // Expected Result: Access denied and redirected to login
    await expect(page).toHaveURL(/.*login/);
    const unauthorizedMessage = page.locator('[data-testid="unauthorized-message"]');
    await expect(unauthorizedMessage.or(page.locator('text=/please log in|unauthorized|access denied/i'))).toBeVisible({ timeout: 5000 });

    // Step 11: Verify no schedule data is cached or visible
    await expect(page.locator('[data-testid="schedule-container"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="schedule-data"]')).not.toBeVisible();

    // Verify login form is displayed instead
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
  });

  test('Validate logout button is accessible from all schedule pages', async ({ page }) => {
    // Login first
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForLoadState('networkidle');

    // Navigate to schedule page
    await page.click('[data-testid="schedule-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Verify logout button is visible on main schedule page
    await expect(page.locator('[data-testid="logout-button"]')).toBeVisible();

    // Navigate to different schedule views if available
    const scheduleViews = ['weekly-view', 'monthly-view', 'daily-view'];
    for (const view of scheduleViews) {
      const viewButton = page.locator(`[data-testid="${view}-button"]`);
      if (await viewButton.isVisible()) {
        await viewButton.click();
        await page.waitForLoadState('networkidle');
        await expect(page.locator('[data-testid="logout-button"]')).toBeVisible();
      }
    }
  });

  test('Validate session invalidation prevents unauthorized access', async ({ page, context }) => {
    // Login
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForLoadState('networkidle');

    // Store session cookies before logout
    const cookiesBeforeLogout = await context.cookies();
    expect(cookiesBeforeLogout.length).toBeGreaterThan(0);

    // Navigate to schedule
    await page.click('[data-testid="schedule-link"]');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Logout
    await page.click('[data-testid="logout-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/.*login/);

    // Verify session cookies are cleared or invalidated
    const cookiesAfterLogout = await context.cookies();
    const sessionCookieAfterLogout = cookiesAfterLogout.find(cookie => 
      cookie.name.toLowerCase().includes('session') || 
      cookie.name.toLowerCase().includes('auth')
    );
    expect(sessionCookieAfterLogout).toBeUndefined();

    // Attempt to access protected resource
    await page.goto(`${BASE_URL}/schedule`);
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="schedule-container"]')).not.toBeVisible();
  });
});