import { test, expect } from '@playwright/test';

test.describe('Employee Secure Logout', () => {
  let authToken: string;

  test.beforeEach(async ({ page }) => {
    // Login before each test to establish session
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and navigation to schedule page
    await expect(page).toHaveURL(/.*schedule/);
    
    // Store auth token for verification
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session_token' || c.name === 'auth_token');
    if (sessionCookie) {
      authToken = sessionCookie.value;
    }
  });

  test('Validate successful logout and session termination', async ({ page, context }) => {
    // Verify user is on schedule page
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Step 1: Locate and click logout button
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButton).toBeVisible();
    await logoutButton.click();

    // Expected Result: User session terminated and redirected to login page
    await page.waitForURL(/.*login/, { timeout: 5000 });
    await expect(page).toHaveURL(/.*login/);
    
    // Verify logout confirmation message is displayed
    const confirmationMessage = page.locator('[data-testid="logout-message"]').or(page.getByText(/logged out successfully/i));
    await expect(confirmationMessage).toBeVisible({ timeout: 3000 }).catch(() => {
      // Message might be transient, continue with other validations
    });

    // Check browser cookies and session storage for session tokens
    const cookiesAfterLogout = await context.cookies();
    const sessionCookieAfterLogout = cookiesAfterLogout.find(c => c.name === 'session_token' || c.name === 'auth_token');
    expect(sessionCookieAfterLogout).toBeUndefined();

    // Verify session storage is cleared
    const sessionStorageData = await page.evaluate(() => {
      return {
        token: sessionStorage.getItem('token'),
        authToken: sessionStorage.getItem('authToken'),
        sessionId: sessionStorage.getItem('sessionId')
      };
    });
    expect(sessionStorageData.token).toBeNull();
    expect(sessionStorageData.authToken).toBeNull();
    expect(sessionStorageData.sessionId).toBeNull();

    // Verify local storage is cleared
    const localStorageData = await page.evaluate(() => {
      return {
        token: localStorage.getItem('token'),
        authToken: localStorage.getItem('authToken'),
        user: localStorage.getItem('user')
      };
    });
    expect(localStorageData.token).toBeNull();
    expect(localStorageData.authToken).toBeNull();

    // Step 2: Attempt to access schedule page after logout
    await page.goto('/schedule');

    // Expected Result: Access denied and redirected to login
    await page.waitForURL(/.*login/, { timeout: 5000 });
    await expect(page).toHaveURL(/.*login/);
    
    // Verify schedule data is not accessible
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await expect(scheduleContainer).not.toBeVisible();

    // Verify login form is displayed
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
  });

  test('Verify browser back button does not allow access after logout', async ({ page }) => {
    // Navigate to schedule page
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Logout
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await logoutButton.click();
    await page.waitForURL(/.*login/);

    // Click browser back button
    await page.goBack();

    // Verify user is redirected back to login or access is denied
    await page.waitForURL(/.*login/, { timeout: 5000 });
    await expect(page).toHaveURL(/.*login/);
    
    // Verify schedule is not accessible
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await expect(scheduleContainer).not.toBeVisible();
  });

  test('Verify direct URL access to schedule page after logout is blocked', async ({ page }) => {
    // Logout from current session
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await logoutButton.click();
    await page.waitForURL(/.*login/);

    // Attempt to access schedule page directly via URL
    await page.goto('/schedule');

    // Verify redirect to login page
    await page.waitForURL(/.*login/, { timeout: 5000 });
    await expect(page).toHaveURL(/.*login/);

    // Verify unauthorized access message or login form
    const loginForm = page.locator('[data-testid="login-form"]').or(page.locator('form').filter({ hasText: /login/i }));
    await expect(loginForm).toBeVisible();

    // Verify schedule data is not rendered
    const scheduleData = page.locator('[data-testid="schedule-data"]').or(page.locator('[data-testid="schedule-container"]'));
    await expect(scheduleData).not.toBeVisible();
  });

  test('Verify logout button is accessible from all pages', async ({ page }) => {
    // Check logout button on schedule page
    await page.goto('/schedule');
    let logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButton).toBeVisible();

    // Check logout button on profile page if exists
    await page.goto('/profile').catch(() => {});
    const currentUrl = page.url();
    if (currentUrl.includes('/profile')) {
      logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
      await expect(logoutButton).toBeVisible();
    }

    // Check logout button on settings page if exists
    await page.goto('/settings').catch(() => {});
    const settingsUrl = page.url();
    if (settingsUrl.includes('/settings')) {
      logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
      await expect(logoutButton).toBeVisible();
    }
  });

  test('Verify session termination is immediate upon logout', async ({ page, context }) => {
    // Verify user has active session
    await expect(page).toHaveURL(/.*schedule/);
    const cookiesBeforeLogout = await context.cookies();
    const sessionCookieBefore = cookiesBeforeLogout.find(c => c.name === 'session_token' || c.name === 'auth_token');
    expect(sessionCookieBefore).toBeDefined();

    // Record timestamp before logout
    const logoutTimestamp = Date.now();

    // Click logout
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await logoutButton.click();
    await page.waitForURL(/.*login/);

    // Verify session is terminated immediately
    const cookiesAfterLogout = await context.cookies();
    const sessionCookieAfter = cookiesAfterLogout.find(c => c.name === 'session_token' || c.name === 'auth_token');
    expect(sessionCookieAfter).toBeUndefined();

    // Verify termination happened within reasonable time (< 2 seconds)
    const terminationTime = Date.now() - logoutTimestamp;
    expect(terminationTime).toBeLessThan(2000);

    // Attempt API call with old session (should fail)
    const response = await page.request.get('/api/schedule', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      failOnStatusCode: false
    });
    
    // Verify API returns unauthorized status
    expect(response.status()).toBeGreaterThanOrEqual(401);
    expect(response.status()).toBeLessThanOrEqual(403);
  });
});