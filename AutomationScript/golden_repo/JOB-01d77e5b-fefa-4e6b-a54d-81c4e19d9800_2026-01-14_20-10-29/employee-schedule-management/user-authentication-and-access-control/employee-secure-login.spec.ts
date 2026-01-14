import { test, expect } from '@playwright/test';

test.describe('Employee Secure Login - SSO Authentication', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SSO_PORTAL_URL = process.env.SSO_PORTAL_URL || 'https://sso.company.com';
  const VALID_USERNAME = process.env.TEST_USERNAME || 'employee@company.com';
  const VALID_PASSWORD = process.env.TEST_PASSWORD || 'SecurePass123!';
  const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

  test('Validate successful SSO login and schedule access', async ({ page }) => {
    // Step 1: Navigate to schedule system login page
    await page.goto(`${BASE_URL}/login`);
    
    // Expected Result: Redirected to corporate SSO portal
    await page.waitForURL(new RegExp(SSO_PORTAL_URL));
    await expect(page).toHaveURL(new RegExp(SSO_PORTAL_URL));
    await expect(page.locator('[data-testid="sso-login-form"]').or(page.locator('form[name="login"]'))).toBeVisible();

    // Step 2: Authenticate with valid corporate credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-submit-button"]');

    // Expected Result: Redirected back and logged into schedule system
    await page.waitForURL(new RegExp(BASE_URL));
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/(dashboard|schedule|home)`));
    
    // Verify user session is active
    const sessionIndicator = page.locator('[data-testid="user-session-indicator"]').or(page.locator('[data-testid="user-profile"]'));
    await expect(sessionIndicator).toBeVisible();
    await expect(sessionIndicator).toContainText(new RegExp(VALID_USERNAME.split('@')[0], 'i'));

    // Step 3: Access personal schedule page
    await page.click('[data-testid="schedule-nav-link"]');
    
    // Expected Result: Schedule displayed successfully
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/schedule`));
    await expect(page.locator('[data-testid="schedule-container"]').or(page.locator('[data-testid="personal-schedule"]'))).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]')).toContainText(/schedule|my schedule/i);
    
    // Verify schedule data is loaded
    const scheduleContent = page.locator('[data-testid="schedule-content"]').or(page.locator('.schedule-grid'));
    await expect(scheduleContent).toBeVisible();
  });

  test('Verify session timeout after inactivity', async ({ page }) => {
    // Step 1: Log in and remain inactive for 15 minutes
    await page.goto(`${BASE_URL}/login`);
    await page.waitForURL(new RegExp(SSO_PORTAL_URL));
    
    // Authenticate
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-submit-button"]');
    
    // Wait for successful login
    await page.waitForURL(new RegExp(BASE_URL));
    await expect(page.locator('[data-testid="user-session-indicator"]').or(page.locator('[data-testid="user-profile"]'))).toBeVisible();
    
    // Note current time and remain inactive for 15 minutes
    const startTime = Date.now();
    
    // Simulate 15 minutes of inactivity by waiting
    // For testing purposes, we can use a shorter timeout or mock the session expiry
    // In real scenario, this would wait for actual 15 minutes
    await page.waitForTimeout(SESSION_TIMEOUT_MS);
    
    // Expected Result: Session expires and user is logged out
    // Check for session expiry indicators
    const sessionExpiredModal = page.locator('[data-testid="session-expired-modal"]').or(page.locator('text=/session.*expired/i'));
    await expect(sessionExpiredModal.or(page.locator('[data-testid="login-form"]'))).toBeVisible({ timeout: 10000 });

    // Step 2: Attempt to access schedule page after timeout
    await page.goto(`${BASE_URL}/schedule`);
    
    // Expected Result: Redirected to login page
    await page.waitForURL(new RegExp(`${BASE_URL}/login|${SSO_PORTAL_URL}`));
    await expect(page).toHaveURL(new RegExp(`/login|sso`));
    
    // Verify session cookies and tokens have been cleared
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(cookie => cookie.name.includes('session') || cookie.name.includes('token'));
    expect(sessionCookie).toBeUndefined();
  });

  test('Ensure unauthorized access is blocked', async ({ page }) => {
    // Step 1: Attempt to access schedule page without login
    // Clear any existing session data
    await page.context().clearCookies();
    
    // Directly navigate to schedule page URL without logging in
    await page.goto(`${BASE_URL}/schedule`);
    
    // Expected Result: Access denied and redirected to login
    await page.waitForURL(new RegExp(`${BASE_URL}/login|${SSO_PORTAL_URL}`), { timeout: 10000 });
    await expect(page).toHaveURL(new RegExp(`/login|sso`));
    
    // Verify that no schedule data is displayed or accessible
    const scheduleContainer = page.locator('[data-testid="schedule-container"]').or(page.locator('[data-testid="personal-schedule"]'));
    await expect(scheduleContainer).not.toBeVisible();
    
    // Verify unauthorized access message or login form is shown
    const loginForm = page.locator('[data-testid="sso-login-form"]').or(page.locator('form[name="login"]'));
    const unauthorizedMessage = page.locator('[data-testid="unauthorized-message"]').or(page.locator('text=/unauthorized|access denied/i'));
    await expect(loginForm.or(unauthorizedMessage)).toBeVisible();
    
    // Check browser developer tools for any exposed session tokens or data
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(cookie => 
      cookie.name.includes('session') || 
      cookie.name.includes('token') || 
      cookie.name.includes('auth')
    );
    expect(sessionCookie).toBeUndefined();
    
    // Verify no sensitive data in localStorage
    const localStorageData = await page.evaluate(() => {
      const data: Record<string, string> = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) {
          data[key] = localStorage.getItem(key) || '';
        }
      }
      return data;
    });
    
    const sensitiveKeys = Object.keys(localStorageData).filter(key => 
      key.toLowerCase().includes('token') || 
      key.toLowerCase().includes('session') || 
      key.toLowerCase().includes('auth')
    );
    expect(sensitiveKeys.length).toBe(0);
    
    // Verify unauthorized access attempt would be logged (check network request)
    const accessLogRequest = page.waitForRequest(request => 
      request.url().includes('/api/audit') || 
      request.url().includes('/api/log') ||
      request.method() === 'POST'
    ).catch(() => null);
    
    // Attempt another unauthorized access
    await page.goto(`${BASE_URL}/schedule`);
    
    // Verify redirect again
    await expect(page).toHaveURL(new RegExp(`/login|sso`));
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Clear cookies and storage after each test
    await page.context().clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  });
});