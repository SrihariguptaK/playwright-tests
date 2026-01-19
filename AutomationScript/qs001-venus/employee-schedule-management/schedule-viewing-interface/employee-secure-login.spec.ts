import { test, expect } from '@playwright/test';

test.describe('Employee Secure Login - Story 16', () => {
  const BASE_URL = process.env.BASE_URL || 'https://schedule-system.example.com';
  const VALID_USERNAME = 'employee.user@company.com';
  const VALID_PASSWORD = 'SecurePass123!';
  const INVALID_USERNAME = 'nonexistent.user@company.com';
  const INVALID_PASSWORD = 'WrongPassword123';
  const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful login with valid credentials (happy-path)', async ({ page }) => {
    // Verify that the connection is secure by checking for HTTPS
    expect(page.url()).toContain('https://');
    
    // Verify secure connection indicators
    const url = new URL(page.url());
    expect(url.protocol).toBe('https:');

    // Enter valid username in the username field
    await page.fill('input[name="username"], input[type="email"], [data-testid="username-input"]', VALID_USERNAME);
    
    // Enter correct password in the password field
    await page.fill('input[name="password"], input[type="password"], [data-testid="password-input"]', VALID_PASSWORD);
    
    // Click the Login/Sign In button
    await page.click('button[type="submit"], button:has-text("Login"), button:has-text("Sign In"), [data-testid="login-button"]');
    
    // Wait for authentication process and page transition
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    
    // Verify that the schedule dashboard displays employee's name
    await expect(page.locator('[data-testid="user-name"], .user-profile, .employee-name')).toBeVisible();
    
    // Verify schedule data is displayed
    await expect(page.locator('[data-testid="schedule-data"], .schedule-container, #schedule')).toBeVisible();
    
    // Verify navigation options are available
    await expect(page.locator('nav, [data-testid="navigation"], .navigation-menu')).toBeVisible();
    
    // Check that a valid session has been established by verifying logout button
    await expect(page.locator('button:has-text("Logout"), button:has-text("Sign Out"), [data-testid="logout-button"]')).toBeVisible();
    
    // Verify user profile indicator is present
    await expect(page.locator('[data-testid="user-profile"], .user-info, .profile-icon')).toBeVisible();
  });

  test('Verify login failure with invalid credentials - invalid username (error-case)', async ({ page }) => {
    // Enter invalid/non-existent username
    await page.fill('input[name="username"], input[type="email"], [data-testid="username-input"]', INVALID_USERNAME);
    
    // Enter any password
    await page.fill('input[name="password"], input[type="password"], [data-testid="password-input"]', VALID_PASSWORD);
    
    // Click the Login/Sign In button
    await page.click('button[type="submit"], button:has-text("Login"), button:has-text("Sign In"), [data-testid="login-button"]');
    
    // Wait for error message to appear
    await page.waitForTimeout(1000);
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"], .error-message, .alert-error, [role="alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"], .error-message, .alert-error, [role="alert"]')).toContainText(/invalid|incorrect|failed|denied/i);
    
    // Verify user remains on login page
    expect(page.url()).toContain('/login');
    
    // Verify no redirect to dashboard occurred
    expect(page.url()).not.toContain('/dashboard');
  });

  test('Verify login failure with invalid credentials - invalid password (error-case)', async ({ page }) => {
    // Enter valid username
    await page.fill('input[name="username"], input[type="email"], [data-testid="username-input"]', VALID_USERNAME);
    
    // Enter incorrect password
    await page.fill('input[name="password"], input[type="password"], [data-testid="password-input"]', INVALID_PASSWORD);
    
    // Click the Login/Sign In button
    await page.click('button[type="submit"], button:has-text("Login"), button:has-text("Sign In"), [data-testid="login-button"]');
    
    // Wait for error message to appear
    await page.waitForTimeout(1000);
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"], .error-message, .alert-error, [role="alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"], .error-message, .alert-error, [role="alert"]')).toContainText(/invalid|incorrect|failed|denied/i);
    
    // Verify user remains on login page
    expect(page.url()).toContain('/login');
    
    // Verify no session is created - logout button should not be visible
    await expect(page.locator('button:has-text("Logout"), button:has-text("Sign Out"), [data-testid="logout-button"]')).not.toBeVisible();
    
    // Verify no access to schedule system is granted
    await expect(page.locator('[data-testid="schedule-data"], .schedule-container')).not.toBeVisible();
  });

  test('Test session timeout after inactivity (edge-case)', async ({ page }) => {
    // Login with valid credentials
    await page.fill('input[name="username"], input[type="email"], [data-testid="username-input"]', VALID_USERNAME);
    await page.fill('input[name="password"], input[type="password"], [data-testid="password-input"]', VALID_PASSWORD);
    await page.click('button[type="submit"], button:has-text("Login"), button:has-text("Sign In"), [data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    
    // Verify session is active by checking user profile
    await expect(page.locator('[data-testid="user-profile"], .user-info, .profile-icon')).toBeVisible();
    await expect(page.locator('button:has-text("Logout"), button:has-text("Sign Out"), [data-testid="logout-button"]')).toBeVisible();
    
    // Note current time and remain inactive for session timeout period
    const startTime = Date.now();
    
    // Wait for session timeout period plus buffer (15 minutes + 1 minute)
    const timeoutWithBuffer = SESSION_TIMEOUT_MS + (60 * 1000);
    await page.waitForTimeout(timeoutWithBuffer);
    
    // Attempt to interact with the schedule system
    await page.click('[data-testid="schedule-link"], nav a:has-text("Schedule"), .navigation-menu a').catch(() => {});
    
    // Wait for timeout redirect or error message
    await page.waitForTimeout(2000);
    
    // Verify user is redirected to login page or shown session expired message
    const currentUrl = page.url();
    const isOnLoginPage = currentUrl.includes('/login');
    const sessionExpiredVisible = await page.locator('[data-testid="session-expired"], .session-expired, [role="alert"]:has-text("session")').isVisible().catch(() => false);
    
    expect(isOnLoginPage || sessionExpiredVisible).toBeTruthy();
    
    // Verify user no longer has access to protected schedule data
    await expect(page.locator('[data-testid="schedule-data"], .schedule-container')).not.toBeVisible();
    
    // Attempt to navigate directly to dashboard URL
    await page.goto(`${BASE_URL}/dashboard`);
    
    // Verify redirect back to login page
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('/login');
    
    // Verify that expired session cannot be reused
    await expect(page.locator('[data-testid="user-profile"], .user-info')).not.toBeVisible();
    await expect(page.locator('[data-testid="schedule-data"], .schedule-container')).not.toBeVisible();
    
    // Verify login form is displayed, requiring re-authentication
    await expect(page.locator('input[name="username"], input[type="email"], [data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('input[name="password"], input[type="password"], [data-testid="password-input"]')).toBeVisible();
  });
});