import { test, expect } from '@playwright/test';

test.describe('Secure Schedule Access - Authentication and Authorization', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee.test@company.com';
  const VALID_PASSWORD = 'SecurePass123!';
  const INVALID_USERNAME = 'invalid.user@company.com';
  const INVALID_PASSWORD = 'WrongPassword123';
  const SESSION_TIMEOUT_MS = 30000; // 30 seconds for testing purposes

  test.beforeEach(async ({ page }) => {
    // Clear any existing sessions
    await page.context().clearCookies();
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate successful login and schedule access', async ({ page }) => {
    // Step 1: Employee navigates to login page
    await expect(page).toHaveURL(/.*login/);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Verify login form elements are displayed
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="login-submit-button"]')).toBeVisible();

    // Step 2: Employee enters valid credentials and submits
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-submit-button"]');

    // Wait for authentication to complete
    await page.waitForURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Verify session is created by checking for session token or user indicator
    const sessionToken = await page.evaluate(() => {
      return localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken');
    });
    expect(sessionToken).toBeTruthy();

    // Verify user is authenticated by checking for user menu or profile
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 3: Employee accesses schedule page
    await page.click('[data-testid="schedule-menu-link"]');
    await page.waitForURL(/.*schedule/, { timeout: 5000 });

    // Verify schedule data for authenticated employee is displayed
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-schedule-data"]')).toBeVisible();
    
    // Verify employee name or ID is displayed
    await expect(page.locator('[data-testid="employee-name"]')).toContainText(VALID_USERNAME.split('@')[0]);
    
    // Verify schedule entries are present
    const scheduleEntries = page.locator('[data-testid="schedule-entry"]');
    await expect(scheduleEntries).toHaveCount(await scheduleEntries.count());
    expect(await scheduleEntries.count()).toBeGreaterThan(0);

    // Verify HTTPS encryption by checking protocol
    const url = page.url();
    if (!url.startsWith('http://localhost')) {
      expect(url).toMatch(/^https:/);
    }
  });

  test('Verify access denial with invalid credentials', async ({ page }) => {
    // Step 1: Employee enters invalid login credentials
    await page.fill('[data-testid="username-input"]', INVALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-submit-button"]');

    // Wait for error message
    await page.waitForSelector('[data-testid="login-error-message"]', { timeout: 3000 });
    
    // Verify authentication fails with error message
    const errorMessage = page.locator('[data-testid="login-error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/invalid credentials|authentication failed|incorrect username or password/i);
    
    // Verify user remains on login page
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Employee attempts to access schedule without login
    await page.goto(`${BASE_URL}/schedule`);
    
    // Verify access denied with authentication required message
    await expect(page).toHaveURL(/.*login/);
    const authRequiredMessage = page.locator('[data-testid="auth-required-message"]');
    await expect(authRequiredMessage).toBeVisible();
    await expect(authRequiredMessage).toContainText(/authentication required|please log in|unauthorized/i);

    // Step 3: Verify no schedule data is exposed
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await expect(scheduleContainer).not.toBeVisible();
    
    // Check that no schedule data exists in page content
    const pageContent = await page.content();
    expect(pageContent).not.toContain('schedule-entry');
    expect(pageContent).not.toContain('employee-schedule-data');

    // Verify no data in local/session storage
    const storageData = await page.evaluate(() => {
      return {
        localStorage: Object.keys(localStorage).filter(key => key.includes('schedule')),
        sessionStorage: Object.keys(sessionStorage).filter(key => key.includes('schedule'))
      };
    });
    expect(storageData.localStorage.length).toBe(0);
    expect(storageData.sessionStorage.length).toBe(0);

    // Test with valid username but incorrect password
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', INVALID_PASSWORD);
    await page.click('[data-testid="login-submit-button"]');
    
    await page.waitForSelector('[data-testid="login-error-message"]', { timeout: 3000 });
    const errorMsg = page.locator('[data-testid="login-error-message"]');
    await expect(errorMsg).toBeVisible();
    await expect(page).toHaveURL(/.*login/);
  });

  test('Test session timeout and logout behavior', async ({ page }) => {
    // Step 1: Employee logs in with valid credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-submit-button"]');
    
    await page.waitForURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Navigate to schedule page
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Store initial session token
    const initialToken = await page.evaluate(() => {
      return localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken');
    });
    expect(initialToken).toBeTruthy();

    // Step 2: Employee remains idle past session timeout
    // Wait for session timeout period
    await page.waitForTimeout(SESSION_TIMEOUT_MS);

    // Step 3: Employee attempts to access schedule after timeout
    await page.click('[data-testid="schedule-menu-link"]').catch(() => {});
    
    // Verify session expires and employee is redirected to login page
    await page.waitForURL(/.*login/, { timeout: 5000 });
    await expect(page).toHaveURL(/.*login/);
    
    // Verify session timeout message
    const timeoutMessage = page.locator('[data-testid="session-timeout-message"]');
    await expect(timeoutMessage).toBeVisible();
    await expect(timeoutMessage).toContainText(/session expired|timed out|please log in again/i);

    // Verify session token is invalidated
    const expiredToken = await page.evaluate(() => {
      return localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken');
    });
    expect(expiredToken).toBeFalsy();

    // Step 4: Test manual logout
    // Log in again
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-submit-button"]');
    
    await page.waitForURL(/.*dashboard|schedule/, { timeout: 5000 });
    
    // Navigate to schedule
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

    // Employee logs out manually
    await page.click('[data-testid="logout-button"]');
    
    // Verify session invalidated and redirected to login
    await page.waitForURL(/.*login/, { timeout: 5000 });
    await expect(page).toHaveURL(/.*login/);

    // Verify session token is cleared
    const loggedOutToken = await page.evaluate(() => {
      return localStorage.getItem('sessionToken') || sessionStorage.getItem('sessionToken');
    });
    expect(loggedOutToken).toBeFalsy();

    // Attempt to access schedule after manual logout
    await page.goto(`${BASE_URL}/schedule`);
    
    // Verify access denied and redirected back to login
    await expect(page).toHaveURL(/.*login/);
    
    // Verify schedule data is not accessible
    await expect(page.locator('[data-testid="schedule-container"]')).not.toBeVisible();

    // Try using browser back button
    await page.goBack();
    
    // Should still be on login or redirected to login
    await expect(page).toHaveURL(/.*login/);
    
    // Verify no schedule data is visible
    const scheduleData = page.locator('[data-testid="employee-schedule-data"]');
    await expect(scheduleData).not.toBeVisible();
  });

  test.afterEach(async ({ page }) => {
    // Clean up: ensure logout and clear session
    await page.context().clearCookies();
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  });
});