import { test, expect } from '@playwright/test';

test.describe('Employee Secure Logout', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const validEmployee = {
    username: 'employee.test@company.com',
    password: 'SecurePass123!'
  };

  test('Validate secure logout process', async ({ page }) => {
    // Step 1: Log in as employee
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', validEmployee.username);
    await page.fill('input[name="password"]', validEmployee.password);
    await page.click('button[type="submit"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Step 2: Click logout button
    const logoutButton = page.locator('button[data-testid="logout-button"]').or(page.locator('button:has-text("Logout")')).or(page.locator('a:has-text("Logout")'));
    await logoutButton.click();
    
    // Expected Result: User session is terminated and redirected to login page
    await expect(page).toHaveURL(/.*\/login/);
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    
    // Step 3: Attempt to navigate back to schedule pages
    await page.goto(`${baseURL}/dashboard`);
    
    // Expected Result: Access is denied and login page is shown
    await expect(page).toHaveURL(/.*\/login/);
    await expect(page.locator('input[name="username"]')).toBeVisible();
  });

  test('Verify cached data clearance on logout', async ({ page, context }) => {
    // Step 1: Log in and view schedule
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', validEmployee.username);
    await page.fill('input[name="password"]', validEmployee.password);
    await page.click('button[type="submit"]');
    
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Expected Result: Schedule data is cached
    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name.includes('session') || c.name.includes('token') || c.name.includes('auth'));
    expect(sessionCookie).toBeDefined();
    
    const localStorage = await page.evaluate(() => {
      return JSON.stringify(window.localStorage);
    });
    expect(localStorage).not.toBe('{}');
    
    // Step 2: Log out
    const logoutButton = page.locator('button[data-testid="logout-button"]').or(page.locator('button:has-text("Logout")')).or(page.locator('a:has-text("Logout")'));
    await logoutButton.click();
    
    await expect(page).toHaveURL(/.*\/login/);
    
    // Expected Result: Cached data is cleared
    const cookiesAfterLogout = await context.cookies();
    const sessionCookieAfterLogout = cookiesAfterLogout.find(c => c.name.includes('session') || c.name.includes('token') || c.name.includes('auth'));
    expect(sessionCookieAfterLogout).toBeUndefined();
    
    const localStorageAfterLogout = await page.evaluate(() => {
      return JSON.stringify(window.localStorage);
    });
    expect(localStorageAfterLogout === '{}' || localStorageAfterLogout === null).toBeTruthy();
    
    // Step 3: Log in again
    await page.fill('input[name="username"]', validEmployee.username);
    await page.fill('input[name="password"]', validEmployee.password);
    await page.click('button[type="submit"]');
    
    // Expected Result: Fresh schedule data is loaded
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    const newCookies = await context.cookies();
    const newSessionCookie = newCookies.find(c => c.name.includes('session') || c.name.includes('token') || c.name.includes('auth'));
    expect(newSessionCookie).toBeDefined();
    expect(newSessionCookie?.value).not.toBe(sessionCookie?.value);
  });

  test('Validate secure logout process - comprehensive navigation test', async ({ page }) => {
    // Navigate to the schedule system login page
    await page.goto(`${baseURL}/login`);
    await expect(page).toHaveURL(/.*\/login/);
    
    // Enter valid employee credentials and click login button
    await page.fill('input[name="username"]', validEmployee.username);
    await page.fill('input[name="password"]', validEmployee.password);
    await page.click('button[type="submit"]');
    
    // Verify that the schedule dashboard is displayed
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Locate the logout button on the dashboard page
    const logoutButton = page.locator('button[data-testid="logout-button"]').or(page.locator('button:has-text("Logout")')).or(page.locator('a:has-text("Logout")'));
    await expect(logoutButton).toBeVisible();
    
    // Click the logout button
    await logoutButton.click();
    
    // Verify the current page is the login page
    await expect(page).toHaveURL(/.*\/login/);
    await expect(page.locator('input[name="username"]')).toBeVisible();
    
    // Click browser back button to attempt navigation to schedule dashboard
    await page.goBack();
    await expect(page).toHaveURL(/.*\/login/);
    
    // Manually enter the schedule dashboard URL in the browser address bar
    await page.goto(`${baseURL}/dashboard`);
    await expect(page).toHaveURL(/.*\/login/);
    
    // Verify no error messages or session warnings are displayed
    const errorMessages = page.locator('[data-testid="error-message"]').or(page.locator('.error')).or(page.locator('[role="alert"]'));
    await expect(errorMessages).toHaveCount(0);
  });

  test('Verify cached data clearance on logout - detailed inspection', async ({ page, context }) => {
    // Navigate to the schedule system login page and log in with valid credentials
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', validEmployee.username);
    await page.fill('input[name="password"]', validEmployee.password);
    await page.click('button[type="submit"]');
    
    await expect(page).toHaveURL(/.*\/dashboard/);
    
    // Navigate through multiple schedule views (daily, weekly, monthly) to generate cached data
    const dailyViewButton = page.locator('[data-testid="daily-view"]').or(page.locator('button:has-text("Daily")')).first();
    if (await dailyViewButton.isVisible()) {
      await dailyViewButton.click();
      await page.waitForTimeout(500);
    }
    
    const weeklyViewButton = page.locator('[data-testid="weekly-view"]').or(page.locator('button:has-text("Weekly")')).first();
    if (await weeklyViewButton.isVisible()) {
      await weeklyViewButton.click();
      await page.waitForTimeout(500);
    }
    
    const monthlyViewButton = page.locator('[data-testid="monthly-view"]').or(page.locator('button:has-text("Monthly")')).first();
    if (await monthlyViewButton.isVisible()) {
      await monthlyViewButton.click();
      await page.waitForTimeout(500);
    }
    
    // Inspect browser cache, cookies, and local storage
    const cookiesBeforeLogout = await context.cookies();
    const localStorageBeforeLogout = await page.evaluate(() => {
      const items: Record<string, string> = {};
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        if (key) items[key] = window.localStorage.getItem(key) || '';
      }
      return items;
    });
    
    // Document the cached items including session tokens, cookies, and local storage entries
    const sessionTokens = cookiesBeforeLogout.filter(c => c.name.includes('session') || c.name.includes('token') || c.name.includes('auth'));
    expect(sessionTokens.length).toBeGreaterThan(0);
    expect(Object.keys(localStorageBeforeLogout).length).toBeGreaterThan(0);
    
    // Click the logout button
    const logoutButton = page.locator('button[data-testid="logout-button"]').or(page.locator('button:has-text("Logout")')).or(page.locator('a:has-text("Logout")'));
    await logoutButton.click();
    
    await expect(page).toHaveURL(/.*\/login/);
    
    // Immediately inspect browser cache, cookies, and local storage again
    const cookiesAfterLogout = await context.cookies();
    const localStorageAfterLogout = await page.evaluate(() => {
      const items: Record<string, string> = {};
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        if (key) items[key] = window.localStorage.getItem(key) || '';
      }
      return items;
    });
    
    // Verify that session tokens and authentication cookies are removed
    const sessionTokensAfterLogout = cookiesAfterLogout.filter(c => c.name.includes('session') || c.name.includes('token') || c.name.includes('auth'));
    expect(sessionTokensAfterLogout.length).toBe(0);
    
    const authKeysAfterLogout = Object.keys(localStorageAfterLogout).filter(key => key.includes('session') || key.includes('token') || key.includes('auth'));
    expect(authKeysAfterLogout.length).toBe(0);
    
    // Log in again with the same credentials
    await page.fill('input[name="username"]', validEmployee.username);
    await page.fill('input[name="password"]', validEmployee.password);
    await page.click('button[type="submit"]');
    
    await expect(page).toHaveURL(/.*\/dashboard/);
    
    // Observe the schedule data loading process
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Verify new session tokens and cookies are created
    const cookiesAfterRelogin = await context.cookies();
    const newSessionTokens = cookiesAfterRelogin.filter(c => c.name.includes('session') || c.name.includes('token') || c.name.includes('auth'));
    expect(newSessionTokens.length).toBeGreaterThan(0);
    
    // Verify new tokens are different from original tokens
    const originalTokenValues = sessionTokens.map(t => t.value);
    const newTokenValues = newSessionTokens.map(t => t.value);
    expect(newTokenValues.some(val => originalTokenValues.includes(val))).toBe(false);
  });
});