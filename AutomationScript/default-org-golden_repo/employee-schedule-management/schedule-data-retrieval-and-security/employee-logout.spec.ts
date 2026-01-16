import { test, expect } from '@playwright/test';

test.describe('Employee Secure Logout', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const LOGIN_URL = `${BASE_URL}/login`;
  const SCHEDULE_URL = `${BASE_URL}/schedule`;
  const SCHEDULE_DETAILS_URL = `${BASE_URL}/schedule/details`;
  const SCHEDULE_SETTINGS_URL = `${BASE_URL}/schedule/settings`;
  const SCHEDULE_HISTORY_URL = `${BASE_URL}/schedule/history`;
  
  // Helper function to login before each test
  async function loginAsEmployee(page) {
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="email-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL(SCHEDULE_URL, { timeout: 5000 });
  }

  test.beforeEach(async ({ page }) => {
    // Login before each test
    await loginAsEmployee(page);
  });

  test('Validate successful logout and session termination', async ({ page }) => {
    // Employee locates and clicks the logout button
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButton).toBeVisible();
    
    const logoutStartTime = Date.now();
    await logoutButton.click();
    
    // Employee verifies redirect to login page
    await page.waitForURL(LOGIN_URL, { timeout: 5000 });
    const logoutEndTime = Date.now();
    const logoutDuration = logoutEndTime - logoutStartTime;
    
    // Verify logout completed within 2 seconds
    expect(logoutDuration).toBeLessThan(2000);
    
    // Verify current page is login page
    expect(page.url()).toBe(LOGIN_URL);
    await expect(page.locator('[data-testid="login-form"]').or(page.getByRole('heading', { name: /login/i }))).toBeVisible();
    
    // Employee attempts to navigate to schedule page by entering URL
    await page.goto(SCHEDULE_URL);
    
    // Access denied, redirected to login page
    await page.waitForURL(LOGIN_URL, { timeout: 5000 });
    expect(page.url()).toBe(LOGIN_URL);
    
    // Employee attempts to use browser back button
    await page.goBack();
    
    // Should still be on login page or redirected back
    await page.waitForTimeout(1000);
    const currentUrl = page.url();
    expect(currentUrl).toContain('login');
    
    // Employee attempts to access schedule details page directly
    await page.goto(SCHEDULE_DETAILS_URL);
    await page.waitForURL(LOGIN_URL, { timeout: 5000 });
    expect(page.url()).toBe(LOGIN_URL);
    
    // Employee attempts to access schedule settings page directly
    await page.goto(SCHEDULE_SETTINGS_URL);
    await page.waitForURL(LOGIN_URL, { timeout: 5000 });
    expect(page.url()).toBe(LOGIN_URL);
  });

  test('Verify logout button accessibility', async ({ page }) => {
    // Employee navigates to main schedule page (already there from beforeEach)
    await expect(page).toHaveURL(SCHEDULE_URL);
    
    // Verify logout button is visible and clickable on main schedule page
    const logoutButtonMain = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButtonMain).toBeVisible();
    await expect(logoutButtonMain).toBeEnabled();
    
    // Employee navigates to schedule details page
    await page.goto(SCHEDULE_DETAILS_URL);
    await page.waitForLoadState('networkidle');
    
    // Verify logout button is clickable on schedule details page
    const logoutButtonDetails = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButtonDetails).toBeVisible();
    await expect(logoutButtonDetails).toBeEnabled();
    
    // Employee navigates to schedule settings page
    await page.goto(SCHEDULE_SETTINGS_URL);
    await page.waitForLoadState('networkidle');
    
    // Verify logout button is clickable on schedule settings page
    const logoutButtonSettings = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButtonSettings).toBeVisible();
    await expect(logoutButtonSettings).toBeEnabled();
    
    // Employee navigates to schedule history page
    await page.goto(SCHEDULE_HISTORY_URL);
    await page.waitForLoadState('networkidle');
    
    // Verify logout button is clickable on schedule history page
    const logoutButtonHistory = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButtonHistory).toBeVisible();
    await expect(logoutButtonHistory).toBeEnabled();
    
    // Employee clicks logout button from current page
    await logoutButtonHistory.click();
    
    // Verify redirect to login page
    await page.waitForURL(LOGIN_URL, { timeout: 5000 });
    expect(page.url()).toBe(LOGIN_URL);
    await expect(page.locator('[data-testid="login-form"]').or(page.getByRole('heading', { name: /login/i }))).toBeVisible();
  });
});