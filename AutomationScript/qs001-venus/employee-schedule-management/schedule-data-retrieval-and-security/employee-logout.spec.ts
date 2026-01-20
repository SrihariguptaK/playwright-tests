import { test, expect } from '@playwright/test';

test.describe('Employee Logout - Secure Session Management', () => {
  let authToken: string;
  let sessionCookie: string;

  test.beforeEach(async ({ page }) => {
    // Navigate to login page and authenticate
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and navigation to schedule page
    await expect(page).toHaveURL(/.*schedule/, { timeout: 5000 });
    
    // Store session information for verification
    const cookies = await page.context().cookies();
    const sessionCookieObj = cookies.find(c => c.name === 'session_token' || c.name === 'auth_token');
    if (sessionCookieObj) {
      sessionCookie = sessionCookieObj.value;
    }
  });

  test('Validate successful logout and session invalidation', async ({ page, context }) => {
    // Step 1: Employee clicks logout button
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButton).toBeVisible();
    
    const startTime = Date.now();
    
    // Monitor network request for logout API call
    const logoutRequestPromise = page.waitForRequest(request => 
      request.url().includes('/api/auth/logout') && request.method() === 'POST'
    );
    
    await logoutButton.click();
    
    // Expected Result: Logout request sent to server
    const logoutRequest = await logoutRequestPromise;
    expect(logoutRequest).toBeTruthy();
    
    // Step 2: System invalidates session and clears cookies
    await page.waitForResponse(response => 
      response.url().includes('/api/auth/logout') && response.status() === 200
    );
    
    // Expected Result: Session terminated
    const cookiesAfterLogout = await context.cookies();
    const sessionCookieAfterLogout = cookiesAfterLogout.find(c => c.name === 'session_token' || c.name === 'auth_token');
    
    // Verify session cookie is cleared or invalidated
    if (sessionCookieAfterLogout) {
      expect(sessionCookieAfterLogout.value).not.toBe(sessionCookie);
    }
    
    // Step 3: Employee is redirected to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Expected Result: Login page is displayed
    await expect(page.locator('[data-testid="login-form"]').or(page.getByRole('heading', { name: /login/i }))).toBeVisible();
    await expect(page.locator('[data-testid="username-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-input"]')).toBeVisible();
    
    // Verify logout completes within 2 seconds
    const endTime = Date.now();
    const logoutDuration = endTime - startTime;
    expect(logoutDuration).toBeLessThan(2000);
    
    // Verify all session-related cookies are cleared
    const allCookies = await context.cookies();
    const sessionRelatedCookies = allCookies.filter(c => 
      c.name.includes('session') || c.name.includes('auth') || c.name.includes('token')
    );
    expect(sessionRelatedCookies.length).toBe(0);
  });

  test('Verify no access after logout', async ({ page, context }) => {
    // Store the schedule page URL before logout
    const schedulePageUrl = page.url();
    expect(schedulePageUrl).toContain('schedule');
    
    // Verify initial access to schedule page
    await expect(page.locator('[data-testid="schedule-container"]').or(page.getByRole('main'))).toBeVisible();
    
    // Perform logout
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await logoutButton.click();
    
    // Wait for redirect to login page
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Step 1: Employee attempts to access schedule page after logout
    await page.goto(schedulePageUrl);
    
    // Expected Result: Access denied and redirected to login
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Verify no schedule data is displayed
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await expect(scheduleContainer).not.toBeVisible();
    
    // Verify login form is displayed instead
    await expect(page.locator('[data-testid="login-form"]').or(page.getByRole('heading', { name: /login/i }))).toBeVisible();
    
    // Attempt to access other protected pages
    const protectedPages = ['/profile', '/settings', '/schedule/weekly', '/schedule/monthly'];
    
    for (const protectedPage of protectedPages) {
      await page.goto(protectedPage);
      
      // Verify redirect to login for each protected page
      await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
      
      // Verify no sensitive information is displayed
      await expect(page.locator('[data-testid="employee-data"]')).not.toBeVisible();
      await expect(page.locator('[data-testid="schedule-data"]')).not.toBeVisible();
      await expect(page.locator('[data-testid="profile-data"]')).not.toBeVisible();
    }
    
    // Attempt to use browser back button
    await page.goBack();
    
    // Verify still on login page or redirected back to login
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    expect(currentUrl).toMatch(/login/);
  });

  test('Validate logout button is visible on all schedule pages', async ({ page }) => {
    // Test logout button visibility on main schedule page
    await expect(page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }))).toBeVisible();
    
    // Navigate to different schedule views and verify logout button presence
    const schedulePages = [
      { url: '/schedule/weekly', name: 'Weekly Schedule' },
      { url: '/schedule/monthly', name: 'Monthly Schedule' },
      { url: '/schedule/daily', name: 'Daily Schedule' }
    ];
    
    for (const schedulePage of schedulePages) {
      await page.goto(schedulePage.url);
      await page.waitForLoadState('networkidle');
      
      const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
      await expect(logoutButton).toBeVisible();
      await expect(logoutButton).toBeEnabled();
    }
  });

  test('Verify session cookies are securely cleared on logout', async ({ page, context }) => {
    // Get all cookies before logout
    const cookiesBeforeLogout = await context.cookies();
    const sessionCookiesBefore = cookiesBeforeLogout.filter(c => 
      c.name.includes('session') || c.name.includes('auth') || c.name.includes('token')
    );
    
    expect(sessionCookiesBefore.length).toBeGreaterThan(0);
    
    // Perform logout
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await logoutButton.click();
    
    // Wait for logout to complete
    await expect(page).toHaveURL(/.*login/, { timeout: 5000 });
    
    // Verify all session cookies are cleared
    const cookiesAfterLogout = await context.cookies();
    const sessionCookiesAfter = cookiesAfterLogout.filter(c => 
      c.name.includes('session') || c.name.includes('auth') || c.name.includes('token')
    );
    
    expect(sessionCookiesAfter.length).toBe(0);
    
    // Verify localStorage is also cleared
    const localStorageItems = await page.evaluate(() => {
      const items: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.includes('session') || key.includes('auth') || key.includes('token'))) {
          items.push(key);
        }
      }
      return items;
    });
    
    expect(localStorageItems.length).toBe(0);
  });
});