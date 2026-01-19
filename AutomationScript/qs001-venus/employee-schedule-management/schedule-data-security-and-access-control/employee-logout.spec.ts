import { test, expect } from '@playwright/test';

test.describe('Employee Secure Logout', () => {
  let authToken: string;

  test.beforeEach(async ({ page }) => {
    // Login before each test to establish a session
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and navigation to schedule page
    await expect(page).toHaveURL(/.*schedule/);
    
    // Store auth token for later verification
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session_token' || c.name === 'auth_token');
    if (sessionCookie) {
      authToken = sessionCookie.value;
    }
  });

  test('Validate successful logout and session termination', async ({ page, context }) => {
    // Step 1: Locate the logout button on the current schedule page
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await expect(logoutButton).toBeVisible();

    // Step 2: Click the logout button
    const logoutStartTime = Date.now();
    await logoutButton.click();

    // Step 3: Observe the system response after clicking logout
    // Verify the current page URL after logout - should redirect to login page
    await page.waitForURL(/.*login/, { timeout: 5000 });
    const logoutDuration = Date.now() - logoutStartTime;
    
    // Expected Result: Session invalidated and employee redirected to login page
    await expect(page).toHaveURL(/.*login/);
    expect(logoutDuration).toBeLessThan(2000); // Logout completes within 2 seconds

    // Step 4: Click the browser back button to attempt returning to the schedule page
    await page.goBack();
    
    // Expected Result: Access denied and redirected to login
    await expect(page).toHaveURL(/.*login/);

    // Step 5: Manually enter the URL of a schedule page in the browser address bar
    await page.goto('/schedule');
    
    // Expected Result: Access denied and redirected to login
    await expect(page).toHaveURL(/.*login/);

    // Step 6: Attempt to make an API call using the previous session token
    const apiResponse = await page.request.get('/api/schedule', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      failOnStatusCode: false
    });
    
    // Expected Result: API call should fail with 401 Unauthorized
    expect(apiResponse.status()).toBe(401);
  });

  test('Verify client-side session data clearance on logout', async ({ page, context }) => {
    // Step 1: Open browser developer tools and navigate to Application/Storage tab
    // Step 2: Inspect and document existing session data in Cookies section
    const cookiesBeforeLogout = await context.cookies();
    const sessionCookiesBefore = cookiesBeforeLogout.filter(c => 
      c.name.includes('session') || c.name.includes('auth') || c.name.includes('token')
    );
    expect(sessionCookiesBefore.length).toBeGreaterThan(0);

    // Step 3: Inspect and document existing session data in Local Storage section
    const localStorageBefore = await page.evaluate(() => {
      const storage: { [key: string]: string } = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) {
          storage[key] = localStorage.getItem(key) || '';
        }
      }
      return storage;
    });

    // Step 4: Inspect and document existing session data in Session Storage section
    const sessionStorageBefore = await page.evaluate(() => {
      const storage: { [key: string]: string } = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key) {
          storage[key] = sessionStorage.getItem(key) || '';
        }
      }
      return storage;
    });

    // Step 5: Click the logout button from the application
    const logoutButton = page.locator('[data-testid="logout-button"]').or(page.getByRole('button', { name: /logout/i }));
    await logoutButton.click();
    
    // Wait for redirect to login page
    await page.waitForURL(/.*login/, { timeout: 5000 });

    // Step 6: Return to browser developer tools and inspect Cookies section
    const cookiesAfterLogout = await context.cookies();
    const sessionCookiesAfter = cookiesAfterLogout.filter(c => 
      c.name.includes('session') || c.name.includes('auth') || c.name.includes('token')
    );
    
    // Expected Result: All session data cleared from browser storage
    expect(sessionCookiesAfter.length).toBe(0);

    // Step 7: Inspect Local Storage section in developer tools
    const localStorageAfter = await page.evaluate(() => {
      const storage: { [key: string]: string } = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.includes('session') || key.includes('auth') || key.includes('token') || key.includes('employee'))) {
          storage[key] = localStorage.getItem(key) || '';
        }
      }
      return storage;
    });
    
    // Expected Result: No authentication tokens or sensitive employee data remains
    expect(Object.keys(localStorageAfter).length).toBe(0);

    // Step 8: Inspect Session Storage section in developer tools
    const sessionStorageAfter = await page.evaluate(() => {
      const storage: { [key: string]: string } = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key && (key.includes('session') || key.includes('auth') || key.includes('token') || key.includes('employee'))) {
          storage[key] = sessionStorage.getItem(key) || '';
        }
      }
      return storage;
    });
    
    // Expected Result: Verify no authentication tokens or sensitive employee data remains in any browser storage
    expect(Object.keys(sessionStorageAfter).length).toBe(0);
  });
});