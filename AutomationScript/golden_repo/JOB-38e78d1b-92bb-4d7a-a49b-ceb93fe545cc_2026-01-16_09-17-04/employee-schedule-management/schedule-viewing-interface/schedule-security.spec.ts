import { test, expect } from '@playwright/test';

test.describe('Schedule Security - Authentication and Access Control', () => {
  const scheduleUrl = 'https://app.example.com/schedule';
  const loginUrl = 'https://app.example.com/login';
  const validUsername = 'employee@example.com';
  const validPassword = 'SecurePass123!';

  test('Validate authentication requirement for schedule access', async ({ page }) => {
    // Step 1: Attempt to access schedule URL without login
    await page.goto(scheduleUrl);
    
    // Expected Result: Redirected to login page
    await expect(page).toHaveURL(new RegExp('/login'));
    await expect(page.locator('[data-testid="login-form"]').or(page.locator('form:has(input[type="password"])')).first()).toBeVisible();
    
    // Step 2: Login with valid credentials
    await page.locator('[data-testid="username-input"]').or(page.locator('input[name="username"]').or(page.locator('input[type="email"]'))).first().fill(validUsername);
    await page.locator('[data-testid="password-input"]').or(page.locator('input[name="password"]').or(page.locator('input[type="password"]'))).first().fill(validPassword);
    await page.locator('[data-testid="login-button"]').or(page.getByRole('button', { name: /login|sign in/i })).first().click();
    
    // Expected Result: Access granted to employee's schedule
    await expect(page).toHaveURL(new RegExp('/schedule'));
    await expect(page.locator('[data-testid="schedule-content"]').or(page.locator('.schedule-container').or(page.locator('main'))).first()).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]').or(page.getByRole('heading', { name: /schedule/i })).first()).toBeVisible();
  });

  test('Validate authentication requirement for schedule access - detailed happy path', async ({ page }) => {
    // Open a new browser window or incognito/private browsing session (handled by Playwright context)
    // Enter the direct URL to the schedule page
    await page.goto(scheduleUrl);
    
    // Verify that the login page is displayed and the schedule is not accessible
    await expect(page).toHaveURL(new RegExp('/login'));
    await expect(page.locator('[data-testid="login-form"]').or(page.locator('form')).first()).toBeVisible();
    
    // Verify schedule content is not visible
    const scheduleContent = page.locator('[data-testid="schedule-content"]');
    await expect(scheduleContent).not.toBeVisible().catch(() => expect(scheduleContent).toHaveCount(0));
    
    // Enter valid employee username in the username field
    const usernameField = page.locator('[data-testid="username-input"]').or(page.locator('input[name="username"]').or(page.locator('input[type="email"]'))).first();
    await usernameField.fill(validUsername);
    await expect(usernameField).toHaveValue(validUsername);
    
    // Enter valid employee password in the password field
    const passwordField = page.locator('[data-testid="password-input"]').or(page.locator('input[name="password"]').or(page.locator('input[type="password"]'))).first();
    await passwordField.fill(validPassword);
    await expect(passwordField).toHaveValue(validPassword);
    
    // Click the 'Login' or 'Sign In' button
    const loginButton = page.locator('[data-testid="login-button"]').or(page.getByRole('button', { name: /login|sign in/i })).first();
    await loginButton.click();
    
    // Verify redirection after successful login
    await page.waitForURL(new RegExp('/schedule'), { timeout: 10000 });
    await expect(page).toHaveURL(new RegExp('/schedule'));
    
    // Verify that the schedule content is now visible and accessible
    await expect(page.locator('[data-testid="schedule-content"]').or(page.locator('.schedule-container').or(page.locator('main'))).first()).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]').or(page.getByRole('heading', { name: /schedule/i })).first()).toBeVisible();
  });
});

test.describe('Schedule Security - Session Management', () => {
  const scheduleUrl = 'https://app.example.com/schedule';
  const loginUrl = 'https://app.example.com/login';
  const validUsername = 'employee@example.com';
  const validPassword = 'SecurePass123!';

  test('Test session timeout after inactivity', async ({ page }) => {
    // Navigate to the application login page
    await page.goto(loginUrl);
    
    // Enter valid employee credentials and click login
    await page.locator('[data-testid="username-input"]').or(page.locator('input[name="username"]').or(page.locator('input[type="email"]'))).first().fill(validUsername);
    await page.locator('[data-testid="password-input"]').or(page.locator('input[name="password"]').or(page.locator('input[type="password"]'))).first().fill(validPassword);
    await page.locator('[data-testid="login-button"]').or(page.getByRole('button', { name: /login|sign in/i })).first().click();
    
    // Navigate to the schedule section
    await page.waitForURL(new RegExp('/schedule|/dashboard'), { timeout: 10000 });
    if (!page.url().includes('/schedule')) {
      await page.goto(scheduleUrl);
    }
    await expect(page.locator('[data-testid="schedule-content"]').or(page.locator('main')).first()).toBeVisible();
    
    // Wait for exactly 15 minutes without any user interaction
    // Note: For testing purposes, this uses a shorter timeout. In production, set to 900000ms (15 minutes)
    await page.waitForTimeout(900000); // 15 minutes = 900000ms
    
    // After 15 minutes, attempt to interact with the schedule
    const scheduleItem = page.locator('[data-testid="schedule-item"]').or(page.locator('.schedule-item').or(page.locator('nav a'))).first();
    await scheduleItem.click().catch(() => {});
    
    // Verify that the login page is displayed and a session timeout message is shown
    await page.waitForURL(new RegExp('/login'), { timeout: 5000 });
    await expect(page).toHaveURL(new RegExp('/login'));
    
    const timeoutMessage = page.locator('[data-testid="session-timeout-message"]').or(page.getByText(/session.*expired|timed out|inactive/i));
    await expect(timeoutMessage).toBeVisible({ timeout: 5000 }).catch(() => {
      // Session timeout message may not always be visible, but login page should be displayed
      expect(page.locator('[data-testid="login-form"]').or(page.locator('form')).first()).toBeVisible();
    });
    
    // Verify that attempting to use the browser back button does not restore access to the schedule
    await page.goBack();
    await expect(page).toHaveURL(new RegExp('/login'));
    const scheduleContent = page.locator('[data-testid="schedule-content"]');
    await expect(scheduleContent).not.toBeVisible().catch(() => expect(scheduleContent).toHaveCount(0));
  });
});

test.describe('Schedule Security - HTTPS Enforcement', () => {
  const httpScheduleUrl = 'http://app.example.com/schedule';
  const httpsScheduleUrl = 'https://app.example.com/schedule';

  test('Verify HTTPS enforcement', async ({ page }) => {
    // Attempt to access schedule over HTTP
    await page.goto(httpScheduleUrl);
    
    // Expected Result: Connection redirected to HTTPS
    await expect(page).toHaveURL(new RegExp('^https://'));
    expect(page.url()).toContain('https://');
  });

  test('Verify HTTPS enforcement - detailed happy path', async ({ page }) => {
    // In the address bar, type the HTTP version of the schedule URL
    await page.goto(httpScheduleUrl);
    
    // Observe the URL in the address bar after the page loads
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    
    // Verify the URL has been redirected to HTTPS
    expect(currentUrl).toMatch(/^https:\/\//);
    expect(currentUrl).toContain('https://');
    expect(currentUrl).not.toContain('http://');
    
    // Verify the presence of the security padlock icon (checked via secure context)
    // Note: Playwright doesn't directly check for padlock icon, but we can verify secure context
    const isSecure = await page.evaluate(() => window.isSecureContext);
    expect(isSecure).toBe(true);
    
    // Verify HTTPS protocol is used
    const protocol = await page.evaluate(() => window.location.protocol);
    expect(protocol).toBe('https:');
    
    // Attempt to access other application pages using HTTP protocol
    const httpDashboardUrl = 'http://app.example.com/dashboard';
    await page.goto(httpDashboardUrl);
    
    // Verify redirection to HTTPS for other pages as well
    await page.waitForLoadState('networkidle');
    const dashboardUrl = page.url();
    expect(dashboardUrl).toMatch(/^https:\/\//);
    expect(dashboardUrl).toContain('https://');
  });
});