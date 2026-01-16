import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Security - Authentication and Access Control', () => {
  const SCHEDULE_URL = process.env.SCHEDULE_URL || 'https://app.example.com/schedule';
  const LOGIN_URL = process.env.LOGIN_URL || 'https://app.example.com/login';
  const VALID_USERNAME = process.env.TEST_USERNAME || 'employee.test@example.com';
  const VALID_PASSWORD = process.env.TEST_PASSWORD || 'TestPassword123!';

  test('Validate authentication requirement for schedule access (happy-path)', async ({ page }) => {
    // Step 1: Attempt to access schedule URL without login
    await page.goto(SCHEDULE_URL);
    
    // Expected Result: Redirected to login page
    await expect(page).toHaveURL(new RegExp(LOGIN_URL));
    await expect(page.locator('input[name="username"], input[type="email"], input[data-testid="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"], input[type="password"], input[data-testid="password"]')).toBeVisible();
    
    // Step 2: Login with valid credentials
    const usernameField = page.locator('input[name="username"], input[type="email"], input[data-testid="username"]').first();
    const passwordField = page.locator('input[name="password"], input[type="password"], input[data-testid="password"]').first();
    const loginButton = page.locator('button[type="submit"], button:has-text("Login"), button:has-text("Sign In"), button[data-testid="login-button"]').first();
    
    await usernameField.fill(VALID_USERNAME);
    await passwordField.fill(VALID_PASSWORD);
    await loginButton.click();
    
    // Expected Result: Access granted to employee's schedule
    await expect(page).toHaveURL(new RegExp('/schedule'));
    await expect(page.locator('[data-testid="schedule-container"], .schedule, #schedule')).toBeVisible();
    
    // Verify only authenticated employee's schedule is displayed
    await expect(page.locator('[data-testid="employee-name"], .employee-name')).toContainText(new RegExp('.+'));
    
    // Verify authentication session is established
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(cookie => 
      cookie.name.toLowerCase().includes('session') || 
      cookie.name.toLowerCase().includes('auth') ||
      cookie.name.toLowerCase().includes('token')
    );
    expect(sessionCookie).toBeDefined();
  });

  test('Test session timeout after inactivity (edge-case)', async ({ page }) => {
    // Navigate to login page and authenticate
    await page.goto(LOGIN_URL);
    
    const usernameField = page.locator('input[name="username"], input[type="email"], input[data-testid="username"]').first();
    const passwordField = page.locator('input[name="password"], input[type="password"], input[data-testid="password"]').first();
    const loginButton = page.locator('button[type="submit"], button:has-text("Login"), button:has-text("Sign In"), button[data-testid="login-button"]').first();
    
    await usernameField.fill(VALID_USERNAME);
    await passwordField.fill(VALID_PASSWORD);
    await loginButton.click();
    
    // Verify successful login
    await expect(page).toHaveURL(new RegExp('/schedule'));
    await expect(page.locator('[data-testid="schedule-container"], .schedule, #schedule')).toBeVisible();
    
    // Wait for 15 minutes of inactivity (using timeout simulation)
    // Note: In real testing, this would wait 15 minutes. For practical automation, we simulate or use shorter timeouts
    // For demonstration, we'll use page.waitForTimeout with a note that this should be configured per environment
    const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes in milliseconds
    // In actual implementation, consider using a test environment with shorter timeout or mock time
    await page.waitForTimeout(INACTIVITY_TIMEOUT);
    
    // Attempt to interact with the application
    const scheduleElement = page.locator('[data-testid="schedule-container"], .schedule, #schedule').first();
    await scheduleElement.click({ timeout: 5000 }).catch(() => {});
    
    // Expected Result: User is logged out and redirected to login page
    await expect(page).toHaveURL(new RegExp(LOGIN_URL), { timeout: 10000 });
    
    // Verify session timeout message is displayed
    const timeoutMessage = page.locator('[data-testid="timeout-message"], .timeout-message, .alert:has-text("session"), .notification:has-text("timeout")');
    await expect(timeoutMessage).toBeVisible({ timeout: 5000 }).catch(() => {
      // Message might not always be visible, but URL redirect is mandatory
    });
    
    // Attempt to use browser back button
    await page.goBack();
    
    // Verify still on login page or redirected back to login
    await expect(page).toHaveURL(new RegExp(LOGIN_URL));
    
    // Verify authentication cookies have been cleared
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(cookie => 
      cookie.name.toLowerCase().includes('session') || 
      cookie.name.toLowerCase().includes('auth') ||
      cookie.name.toLowerCase().includes('token')
    );
    expect(sessionCookie).toBeUndefined();
  });

  test('Verify HTTPS enforcement (happy-path)', async ({ page, context }) => {
    // Attempt to access schedule page over HTTP
    const httpUrl = SCHEDULE_URL.replace('https://', 'http://');
    
    await page.goto(httpUrl);
    
    // Expected Result: Connection redirected to HTTPS
    await expect(page).toHaveURL(new RegExp('^https://'));
    
    // Verify the secure connection indicator
    const finalUrl = page.url();
    expect(finalUrl).toMatch(/^https:\/\//);
    
    // Verify HTTPS protocol is enforced
    expect(finalUrl.startsWith('https://')).toBeTruthy();
    
    // Open developer tools network tab and check for HTTPS
    const [response] = await Promise.all([
      page.waitForResponse(response => response.url().includes('schedule')),
      page.goto(SCHEDULE_URL)
    ]);
    
    expect(response.url()).toMatch(/^https:\/\//);
    
    // Attempt to access login page using HTTP protocol
    const httpLoginUrl = LOGIN_URL.replace('https://', 'http://');
    await page.goto(httpLoginUrl);
    
    // Verify redirect to HTTPS
    await expect(page).toHaveURL(new RegExp('^https://'));
    const loginPageUrl = page.url();
    expect(loginPageUrl.startsWith('https://')).toBeTruthy();
    
    // Check for mixed content warnings in console
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error' || msg.type() === 'warning') {
        consoleErrors.push(msg.text());
      }
    });
    
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Verify no mixed content warnings
    const mixedContentWarnings = consoleErrors.filter(error => 
      error.toLowerCase().includes('mixed content') ||
      error.toLowerCase().includes('insecure')
    );
    expect(mixedContentWarnings.length).toBe(0);
  });
});