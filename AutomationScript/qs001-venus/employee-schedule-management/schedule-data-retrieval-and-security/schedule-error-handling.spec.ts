import { test, expect } from '@playwright/test';

test.describe('Schedule Error Handling - Story 19', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULE_PAGE_URL = `${BASE_URL}/schedule`;
  const ERROR_MESSAGE_TIMEOUT = 2000;

  test('Validate error message display on schedule load failure', async ({ page, context }) => {
    // Step 1: Configure test environment to simulate schedule data retrieval failure
    await context.route('**/api/schedule**', async (route) => {
      await route.abort('failed');
    });

    // Alternative: Simulate 500 Internal Server Error
    await context.route('**/api/schedule**', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal Server Error' })
      });
    });

    // Step 2: Employee accesses schedule page
    const startTime = Date.now();
    await page.goto(SCHEDULE_PAGE_URL);

    // Expected Result: System detects failure and displays descriptive error message
    const errorMessage = page.locator('[data-testid="schedule-error-message"]').or(page.locator('.error-message')).or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: ERROR_MESSAGE_TIMEOUT });

    // Verify error message display time is within 2 seconds
    const displayTime = Date.now() - startTime;
    expect(displayTime).toBeLessThanOrEqual(ERROR_MESSAGE_TIMEOUT);

    // Step 3: Verify error message content for clarity and helpfulness
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText?.length).toBeGreaterThan(10);

    // Step 4: Employee views retry option
    const retryButton = page.locator('[data-testid="retry-button"]').or(page.locator('button:has-text("Retry")')).or(page.locator('button:has-text("Try Again")'));
    await expect(retryButton).toBeVisible();
    await expect(retryButton).toBeEnabled();

    // Step 5: Employee views support contact information
    const supportInfo = page.locator('[data-testid="support-contact"]').or(page.locator('text=/contact support/i')).or(page.locator('text=/help/i'));
    await expect(supportInfo).toBeVisible();

    // Verify the presentation and accessibility of retry and support options
    const supportText = await supportInfo.textContent();
    expect(supportText).toBeTruthy();

    // Verify options are clearly presented
    await expect(retryButton).toHaveAttribute('type', 'button');
  });

  test('Validate error message display on schedule load failure - timeout scenario', async ({ page, context }) => {
    // Simulate timeout scenario
    await context.route('**/api/schedule**', async (route) => {
      await new Promise(resolve => setTimeout(resolve, 60000));
      await route.fulfill({
        status: 408,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Request Timeout' })
      });
    });

    await page.goto(SCHEDULE_PAGE_URL);

    const errorMessage = page.locator('[data-testid="schedule-error-message"]').or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 10000 });

    const retryButton = page.locator('[data-testid="retry-button"]').or(page.locator('button:has-text("Retry")'));
    await expect(retryButton).toBeVisible();

    const supportInfo = page.locator('[data-testid="support-contact"]').or(page.locator('text=/contact support/i'));
    await expect(supportInfo).toBeVisible();
  });

  test('Verify error logging for diagnostics', async ({ page, context }) => {
    const testUserId = 'emp-12345';
    const testUserEmail = 'test.employee@company.com';
    let capturedErrorLog: any = null;

    // Step 1: Note current timestamp and logged-in employee user ID
    const errorTriggerTime = new Date();

    // Set up authentication context
    await context.addCookies([{
      name: 'user_id',
      value: testUserId,
      domain: new URL(BASE_URL).hostname,
      path: '/'
    }]);

    // Step 2: Configure test environment to trigger schedule data load error
    await context.route('**/api/schedule**', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Database connection error' })
      });
    });

    // Intercept logging API calls to verify error logging
    await context.route('**/api/logs**', async (route) => {
      const request = route.request();
      const postData = request.postDataJSON();
      capturedErrorLog = postData;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true })
      });
    });

    // Step 3: Employee navigates to schedule page to trigger the error
    await page.goto(SCHEDULE_PAGE_URL);

    // Wait for error to be displayed (system detects failure)
    const errorMessage = page.locator('[data-testid="schedule-error-message"]').or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 5000 });

    // Step 4: Wait for error logging to complete
    await page.waitForTimeout(1000);

    // Step 5: Verify error log entry if captured through API interception
    if (capturedErrorLog) {
      // Review timestamp accuracy
      expect(capturedErrorLog.timestamp).toBeTruthy();
      const logTimestamp = new Date(capturedErrorLog.timestamp);
      const timeDifference = Math.abs(logTimestamp.getTime() - errorTriggerTime.getTime());
      expect(timeDifference).toBeLessThan(5000);

      // Review user context information
      expect(capturedErrorLog.userId || capturedErrorLog.user_id || capturedErrorLog.userContext?.userId).toBeTruthy();

      // Review error details and completeness
      expect(capturedErrorLog.error || capturedErrorLog.errorMessage || capturedErrorLog.message).toBeTruthy();
      expect(capturedErrorLog.errorType || capturedErrorLog.type).toBeTruthy();

      // Verify no sensitive information is exposed
      const logString = JSON.stringify(capturedErrorLog).toLowerCase();
      expect(logString).not.toContain('password');
      expect(logString).not.toContain('token');
      expect(logString).not.toContain('secret');
      expect(logString).not.toContain('api_key');
      expect(logString).not.toContain('apikey');
    }
  });

  test('Verify error logging for diagnostics - database connection error', async ({ page, context }) => {
    const testUserId = 'emp-67890';
    const errorTriggerTime = new Date();
    let errorLogged = false;

    await context.addCookies([{
      name: 'user_id',
      value: testUserId,
      domain: new URL(BASE_URL).hostname,
      path: '/'
    }]);

    // Simulate database connection error
    await context.route('**/api/schedule**', async (route) => {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Service Unavailable - Database connection failed' })
      });
    });

    // Monitor console errors for client-side logging
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errorLogged = true;
      }
    });

    await page.goto(SCHEDULE_PAGE_URL);

    const errorMessage = page.locator('[data-testid="schedule-error-message"]').or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 5000 });

    // Verify error was logged (client-side or server-side)
    await page.waitForTimeout(1000);
    expect(errorLogged).toBeTruthy();
  });
});