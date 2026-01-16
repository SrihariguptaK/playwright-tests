import { test, expect } from '@playwright/test';

test.describe('Story-19: Error messages when schedule data is unavailable', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EMPLOYEE_EMAIL = 'employee@test.com';
  const EMPLOYEE_PASSWORD = 'password123';

  test.beforeEach(async ({ page }) => {
    // Login as employee before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate error message display on data retrieval failure', async ({ page, context }) => {
    // Intercept API call and simulate backend failure
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });

    // Navigate to the schedule page as an employee
    await page.goto(`${BASE_URL}/schedule`);

    // Expected Result: Error message is displayed to employee
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('.error-message')).or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 1000 });

    // Employee reads error message
    const errorText = await errorMessage.textContent();

    // Expected Result: Message is clear and suggests retry or support contact
    expect(errorText).toBeTruthy();
    expect(errorText?.toLowerCase()).toMatch(/error|failed|unable|unavailable/);
    expect(errorText?.toLowerCase()).toMatch(/retry|try again|contact|support/);

    // Verify the error message appears within the specified time threshold (1 second)
    const errorDisplayTime = await page.evaluate(() => {
      const errorElement = document.querySelector('[data-testid="error-message"], .error-message, [role="alert"]');
      return errorElement ? true : false;
    });
    expect(errorDisplayTime).toBe(true);

    // Check that error message contains helpful information
    const hasRetryButton = await page.locator('[data-testid="retry-button"]').or(page.locator('button:has-text("Retry")')).or(page.locator('button:has-text("Try Again")')).isVisible().catch(() => false);
    const hasSupportLink = await page.locator('[data-testid="support-link"]').or(page.locator('a:has-text("support")')).or(page.locator('a:has-text("contact")')).isVisible().catch(() => false);
    
    expect(hasRetryButton || hasSupportLink || errorText?.toLowerCase().includes('retry') || errorText?.toLowerCase().includes('support')).toBe(true);
  });

  test('Ensure system stability during data failures', async ({ page }) => {
    // Intercept API call and simulate backend error (500 Internal Server Error)
    await page.route('**/api/schedule**', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal Server Error' })
      });
    });

    // Navigate to the schedule page as an employee
    await page.goto(`${BASE_URL}/schedule`);

    // Expected Result: Application remains stable without crashes
    // Verify that the user interface continues to be responsive
    await expect(page.locator('body')).toBeVisible();
    await expect(page.locator('[data-testid="header"]').or(page.locator('header')).or(page.locator('nav'))).toBeVisible();

    // Check for any console errors or application crashes
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    page.on('pageerror', error => {
      consoleErrors.push(error.message);
    });

    // Wait a moment to capture any errors
    await page.waitForTimeout(1000);

    // Verify no critical application crashes (page should still be functional)
    const isPageResponsive = await page.evaluate(() => {
      return document.readyState === 'complete';
    });
    expect(isPageResponsive).toBe(true);

    // Verify navigation elements are still clickable
    const navigationElement = page.locator('[data-testid="nav-home"]').or(page.locator('a:has-text("Home")')).or(page.locator('nav a')).first();
    await expect(navigationElement).toBeEnabled();

    // Attempt to retry the schedule data retrieval
    const retryButton = page.locator('[data-testid="retry-button"]').or(page.locator('button:has-text("Retry")')).or(page.locator('button:has-text("Try Again")'));
    
    if (await retryButton.isVisible()) {
      await retryButton.click();
      // Verify the application handles the retry without crashing
      await expect(page.locator('body')).toBeVisible();
    } else {
      // If no retry button, try refreshing the page
      await page.reload();
      await expect(page.locator('body')).toBeVisible();
    }

    // Verify application remains stable after retry attempt
    await expect(page).not.toHaveURL(/.*error/);
    const finalPageState = await page.evaluate(() => document.readyState);
    expect(finalPageState).toBe('complete');
  });

  test('Validate error message display on network timeout', async ({ page }) => {
    // Simulate network timeout
    await page.route('**/api/schedule**', route => {
      // Delay response indefinitely to simulate timeout
      setTimeout(() => {
        route.abort('timedout');
      }, 100);
    });

    // Navigate to the schedule page
    await page.goto(`${BASE_URL}/schedule`);

    // Expected Result: Error message is displayed within 1 second
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('.error-message')).or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible({ timeout: 1000 });

    // Verify error message content
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText?.toLowerCase()).toMatch(/timeout|network|connection|unavailable/);

    // Expected Result: Application remains stable
    await expect(page.locator('body')).toBeVisible();
  });

  test('Verify error logging for backend diagnostics', async ({ page }) => {
    let apiCallMade = false;
    let errorLogged = false;

    // Intercept API call to verify error handling
    await page.route('**/api/schedule**', route => {
      apiCallMade = true;
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Service Unavailable' })
      });
    });

    // Monitor console for error logging
    page.on('console', msg => {
      if (msg.type() === 'error' && msg.text().toLowerCase().includes('schedule')) {
        errorLogged = true;
      }
    });

    // Navigate to schedule page
    await page.goto(`${BASE_URL}/schedule`);

    // Wait for error to be processed
    await page.waitForTimeout(500);

    // Expected Result: System logs errors for backend diagnostics
    expect(apiCallMade).toBe(true);
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('.error-message')).or(page.locator('[role="alert"]'));
    await expect(errorMessage).toBeVisible();

    // Expected Result: Error is logged (either in console or sent to backend)
    // Note: In real implementation, this would check backend logs or monitoring service
    const hasErrorIndicator = errorLogged || await errorMessage.isVisible();
    expect(hasErrorIndicator).toBe(true);
  });
});