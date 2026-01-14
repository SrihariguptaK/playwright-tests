import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Status Confirmation on Login', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_EMAIL = 'employee@company.com';
  const VALID_PASSWORD = 'Password123!';

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate schedule status message on login - current schedule data', async ({ page }) => {
    // Intercept the schedule status API call and mock current data
    await page.route('**/api/schedules/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          lastUpdated: new Date().toISOString(),
          isUpToDate: true,
          message: 'Schedule is up to date'
        })
      });
    });

    // Employee enters valid credentials
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    
    // Click login button
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to dashboard/schedule page
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    
    // Verify 'Schedule is up to date' message is displayed immediately
    const statusMessage = page.locator('[data-testid="schedule-status-message"]');
    await expect(statusMessage).toBeVisible({ timeout: 5000 });
    await expect(statusMessage).toContainText('Schedule is up to date');
    
    // Verify message has success/positive styling
    await expect(statusMessage).toHaveClass(/success|up-to-date|current/);
  });

  test('Validate schedule status message on login - outdated schedule data', async ({ page }) => {
    // Calculate outdated timestamp (more than 48 hours ago)
    const outdatedDate = new Date();
    outdatedDate.setHours(outdatedDate.getHours() - 49);
    
    // Intercept the schedule status API call and mock outdated data
    await page.route('**/api/schedules/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          lastUpdated: outdatedDate.toISOString(),
          isUpToDate: false,
          message: 'Warning: Your schedule data may be outdated. Last updated 49 hours ago.'
        })
      });
    });

    // Employee enters valid credentials
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    
    // Click login button
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to dashboard/schedule page
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    
    // Verify warning message is displayed immediately
    const warningMessage = page.locator('[data-testid="schedule-status-message"]');
    await expect(warningMessage).toBeVisible({ timeout: 5000 });
    await expect(warningMessage).toContainText(/warning|outdated/i);
    
    // Verify message has warning styling
    await expect(warningMessage).toHaveClass(/warning|outdated|alert/);
  });

  test('Verify status check is performed securely for logged-in employee', async ({ page }) => {
    let scheduleStatusCalled = false;
    let authHeaderPresent = false;

    // Intercept API call to verify authentication
    await page.route('**/api/schedules/status', async (route) => {
      scheduleStatusCalled = true;
      const headers = route.request().headers();
      
      // Check for authentication header
      if (headers['authorization'] || headers['cookie']) {
        authHeaderPresent = true;
      }
      
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          lastUpdated: new Date().toISOString(),
          isUpToDate: true,
          message: 'Schedule is up to date'
        })
      });
    });

    // Employee logs in
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for dashboard
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    
    // Wait for status message to appear
    await page.waitForSelector('[data-testid="schedule-status-message"]', { timeout: 5000 });
    
    // Verify API was called
    expect(scheduleStatusCalled).toBeTruthy();
    
    // Verify authentication was present in request
    expect(authHeaderPresent).toBeTruthy();
  });

  test('Verify status message is shown immediately upon login', async ({ page }) => {
    const startTime = Date.now();
    
    // Mock API response
    await page.route('**/api/schedules/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          lastUpdated: new Date().toISOString(),
          isUpToDate: true,
          message: 'Schedule is up to date'
        })
      });
    });

    // Employee logs in
    await page.fill('[data-testid="email-input"]', VALID_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation
    await page.waitForURL('**/dashboard', { timeout: 10000 });
    
    // Verify status message appears immediately (within 3 seconds)
    const statusMessage = page.locator('[data-testid="schedule-status-message"]');
    await expect(statusMessage).toBeVisible({ timeout: 3000 });
    
    const endTime = Date.now();
    const displayTime = endTime - startTime;
    
    // Verify message appeared within reasonable time (less than 5 seconds total)
    expect(displayTime).toBeLessThan(5000);
  });
});