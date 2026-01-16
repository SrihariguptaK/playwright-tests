import { test, expect } from '@playwright/test';

test.describe('Story-14: Refresh Schedule View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the schedule page before each test
    await page.goto('/schedule');
    // Wait for initial schedule data to load
    await page.waitForSelector('[data-testid="schedule-container"]', { state: 'visible' });
  });

  test('Validate manual refresh updates schedule', async ({ page }) => {
    // Get initial schedule data
    const initialScheduleData = await page.locator('[data-testid="schedule-container"]').textContent();
    
    // Action: Employee clicks refresh button
    const refreshButton = page.locator('[data-testid="refresh-button"]');
    await expect(refreshButton).toBeVisible();
    await refreshButton.click();
    
    // Expected Result: Schedule data reloads without full page refresh
    // Verify loading indicator appears
    await expect(page.locator('[data-testid="refresh-indicator"]')).toBeVisible();
    
    // Wait for refresh to complete
    await expect(page.locator('[data-testid="refresh-indicator"]')).toBeHidden({ timeout: 5000 });
    
    // Verify page did not reload (check that page object is still valid and no navigation occurred)
    const currentUrl = page.url();
    expect(currentUrl).toContain('/schedule');
    
    // Action: Verify schedule data is current and accurate
    const updatedScheduleData = await page.locator('[data-testid="schedule-container"]').textContent();
    
    // Expected Result: Displayed schedule matches latest data
    expect(updatedScheduleData).toBeTruthy();
    // Verify schedule container is still visible and contains data
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Verify timestamp or last updated indicator shows recent time
    const lastUpdated = page.locator('[data-testid="last-updated-timestamp"]');
    if (await lastUpdated.isVisible()) {
      const timestamp = await lastUpdated.textContent();
      expect(timestamp).toBeTruthy();
    }
  });

  test('Validate automatic refresh functionality', async ({ page }) => {
    // Get initial schedule data
    const initialScheduleData = await page.locator('[data-testid="schedule-container"]').textContent();
    
    // Enable auto-refresh if there's a toggle
    const autoRefreshToggle = page.locator('[data-testid="auto-refresh-toggle"]');
    if (await autoRefreshToggle.isVisible()) {
      await autoRefreshToggle.check();
    }
    
    // Action: Wait for auto-refresh interval
    // Expected Result: Schedule data updates automatically
    // Wait for refresh indicator to appear (indicating auto-refresh started)
    await expect(page.locator('[data-testid="refresh-indicator"]')).toBeVisible({ timeout: 65000 });
    
    // Action: Verify visual refresh indicator appears during update
    // Expected Result: Indicator is visible and disappears after refresh
    await expect(page.locator('[data-testid="refresh-indicator"]')).toBeVisible();
    
    // Wait for refresh to complete
    await expect(page.locator('[data-testid="refresh-indicator"]')).toBeHidden({ timeout: 5000 });
    
    // Verify schedule data is still displayed after auto-refresh
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    const updatedScheduleData = await page.locator('[data-testid="schedule-container"]').textContent();
    expect(updatedScheduleData).toBeTruthy();
    
    // Verify no page reload occurred
    const currentUrl = page.url();
    expect(currentUrl).toContain('/schedule');
  });

  test('Validate error message on data unavailability', async ({ page }) => {
    // Navigate to the schedule page URL
    await page.goto('/schedule');
    
    // Simulate schedule data API failure by intercepting and failing the request
    await page.route('**/api/schedule**', route => {
      route.abort('failed');
    });
    
    // Trigger a refresh to cause the API failure
    const refreshButton = page.locator('[data-testid="refresh-button"]');
    if (await refreshButton.isVisible()) {
      await refreshButton.click();
    } else {
      await page.reload();
    }
    
    // Observe the schedule page display after API failure
    // Review the error message content for clarity and helpfulness
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    
    const errorText = await errorMessage.textContent();
    expect(errorText).toBeTruthy();
    expect(errorText?.length).toBeGreaterThan(10);
    
    // Verify error message includes contact information for assistance
    const contactInfo = page.locator('[data-testid="contact-support"]');
    await expect(contactInfo).toBeVisible();
    
    // Check that the contact information is clickable/actionable
    const contactLink = page.locator('[data-testid="contact-support"] a, [data-testid="contact-support"] button');
    if (await contactLink.count() > 0) {
      await expect(contactLink.first()).toBeVisible();
      const href = await contactLink.first().getAttribute('href');
      if (href) {
        expect(href).toMatch(/^(mailto:|tel:|http)/i);
      }
    }
  });

  test('Verify no sensitive info in error messages', async ({ page }) => {
    // Configure the schedule API to return an error response with sensitive details
    await page.route('**/api/schedule**', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Database connection failed',
          details: 'Connection string: postgresql://user:password@localhost:5432/db',
          stack: 'Error at /internal/path/controller.js:123',
          apiKey: 'sk_test_12345abcdef'
        })
      });
    });
    
    // Navigate to the schedule page as an employee user
    await page.goto('/schedule');
    
    // Trigger the error by refreshing
    const refreshButton = page.locator('[data-testid="refresh-button"]');
    if (await refreshButton.isVisible()) {
      await refreshButton.click();
    }
    
    // Wait for error to appear
    await page.waitForTimeout(2000);
    
    // Observe the error message displayed to the employee on the frontend
    const errorMessage = page.locator('[data-testid="error-message"]');
    if (await errorMessage.isVisible()) {
      const errorText = await errorMessage.textContent();
      
      // Verify no sensitive information is exposed
      expect(errorText).not.toContain('postgresql://');
      expect(errorText).not.toContain('password');
      expect(errorText).not.toContain('connection string');
      expect(errorText).not.toContain('sk_test_');
      expect(errorText).not.toContain('apiKey');
      expect(errorText).not.toContain('.js:');
      expect(errorText).not.toContain('/internal/');
      expect(errorText).not.toContain('stack');
    }
    
    // Inspect the browser console for any exposed sensitive information
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(msg.text());
    });
    
    // Check the network response in browser developer tools
    const responses: string[] = [];
    page.on('response', async response => {
      if (response.url().includes('/api/schedule')) {
        try {
          const body = await response.text();
          responses.push(body);
        } catch (e) {
          // Response body may not be available
        }
      }
    });
    
    // Trigger another refresh to capture console and network activity
    if (await refreshButton.isVisible()) {
      await refreshButton.click();
    }
    
    await page.waitForTimeout(2000);
    
    // Verify console logs don't contain sensitive info
    const consoleText = consoleLogs.join(' ');
    expect(consoleText).not.toContain('postgresql://');
    expect(consoleText).not.toContain('sk_test_');
    
    // Confirm the user-facing error message provides appropriate level of information
    const finalErrorText = await errorMessage.textContent();
    expect(finalErrorText).toBeTruthy();
    expect(finalErrorText).toMatch(/error|unavailable|try again|contact/i);
  });
});