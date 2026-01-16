import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('Export Schedule to PDF', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the schedule page and login as employee
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*schedule/);
  });

  test('#1 Validate successful PDF export of schedule', async ({ page }) => {
    // Step 1: Employee views schedule in any supported view
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Verify schedule is displayed with shifts
    const scheduleItems = page.locator('[data-testid="shift-item"]');
    await expect(scheduleItems.first()).toBeVisible();
    
    // Step 2: Employee clicks 'Export to PDF' button
    const downloadPromise = page.waitForEvent('download');
    const startTime = Date.now();
    
    await page.click('[data-testid="export-pdf-button"]');
    
    // Wait for download to start
    const download = await downloadPromise;
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    // Verify PDF is generated within 5 seconds
    expect(generationTime).toBeLessThanOrEqual(5);
    
    // Step 3: Employee downloads and opens PDF
    const downloadPath = path.join(__dirname, 'downloads', download.suggestedFilename());
    await download.saveAs(downloadPath);
    
    // Verify file exists and is a PDF
    expect(fs.existsSync(downloadPath)).toBeTruthy();
    expect(download.suggestedFilename()).toMatch(/\.pdf$/);
    
    // Verify file size is reasonable (not empty)
    const stats = fs.statSync(downloadPath);
    expect(stats.size).toBeGreaterThan(1000);
    
    // Clean up downloaded file
    fs.unlinkSync(downloadPath);
  });

  test('#1 Validate successful PDF export - Daily view', async ({ page }) => {
    // Navigate to schedule and select daily view
    await page.goto('/schedule');
    await page.click('[data-testid="view-selector"]');
    await page.click('[data-testid="daily-view-option"]');
    
    await expect(page.locator('[data-testid="schedule-view"]')).toHaveAttribute('data-view', 'daily');
    
    // Export PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('schedule');
    expect(download.suggestedFilename()).toMatch(/\.pdf$/);
  });

  test('#1 Validate successful PDF export - Weekly view', async ({ page }) => {
    // Navigate to schedule and select weekly view
    await page.goto('/schedule');
    await page.click('[data-testid="view-selector"]');
    await page.click('[data-testid="weekly-view-option"]');
    
    await expect(page.locator('[data-testid="schedule-view"]')).toHaveAttribute('data-view', 'weekly');
    
    // Export PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('schedule');
    expect(download.suggestedFilename()).toMatch(/\.pdf$/);
  });

  test('#1 Validate successful PDF export - Monthly view', async ({ page }) => {
    // Navigate to schedule and select monthly view
    await page.goto('/schedule');
    await page.click('[data-testid="view-selector"]');
    await page.click('[data-testid="monthly-view-option"]');
    
    await expect(page.locator('[data-testid="schedule-view"]')).toHaveAttribute('data-view', 'monthly');
    
    // Export PDF
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-button"]');
    
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('schedule');
    expect(download.suggestedFilename()).toMatch(/\.pdf$/);
  });

  test('#2 Verify error handling during export', async ({ page, context }) => {
    // Navigate to schedule page
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    
    // Step 1: Simulate backend failure during PDF generation
    // Intercept the export API call and return an error
    await page.route('**/api/schedules/export', async (route) => {
      await route.abort('failed');
    });
    
    // Click export button
    await page.click('[data-testid="export-pdf-button"]');
    
    // Step 2: Verify user-friendly error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    await expect(errorMessage).toContainText(/unable to export|failed to generate|error/i);
    
    // Verify error message is user-friendly (not technical)
    const errorText = await errorMessage.textContent();
    expect(errorText).not.toMatch(/500|error code|stack trace/i);
  });

  test('#2 Verify error handling - Network timeout', async ({ page }) => {
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    
    // Simulate network timeout
    await page.route('**/api/schedules/export', async (route) => {
      await page.waitForTimeout(10000);
      await route.abort('timedout');
    });
    
    await page.click('[data-testid="export-pdf-button"]');
    
    // Verify timeout error message
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 15000 });
    await expect(errorMessage).toContainText(/timeout|taking longer|try again/i);
  });

  test('#2 Verify error handling - Server error 500', async ({ page }) => {
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    
    // Simulate server error
    await page.route('**/api/schedules/export', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal server error' })
      });
    });
    
    await page.click('[data-testid="export-pdf-button"]');
    
    // Verify error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible({ timeout: 10000 });
    await expect(errorMessage).toContainText(/unable to export|something went wrong|try again later/i);
    
    // Verify close button or dismiss option exists
    const closeButton = page.locator('[data-testid="error-close-button"]');
    await expect(closeButton).toBeVisible();
  });
});