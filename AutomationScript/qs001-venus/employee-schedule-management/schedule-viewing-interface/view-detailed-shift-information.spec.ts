import { test, expect } from '@playwright/test';

test.describe('View Detailed Shift Information', () => {
  test.beforeEach(async ({ page }) => {
    // Login as employee before each test
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*schedule/);
  });

  test('Validate detailed shift information display (happy-path)', async ({ page }) => {
    // Navigate to the schedule view page
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();

    // Identify a shift in the schedule view
    const shift = page.locator('[data-testid="shift-card"]').first();
    await expect(shift).toBeVisible();

    // Click or select the shift to view detailed information
    await shift.click();
    await expect(page.locator('[data-testid="shift-details-modal"]')).toBeVisible();

    // Verify that the role field is displayed in the detailed information
    const roleField = page.locator('[data-testid="shift-role"]');
    await expect(roleField).toBeVisible();
    await expect(roleField).not.toBeEmpty();

    // Verify that the location field is displayed in the detailed information
    const locationField = page.locator('[data-testid="shift-location"]');
    await expect(locationField).toBeVisible();
    await expect(locationField).not.toBeEmpty();

    // Verify that special instructions or notes are displayed
    const notesField = page.locator('[data-testid="shift-notes"]');
    await expect(notesField).toBeVisible();

    // Locate and observe the shift status indicator in the schedule view
    const statusIndicator = page.locator('[data-testid="shift-status"]');
    await expect(statusIndicator).toBeVisible();

    // Verify the status is displayed as either 'confirmed' or 'tentative'
    const statusText = await statusIndicator.textContent();
    expect(statusText?.toLowerCase()).toMatch(/confirmed|tentative/);
  });

  test('Verify access control for detailed shift data (error-case)', async ({ page }) => {
    // Navigate to the schedule view page
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();

    // Attempt to access another employee's shift details by manipulating URL parameters
    const anotherEmployeeShiftId = '99999';
    await page.goto(`/schedule/details?shiftId=${anotherEmployeeShiftId}`);

    // Observe the system response to the unauthorized access attempt
    // Verify that access is denied with appropriate message
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/access.*denied|unauthorized|not authorized/i);

    // Verify that no detailed shift information is displayed for the other employee's shift
    await expect(page.locator('[data-testid="shift-details-modal"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).not.toBeVisible();

    // Confirm that the employee can still access their own shift details
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();
    
    const ownShift = page.locator('[data-testid="shift-card"]').first();
    await ownShift.click();
    
    // Verify own shift details are accessible
    await expect(page.locator('[data-testid="shift-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
  });

  test('Employee selects a shift and views detailed information', async ({ page }) => {
    // Navigate to schedule view
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();

    // Employee selects a shift in schedule view
    const shift = page.locator('[data-testid="shift-card"]').first();
    await shift.click();

    // Detailed information including role, location, and notes is displayed
    const detailsModal = page.locator('[data-testid="shift-details-modal"]');
    await expect(detailsModal).toBeVisible();
    
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-notes"]')).toBeVisible();
  });

  test('Employee views shift status indicator', async ({ page }) => {
    // Navigate to schedule view
    await page.goto('/schedule');
    await expect(page.locator('[data-testid="schedule-view"]')).toBeVisible();

    // Employee selects a shift
    const shift = page.locator('[data-testid="shift-card"]').first();
    await shift.click();

    // Status is clearly shown as confirmed or tentative
    const statusIndicator = page.locator('[data-testid="shift-status"]');
    await expect(statusIndicator).toBeVisible();
    
    const statusText = await statusIndicator.textContent();
    expect(statusText).toBeTruthy();
    expect(statusText?.toLowerCase()).toMatch(/confirmed|tentative/);
  });

  test('Employee attempts to view another employee shift details', async ({ page }) => {
    // Navigate to schedule
    await page.goto('/schedule');

    // Attempt to access another employee's shift details
    const unauthorizedShiftId = '88888';
    await page.goto(`/api/schedules/details?shiftId=${unauthorizedShiftId}`);

    // Access is denied with appropriate message
    const response = await page.waitForResponse(response => 
      response.url().includes('/api/schedules/details') && response.status() === 403
    ).catch(() => null);

    if (response) {
      expect(response.status()).toBe(403);
    } else {
      // Check for UI error message
      const errorMessage = page.locator('[data-testid="error-message"]');
      await expect(errorMessage).toBeVisible();
      await expect(errorMessage).toContainText(/access.*denied|unauthorized/i);
    }
  });
});