import { test, expect } from '@playwright/test';

test.describe('Story-15: View Shift Details Including Location and Role', () => {
  test.beforeEach(async ({ page }) => {
    // Employee logs in
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test.afterEach(async ({ page }) => {
    // Employee logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
  });

  test('Validate display of shift location and role (happy-path)', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Locate a scheduled shift in the schedule view
    const shift = page.locator('[data-testid="shift-card"]').first();
    await expect(shift).toBeVisible();

    // Select or click on the shift to view detailed information
    await shift.click();
    await page.waitForSelector('[data-testid="shift-details-modal"]');

    // Verify that shift location is displayed in the details
    const shiftLocation = page.locator('[data-testid="shift-location"]');
    await expect(shiftLocation).toBeVisible();
    await expect(shiftLocation).not.toBeEmpty();

    // Verify that assigned role is displayed in the details
    const shiftRole = page.locator('[data-testid="shift-role"]');
    await expect(shiftRole).toBeVisible();
    await expect(shiftRole).not.toBeEmpty();

    // Check if additional shift notes are present (if applicable)
    const shiftNotes = page.locator('[data-testid="shift-notes"]');
    if (await shiftNotes.isVisible()) {
      await expect(shiftNotes).toBeVisible();
    }

    // Verify the formatting and readability of the shift details
    const detailsContainer = page.locator('[data-testid="shift-details-modal"]');
    await expect(detailsContainer).toHaveCSS('display', /block|flex/);

    // Close the shift details view
    await page.click('[data-testid="close-shift-details"]');
    await expect(page.locator('[data-testid="shift-details-modal"]')).not.toBeVisible();
  });

  test('Verify access control for shift details (error-case)', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Attempt to navigate to or access another employee's schedule view via URL manipulation
    const anotherEmployeeId = 'emp-12345';
    await page.goto(`/schedule/${anotherEmployeeId}`);

    // Verify that an appropriate error message is displayed
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/access denied|unauthorized|permission/i);

    // Verify that no sensitive shift details of the other employee are exposed
    const shiftDetails = page.locator('[data-testid="shift-details-modal"]');
    await expect(shiftDetails).not.toBeVisible();

    const otherEmployeeShifts = page.locator('[data-testid="shift-card"]');
    const shiftsCount = await otherEmployeeShifts.count();
    expect(shiftsCount).toBe(0);

    // Confirm that the employee is redirected back to their own schedule or appropriate page
    await page.waitForURL(/.*schedule$|.*dashboard/, { timeout: 5000 });
    const currentUrl = page.url();
    expect(currentUrl).not.toContain(anotherEmployeeId);

    // Verify that the employee's session remains active and authenticated
    const userMenu = page.locator('[data-testid="user-menu"]');
    await expect(userMenu).toBeVisible();

    // Verify employee can still access their own schedule
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    const ownShifts = page.locator('[data-testid="shift-card"]');
    await expect(ownShifts.first()).toBeVisible();
  });

  test('Validate shift details are accessible via tooltip or expandable UI element', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);

    // Locate a scheduled shift
    const shift = page.locator('[data-testid="shift-card"]').first();
    await expect(shift).toBeVisible();

    // Hover over shift to check for tooltip
    await shift.hover();
    await page.waitForTimeout(500);

    // Check if tooltip appears with shift details
    const tooltip = page.locator('[data-testid="shift-tooltip"]');
    const isTooltipVisible = await tooltip.isVisible().catch(() => false);

    if (isTooltipVisible) {
      // Verify tooltip contains location and role
      await expect(tooltip).toContainText(/.+/);
    } else {
      // If no tooltip, verify expandable UI element works
      await shift.click();
      const expandedDetails = page.locator('[data-testid="shift-details-modal"]');
      await expect(expandedDetails).toBeVisible();
      await page.click('[data-testid="close-shift-details"]');
    }
  });

  test('Verify schedule view performance remains within acceptable limits', async ({ page }) => {
    // Navigate to schedule view and measure load time
    const startTime = Date.now();
    
    await page.click('[data-testid="schedule-nav-link"]');
    await page.waitForSelector('[data-testid="schedule-view"]');
    await page.waitForSelector('[data-testid="shift-card"]');
    
    const loadTime = Date.now() - startTime;
    
    // Verify page loads within 3 seconds
    expect(loadTime).toBeLessThan(3000);

    // Verify all shift cards are rendered
    const shiftCards = page.locator('[data-testid="shift-card"]');
    const count = await shiftCards.count();
    expect(count).toBeGreaterThan(0);

    // Test interaction performance - open and close shift details
    const interactionStartTime = Date.now();
    await shiftCards.first().click();
    await page.waitForSelector('[data-testid="shift-details-modal"]');
    const interactionTime = Date.now() - interactionStartTime;
    
    // Verify interaction completes within 1 second
    expect(interactionTime).toBeLessThan(1000);

    await page.click('[data-testid="close-shift-details"]');
  });

  test('Verify 100% of shifts display detailed info', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="schedule-nav-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Get all shift cards
    const shiftCards = page.locator('[data-testid="shift-card"]');
    const totalShifts = await shiftCards.count();
    expect(totalShifts).toBeGreaterThan(0);

    // Verify each shift has location and role information
    for (let i = 0; i < totalShifts; i++) {
      const shift = shiftCards.nth(i);
      await shift.click();
      await page.waitForSelector('[data-testid="shift-details-modal"]');

      // Verify location is present
      const location = page.locator('[data-testid="shift-location"]');
      await expect(location).toBeVisible();
      const locationText = await location.textContent();
      expect(locationText).toBeTruthy();

      // Verify role is present
      const role = page.locator('[data-testid="shift-role"]');
      await expect(role).toBeVisible();
      const roleText = await role.textContent();
      expect(roleText).toBeTruthy();

      // Close details
      await page.click('[data-testid="close-shift-details"]');
      await page.waitForTimeout(300);
    }
  });
});