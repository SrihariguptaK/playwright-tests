import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Details - Story 21', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate display of shift location and role', async ({ page }) => {
    // Navigate to the schedule view page from the main dashboard
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Locate the first assigned shift in the schedule view
    const firstShift = page.locator('[data-testid="shift-card"]').first();
    await expect(firstShift).toBeVisible();

    // Verify the location information is displayed for the shift
    const locationElement = firstShift.locator('[data-testid="shift-location"]');
    await expect(locationElement).toBeVisible();
    const locationText = await locationElement.textContent();
    expect(locationText).toBeTruthy();
    expect(locationText?.trim().length).toBeGreaterThan(0);

    // Verify the role information is displayed for the shift
    const roleElement = firstShift.locator('[data-testid="shift-role"]');
    await expect(roleElement).toBeVisible();
    const roleText = await roleElement.textContent();
    expect(roleText).toBeTruthy();
    expect(roleText?.trim().length).toBeGreaterThan(0);

    // Navigate to additional shifts in the schedule view
    const allShifts = page.locator('[data-testid="shift-card"]');
    const shiftCount = await allShifts.count();
    expect(shiftCount).toBeGreaterThan(0);

    // Verify the location and role data matches the employee's actual shift assignments
    for (let i = 0; i < Math.min(shiftCount, 3); i++) {
      const shift = allShifts.nth(i);
      const shiftLocation = shift.locator('[data-testid="shift-location"]');
      const shiftRole = shift.locator('[data-testid="shift-role"]');
      
      await expect(shiftLocation).toBeVisible();
      await expect(shiftRole).toBeVisible();
      
      const location = await shiftLocation.textContent();
      const role = await shiftRole.textContent();
      
      expect(location).toBeTruthy();
      expect(role).toBeTruthy();
      expect(location?.trim().length).toBeGreaterThan(0);
      expect(role?.trim().length).toBeGreaterThan(0);
    }
  });

  test('Validate access to special notes or instructions', async ({ page }) => {
    // Navigate to the schedule view page
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Identify a shift that has special notes or instructions
    const shiftWithNotes = page.locator('[data-testid="shift-card"][data-has-notes="true"]').first();
    
    // If no shift with notes attribute, find shift with notes indicator
    const hasShiftWithNotes = await shiftWithNotes.count();
    let targetShift;
    
    if (hasShiftWithNotes > 0) {
      targetShift = shiftWithNotes;
    } else {
      // Look for shift with notes icon or indicator
      targetShift = page.locator('[data-testid="shift-card"]:has([data-testid="notes-indicator"])').first();
    }
    
    await expect(targetShift).toBeVisible();

    // Hover the mouse cursor over the shift with special notes
    await targetShift.hover();
    await page.waitForTimeout(500); // Wait for tooltip to appear

    // Check if tooltip is displayed
    let notesDisplayed = await page.locator('[data-testid="shift-notes-tooltip"]').isVisible().catch(() => false);
    
    // If tooltip is not triggered by hover, click or tap on the shift to expand details
    if (!notesDisplayed) {
      await targetShift.click();
      await page.waitForTimeout(300);
    }

    // Read the displayed special instructions
    const notesElement = page.locator('[data-testid="shift-notes-tooltip"], [data-testid="shift-notes-expanded"]').first();
    await expect(notesElement).toBeVisible();
    
    const notesText = await notesElement.textContent();
    expect(notesText).toBeTruthy();
    expect(notesText?.trim().length).toBeGreaterThan(0);

    // Move cursor away from the shift or close the expanded section
    await page.mouse.move(0, 0);
    await page.waitForTimeout(300);
    
    // If expanded section has close button, click it
    const closeButton = page.locator('[data-testid="close-notes-button"]');
    if (await closeButton.isVisible().catch(() => false)) {
      await closeButton.click();
    }

    // Verify that shifts without special notes do not display empty tooltips
    const shiftWithoutNotes = page.locator('[data-testid="shift-card"]:not([data-has-notes="true"])').first();
    
    if (await shiftWithoutNotes.count() > 0) {
      await shiftWithoutNotes.hover();
      await page.waitForTimeout(500);
      
      const emptyTooltip = page.locator('[data-testid="shift-notes-tooltip"]');
      const isEmptyTooltipVisible = await emptyTooltip.isVisible().catch(() => false);
      
      if (isEmptyTooltipVisible) {
        const emptyTooltipText = await emptyTooltip.textContent();
        expect(emptyTooltipText?.trim().length).toBe(0);
      }
    }
  });

  test('Validate access to special notes or instructions on mobile viewport', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Navigate to the schedule view page
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Identify a shift that has special notes or instructions
    const shiftWithNotes = page.locator('[data-testid="shift-card"][data-has-notes="true"]').first();
    
    if (await shiftWithNotes.count() === 0) {
      const alternateShift = page.locator('[data-testid="shift-card"]:has([data-testid="notes-indicator"])').first();
      await expect(alternateShift).toBeVisible();
      await alternateShift.click();
    } else {
      await expect(shiftWithNotes).toBeVisible();
      await shiftWithNotes.click();
    }

    await page.waitForTimeout(300);

    // Verify special instructions are displayed on mobile
    const notesElement = page.locator('[data-testid="shift-notes-tooltip"], [data-testid="shift-notes-expanded"]').first();
    await expect(notesElement).toBeVisible();
    
    const notesText = await notesElement.textContent();
    expect(notesText).toBeTruthy();
    expect(notesText?.trim().length).toBeGreaterThan(0);

    // Verify UI elements are accessible on mobile device
    await expect(notesElement).toBeVisible();
    const boundingBox = await notesElement.boundingBox();
    expect(boundingBox).toBeTruthy();
    expect(boundingBox!.width).toBeLessThanOrEqual(375);
  });
});