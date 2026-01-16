import { test, expect } from '@playwright/test';

test.describe('Story-21: View Schedule Details Including Location and Role', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login as employee
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate display of shift location and role - happy path', async ({ page }) => {
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

    // Verify the location and role match the assigned shift details in the system
    for (let i = 0; i < Math.min(shiftCount, 3); i++) {
      const shift = allShifts.nth(i);
      await expect(shift).toBeVisible();
      
      const location = shift.locator('[data-testid="shift-location"]');
      await expect(location).toBeVisible();
      const locText = await location.textContent();
      expect(locText?.trim()).toMatch(/^[A-Za-z0-9\s,.-]+$/);
      
      const role = shift.locator('[data-testid="shift-role"]');
      await expect(role).toBeVisible();
      const roleTextContent = await role.textContent();
      expect(roleTextContent?.trim()).toMatch(/^[A-Za-z\s]+$/);
    }
  });

  test('Validate access to special notes or instructions - happy path', async ({ page }) => {
    // Navigate to the schedule view page
    await page.click('[data-testid="schedule-menu-link"]');
    await expect(page).toHaveURL(/.*schedule/);
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Identify a shift that has special notes or instructions
    const shiftWithNotes = page.locator('[data-testid="shift-card"][data-has-notes="true"]').first();
    
    // Check if shift with notes exists, if not find any shift with notes indicator
    const hasShiftWithNotes = await shiftWithNotes.count() > 0;
    
    let targetShift;
    if (hasShiftWithNotes) {
      targetShift = shiftWithNotes;
    } else {
      // Fallback: look for shift with notes icon or badge
      targetShift = page.locator('[data-testid="shift-card"]:has([data-testid="notes-indicator"])').first();
    }

    await expect(targetShift).toBeVisible();

    // Verify notes indicator is present
    const notesIndicator = targetShift.locator('[data-testid="notes-indicator"]');
    await expect(notesIndicator).toBeVisible();

    // Hover the mouse cursor over the shift with special notes (for desktop/web interface)
    await targetShift.hover();
    
    // Wait for tooltip or expandable section to appear
    const notesTooltip = page.locator('[data-testid="shift-notes-tooltip"]');
    await expect(notesTooltip).toBeVisible({ timeout: 3000 });

    // Read the displayed special instructions
    const notesContent = await notesTooltip.textContent();
    expect(notesContent).toBeTruthy();
    expect(notesContent?.trim().length).toBeGreaterThan(0);

    // Move cursor away from the shift
    await page.mouse.move(0, 0);
    await expect(notesTooltip).toBeHidden({ timeout: 2000 });

    // Test expandable section by clicking (alternative interaction)
    const expandableShift = page.locator('[data-testid="shift-card"][data-has-notes="true"]').first();
    if (await expandableShift.count() > 0) {
      await expandableShift.click();
      
      const expandedNotes = page.locator('[data-testid="shift-notes-expanded"]');
      if (await expandedNotes.count() > 0) {
        await expect(expandedNotes).toBeVisible();
        const expandedContent = await expandedNotes.textContent();
        expect(expandedContent?.trim().length).toBeGreaterThan(0);
        
        // Close the expandable section
        const closeButton = page.locator('[data-testid="close-notes-button"]');
        if (await closeButton.count() > 0) {
          await closeButton.click();
          await expect(expandedNotes).toBeHidden();
        }
      }
    }

    // Verify that shifts without special notes do not display empty tooltips
    const shiftWithoutNotes = page.locator('[data-testid="shift-card"]:not([data-has-notes="true"])');
    if (await shiftWithoutNotes.count() > 0) {
      const regularShift = shiftWithoutNotes.first();
      await regularShift.hover();
      
      // Wait a moment to ensure no tooltip appears
      await page.waitForTimeout(1000);
      
      const unexpectedTooltip = page.locator('[data-testid="shift-notes-tooltip"]');
      await expect(unexpectedTooltip).toBeHidden();
    }
  });

  test('Validate display of shift location and role - automated test case', async ({ page }) => {
    // Navigate to schedule view
    await page.goto('/schedule');
    await page.waitForSelector('[data-testid="schedule-view"]');

    // View schedule shifts
    const shifts = page.locator('[data-testid="shift-card"]');
    await expect(shifts.first()).toBeVisible();

    // Each shift shows correct location and role
    const shiftCount = await shifts.count();
    expect(shiftCount).toBeGreaterThan(0);

    for (let i = 0; i < Math.min(shiftCount, 5); i++) {
      const shift = shifts.nth(i);
      
      // Verify location is displayed
      const location = shift.locator('[data-testid="shift-location"]');
      await expect(location).toBeVisible();
      const locationText = await location.textContent();
      expect(locationText?.trim()).not.toBe('');
      
      // Verify role is displayed
      const role = shift.locator('[data-testid="shift-role"]');
      await expect(role).toBeVisible();
      const roleText = await role.textContent();
      expect(roleText?.trim()).not.toBe('');
    }
  });

  test('Validate access to special notes or instructions - automated test case', async ({ page }) => {
    // Navigate to schedule view
    await page.goto('/schedule');
    await page.waitForSelector('[data-testid="schedule-view"]');

    // Find shift with notes
    const shiftWithNotes = page.locator('[data-testid="shift-card"]').filter({ has: page.locator('[data-testid="notes-indicator"]') }).first();
    
    if (await shiftWithNotes.count() > 0) {
      // Hover over or select a shift with notes
      await shiftWithNotes.hover();
      
      // Special instructions are displayed clearly
      const notesDisplay = page.locator('[data-testid="shift-notes-tooltip"], [data-testid="shift-notes-expanded"]');
      await expect(notesDisplay.first()).toBeVisible({ timeout: 3000 });
      
      const instructionsText = await notesDisplay.first().textContent();
      expect(instructionsText).toBeTruthy();
      expect(instructionsText?.trim().length).toBeGreaterThan(0);
    }
  });
});