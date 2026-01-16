import { test, expect } from '@playwright/test';

test.describe('Story-18: Resource Availability Real-Time View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to application login page
    await page.goto('/login');
  });

  test('Display real-time resource availability - happy path', async ({ page }) => {
    // Login as scheduler with appropriate permissions
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'SchedulerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 1: Navigate to the resource availability dashboard from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="resource-availability-menu-item"]');
    await expect(page).toHaveURL(/.*resources\/availability/);
    await expect(page.locator('[data-testid="availability-dashboard"]')).toBeVisible();

    // Step 2: Verify that the displayed availability data matches the current state of resources
    const availabilityData = await page.locator('[data-testid="resource-availability-list"]');
    await expect(availabilityData).toBeVisible();
    const resourceCount = await page.locator('[data-testid="resource-item"]').count();
    expect(resourceCount).toBeGreaterThan(0);

    // Step 3: Select a specific resource from the availability dashboard
    const firstResource = page.locator('[data-testid="resource-item"]').first();
    const resourceName = await firstResource.locator('[data-testid="resource-name"]').textContent();
    await firstResource.click();
    await expect(page.locator('[data-testid="resource-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="selected-resource-name"]')).toContainText(resourceName || '');

    // Step 4: Create a new appointment for the selected resource in a previously available time slot
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();
    await page.fill('[data-testid="appointment-title"]', 'Test Appointment');
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    
    // Step 5: Observe the resource availability dashboard and note the timestamp
    const timestampBeforeCreate = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-success-message"]')).toBeVisible();
    
    // Verify availability updates within 5 seconds
    await page.waitForTimeout(5000);
    const timestampAfterCreate = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(timestampAfterCreate).not.toBe(timestampBeforeCreate);
    
    // Verify the time slot is now marked as unavailable
    const timeSlot = page.locator('[data-testid="time-slot-10-00"]');
    await expect(timeSlot).toHaveAttribute('data-status', 'unavailable');

    // Step 6: Modify an existing appointment by changing its time or duration
    await page.click('[data-testid="appointments-list-button"]');
    await page.locator('[data-testid="appointment-item"]').filter({ hasText: 'Test Appointment' }).click();
    await page.click('[data-testid="edit-appointment-button"]');
    await page.fill('[data-testid="appointment-end-time"]', '12:00');
    
    // Step 7: Monitor the resource availability dashboard for real-time updates
    const timestampBeforeModify = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-updated-message"]')).toBeVisible();
    
    // Wait for real-time update (within 5 seconds)
    await page.waitForTimeout(5000);
    const timestampAfterModify = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(timestampAfterModify).not.toBe(timestampBeforeModify);

    // Step 8: Attempt to schedule another appointment in a time slot that would create a conflict
    await page.click('[data-testid="resource-availability-menu-item"]');
    await firstResource.click();
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-title"]', 'Conflicting Appointment');
    await page.fill('[data-testid="appointment-date"]', '2024-03-15');
    await page.fill('[data-testid="appointment-start-time"]', '10:30');
    await page.fill('[data-testid="appointment-end-time"]', '11:30');
    
    // Step 9: Verify that conflict indicators are visible and accurately represent the scheduling conflict
    await page.click('[data-testid="check-availability-button"]');
    await expect(page.locator('[data-testid="conflict-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('conflict');
    const conflictDetails = page.locator('[data-testid="conflict-details"]');
    await expect(conflictDetails).toBeVisible();
    await expect(conflictDetails).toContainText('Test Appointment');
  });

  test('Ensure secure access to resource availability data - error case', async ({ page }) => {
    // Step 1: Log out from any existing session to ensure a clean test state
    await page.goto('/logout');
    await expect(page).toHaveURL(/.*login/);

    // Step 2: Log in with a user account that does not have permissions
    await page.fill('[data-testid="username-input"]', 'guest@example.com');
    await page.fill('[data-testid="password-input"]', 'GuestPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 3: Attempt to navigate to the resource availability dashboard through the application menu
    await page.click('[data-testid="main-menu"]');
    const availabilityMenuItem = page.locator('[data-testid="resource-availability-menu-item"]');
    
    // Verify menu item is either hidden or disabled for unauthorized users
    const isVisible = await availabilityMenuItem.isVisible().catch(() => false);
    if (isVisible) {
      const isDisabled = await availabilityMenuItem.isDisabled();
      expect(isDisabled).toBe(true);
    }

    // Step 4: Attempt to directly access the resource availability dashboard using the direct URL
    await page.goto('/resources/availability');
    
    // Verify access is denied
    const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
    const unauthorizedMessage = page.locator('[data-testid="unauthorized-message"]');
    const errorMessage = page.locator('text=/access denied|unauthorized|permission/i');
    
    await expect(
      accessDeniedMessage.or(unauthorizedMessage).or(errorMessage)
    ).toBeVisible({ timeout: 5000 });

    // Step 5: Verify that no resource availability data is displayed
    const availabilityDashboard = page.locator('[data-testid="availability-dashboard"]');
    await expect(availabilityDashboard).not.toBeVisible();
    const resourceList = page.locator('[data-testid="resource-availability-list"]');
    await expect(resourceList).not.toBeVisible();

    // Step 6: Log out from the unauthorized user account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 7: Log in with a user account that has valid permissions
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'SchedulerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Step 8: Navigate to the resource availability dashboard from the main menu
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="resource-availability-menu-item"]');
    await expect(page).toHaveURL(/.*resources\/availability/);

    // Step 9: Access the resource availability dashboard
    await expect(page.locator('[data-testid="availability-dashboard"]')).toBeVisible();

    // Step 10: Verify that all expected features and data are accessible
    await expect(page.locator('[data-testid="calendar-view-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="timeline-view-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="resource-availability-list"]')).toBeVisible();
    
    // Verify calendar view is accessible
    await page.click('[data-testid="calendar-view-button"]');
    await expect(page.locator('[data-testid="calendar-view-container"]')).toBeVisible();
    
    // Verify timeline view is accessible
    await page.click('[data-testid="timeline-view-button"]');
    await expect(page.locator('[data-testid="timeline-view-container"]')).toBeVisible();
    
    // Verify resource details are accessible
    const resourceItem = page.locator('[data-testid="resource-item"]').first();
    await resourceItem.click();
    await expect(page.locator('[data-testid="resource-details-panel"]')).toBeVisible();
    
    // Verify conflict indicators feature is accessible
    await expect(page.locator('[data-testid="conflict-detection-toggle"]')).toBeVisible();
  });
});