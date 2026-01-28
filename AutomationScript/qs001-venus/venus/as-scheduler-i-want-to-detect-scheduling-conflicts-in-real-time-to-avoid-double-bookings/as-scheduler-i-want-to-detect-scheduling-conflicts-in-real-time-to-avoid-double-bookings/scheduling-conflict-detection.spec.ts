import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling interface
    await page.goto('/scheduling');
    // Wait for the page to load
    await page.waitForLoadState('networkidle');
  });

  test('Validate conflict detection for overlapping events', async ({ page }) => {
    // Step 1: Schedule first event from 10:00 to 11:00
    await page.click('[data-testid="create-new-event-button"]');
    await page.fill('[data-testid="event-title-input"]', 'Meeting A');
    await page.fill('[data-testid="event-start-time-input"]', '10:00');
    await page.fill('[data-testid="event-end-time-input"]', '11:00');
    await page.click('[data-testid="schedule-event-button"]');
    
    // Verify the first event is scheduled successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 3000 });
    await page.reload();
    await page.waitForLoadState('networkidle');
    await expect(page.locator('text=Meeting A')).toBeVisible();
    
    // Step 2: Schedule another event from 10:30 to 11:30 (overlapping)
    await page.click('[data-testid="create-new-event-button"]');
    await page.fill('[data-testid="event-title-input"]', 'Meeting B');
    await page.fill('[data-testid="event-start-time-input"]', '10:30');
    await page.fill('[data-testid="event-end-time-input"]', '11:30');
    await page.click('[data-testid="schedule-event-button"]');
    
    // Step 3: Check for conflict alert notification
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible({ timeout: 2000 });
    await expect(conflictAlert).toContainText('conflict', { ignoreCase: true });
    
    // Verify conflict details are displayed
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Meeting A');
    
    // Verify that Meeting B was not added to the calendar
    await page.click('[data-testid="close-conflict-alert"]');
    await page.reload();
    await page.waitForLoadState('networkidle');
    await expect(page.locator('text=Meeting A')).toBeVisible();
    await expect(page.locator('text=Meeting B')).not.toBeVisible();
  });

  test('Ensure no conflict detection for non-overlapping events', async ({ page }) => {
    // Step 1: Schedule first event from 10:00 to 11:00
    await page.click('[data-testid="create-new-event-button"]');
    await page.fill('[data-testid="event-title-input"]', 'Meeting A');
    await page.fill('[data-testid="event-start-time-input"]', '10:00');
    await page.fill('[data-testid="event-end-time-input"]', '11:00');
    await page.click('[data-testid="schedule-event-button"]');
    
    // Verify the first event is saved by checking the calendar view
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="calendar-view"]')).toContainText('Meeting A');
    
    // Step 2: Schedule second event from 11:00 to 12:00 (non-overlapping)
    await page.click('[data-testid="create-new-event-button"]');
    await page.fill('[data-testid="event-title-input"]', 'Meeting B');
    await page.fill('[data-testid="event-start-time-input"]', '11:00');
    await page.fill('[data-testid="event-end-time-input"]', '12:00');
    await page.click('[data-testid="schedule-event-button"]');
    
    // Verify that Meeting B is scheduled successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 3000 });
    
    // Step 3: Check for any conflict alert notifications
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).not.toBeVisible();
    
    // Check notification panel for any conflict alerts
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    if (await notificationPanel.isVisible()) {
      await expect(notificationPanel).not.toContainText('conflict', { ignoreCase: true });
    }
    
    // Verify both events are visible in the calendar view
    await expect(page.locator('[data-testid="calendar-view"]')).toContainText('Meeting A');
    await expect(page.locator('[data-testid="calendar-view"]')).toContainText('Meeting B');
    
    // Check the event list to confirm both events are saved
    const eventList = page.locator('[data-testid="event-list"]');
    await expect(eventList.locator('text=Meeting A')).toBeVisible();
    await expect(eventList.locator('text=Meeting B')).toBeVisible();
    
    // Verify event count is 2
    const eventItems = page.locator('[data-testid="event-item"]');
    await expect(eventItems).toHaveCount(2);
  });
});