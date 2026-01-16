import { test, expect } from '@playwright/test';

test.describe('Participant Availability Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduling');
    // Wait for the page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate participant availability on scheduling (happy-path)', async ({ page }) => {
    // Navigate to the event creation page in the scheduling interface
    await page.click('[data-testid="create-event-button"]');
    await expect(page.locator('[data-testid="event-creation-form"]')).toBeVisible();

    // Enter event title 'Project Review Meeting'
    await page.fill('[data-testid="event-title-input"]', 'Project Review Meeting');
    await expect(page.locator('[data-testid="event-title-input"]')).toHaveValue('Project Review Meeting');

    // Select date as tomorrow at 2:00 PM
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];
    
    await page.fill('[data-testid="event-date-input"]', tomorrowFormatted);
    await page.fill('[data-testid="event-time-input"]', '14:00');
    
    // Set duration of 1 hour
    await page.selectOption('[data-testid="event-duration-select"]', '60');
    await expect(page.locator('[data-testid="event-duration-select"]')).toHaveValue('60');

    // Click on the participant selection field
    await page.click('[data-testid="participant-selection-field"]');
    await expect(page.locator('[data-testid="participant-dropdown"]')).toBeVisible();

    // Select 3 participants from the dropdown list
    await page.click('[data-testid="participant-option-1"]');
    await page.click('[data-testid="participant-option-2"]');
    await page.click('[data-testid="participant-option-3"]');

    // Observe the system behavior as it retrieves participant availability data
    await page.waitForSelector('[data-testid="availability-loading-indicator"]', { state: 'visible' });
    await page.waitForSelector('[data-testid="availability-loading-indicator"]', { state: 'hidden', timeout: 3000 });

    // Review the availability status displayed for each participant
    await expect(page.locator('[data-testid="participant-availability-status"]')).toHaveCount(3);
    const availabilityStatuses = await page.locator('[data-testid="participant-availability-status"]').all();
    
    for (const status of availabilityStatuses) {
      await expect(status).toBeVisible();
    }

    // Verify that conflict alerts are prominently displayed in the scheduling UI
    const conflictAlert = page.locator('[data-testid="conflict-alert"]');
    await expect(conflictAlert).toBeVisible();
    await expect(conflictAlert).toContainText('conflict', { ignoreCase: true });

    // Click on the conflict details to view more information about the participant's unavailability
    await page.click('[data-testid="conflict-details-button"]');
    await expect(page.locator('[data-testid="conflict-details-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-participant-info"]')).toBeVisible();
    
    // Close conflict details modal
    await page.click('[data-testid="close-conflict-details"]');
    await expect(page.locator('[data-testid="conflict-details-modal"]')).not.toBeVisible();

    // Adjust the event time by changing the start time to 4:00 PM
    await page.fill('[data-testid="event-time-input"]', '16:00');
    await expect(page.locator('[data-testid="event-time-input"]')).toHaveValue('16:00');

    // Observe the system as it automatically revalidates participant availability for the new time slot
    await page.waitForSelector('[data-testid="availability-loading-indicator"]', { state: 'visible' });
    await page.waitForSelector('[data-testid="availability-loading-indicator"]', { state: 'hidden', timeout: 3000 });

    // Review the updated availability status for all participants
    const updatedStatuses = await page.locator('[data-testid="participant-availability-status"]').all();
    
    for (const status of updatedStatuses) {
      await expect(status).toBeVisible();
      // Verify all participants are now available (no conflicts)
      const statusText = await status.textContent();
      expect(statusText?.toLowerCase()).toContain('available');
    }

    // Verify conflict alert is no longer displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();

    // Click the 'Create Event' or 'Schedule' button to finalize the event
    await page.click('[data-testid="create-event-submit-button"]');

    // Verify successful event creation
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Event created successfully', { ignoreCase: true });
  });

  test('Validate participant availability retrieval on participant selection', async ({ page }) => {
    // Navigate to event creation page
    await page.click('[data-testid="create-event-button"]');
    
    // Fill basic event details
    await page.fill('[data-testid="event-title-input"]', 'Team Sync');
    
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];
    
    await page.fill('[data-testid="event-date-input"]', tomorrowFormatted);
    await page.fill('[data-testid="event-time-input"]', '10:00');
    
    // Action: Scheduler selects participants for event
    await page.click('[data-testid="participant-selection-field"]');
    await page.click('[data-testid="participant-option-1"]');
    await page.click('[data-testid="participant-option-2"]');
    
    // Expected Result: System retrieves availability data
    await expect(page.locator('[data-testid="availability-loading-indicator"]')).toBeVisible();
    
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="availability-loading-indicator"]', { state: 'hidden', timeout: 3000 });
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Verify availability check completes within 2 seconds
    expect(loadTime).toBeLessThan(2000);
    
    // Verify availability data is displayed
    await expect(page.locator('[data-testid="participant-availability-status"]').first()).toBeVisible();
  });

  test('System detects and displays participant conflicts', async ({ page }) => {
    // Navigate to event creation page
    await page.click('[data-testid="create-event-button"]');
    
    // Fill event details with conflicting time
    await page.fill('[data-testid="event-title-input"]', 'Conflict Test Meeting');
    
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];
    
    await page.fill('[data-testid="event-date-input"]', tomorrowFormatted);
    await page.fill('[data-testid="event-time-input"]', '14:00');
    await page.selectOption('[data-testid="event-duration-select"]', '60');
    
    // Select participants
    await page.click('[data-testid="participant-selection-field"]');
    await page.click('[data-testid="participant-option-1"]');
    await page.click('[data-testid="participant-option-3"]');
    
    // Wait for availability check
    await page.waitForSelector('[data-testid="availability-loading-indicator"]', { state: 'hidden', timeout: 3000 });
    
    // Action: System detects participant conflicts
    // Expected Result: Conflict alerts are displayed
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('conflict', { ignoreCase: true });
    
    // Verify conflict details are available
    const conflictCount = await page.locator('[data-testid="conflict-indicator"]').count();
    expect(conflictCount).toBeGreaterThan(0);
  });

  test('Scheduler adjusts event time and system revalidates availability', async ({ page }) => {
    // Navigate to event creation page
    await page.click('[data-testid="create-event-button"]');
    
    // Fill initial event details
    await page.fill('[data-testid="event-title-input"]', 'Revalidation Test');
    
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowFormatted = tomorrow.toISOString().split('T')[0];
    
    await page.fill('[data-testid="event-date-input"]', tomorrowFormatted);
    await page.fill('[data-testid="event-time-input"]', '14:00');
    await page.selectOption('[data-testid="event-duration-select"]', '60');
    
    // Select participants
    await page.click('[data-testid="participant-selection-field"]');
    await page.click('[data-testid="participant-option-1"]');
    await page.click('[data-testid="participant-option-2"]');
    
    // Wait for initial availability check
    await page.waitForSelector('[data-testid="availability-loading-indicator"]', { state: 'hidden', timeout: 3000 });
    
    // Action: Scheduler adjusts event time and resubmits
    await page.fill('[data-testid="event-time-input"]', '16:00');
    
    // Expected Result: System revalidates and confirms availability
    await expect(page.locator('[data-testid="availability-loading-indicator"]')).toBeVisible();
    
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="availability-loading-indicator"]', { state: 'hidden', timeout: 3000 });
    const endTime = Date.now();
    const revalidationTime = endTime - startTime;
    
    // Verify revalidation completes within 2 seconds
    expect(revalidationTime).toBeLessThan(2000);
    
    // Verify updated availability status
    await expect(page.locator('[data-testid="participant-availability-status"]').first()).toBeVisible();
    
    // Verify no conflicts after time adjustment
    await expect(page.locator('[data-testid="conflict-alert"]')).not.toBeVisible();
  });
});