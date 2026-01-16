import { test, expect } from '@playwright/test';

test.describe('Story-20: Multiple Calendar Format Support for Conflict Detection', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/scheduler/dashboard`);
    await expect(page).toHaveTitle(/Scheduler Dashboard/);
  });

  test('Parse and detect conflicts from iCal format (happy-path)', async ({ page }) => {
    // Navigate to calendar import section and select 'Import Calendar' option
    await page.click('[data-testid="calendar-import-section"]');
    await page.click('[data-testid="import-calendar-button"]');
    await expect(page.locator('[data-testid="import-calendar-modal"]')).toBeVisible();

    // Select iCal format option and browse to upload the prepared .ics test file
    await page.click('[data-testid="format-selector"]');
    await page.click('[data-testid="format-option-ical"]');
    
    const fileInput = page.locator('input[type="file"][data-testid="calendar-file-upload"]');
    await fileInput.setInputFiles('test-data/test-calendar.ics');
    await expect(page.locator('[data-testid="file-name-display"]')).toContainText('test-calendar.ics');

    // Click 'Import' button to upload and process the iCal file
    await page.click('[data-testid="import-submit-button"]');
    await expect(page.locator('[data-testid="import-progress-indicator"]')).toBeVisible();

    // Verify parsing completion and review import summary
    await expect(page.locator('[data-testid="import-success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="import-summary"]')).toBeVisible();
    const importedCount = await page.locator('[data-testid="imported-events-count"]').textContent();
    expect(parseInt(importedCount || '0')).toBeGreaterThan(0);

    // Navigate to calendar view and verify imported iCal events are displayed
    await page.click('[data-testid="close-import-modal"]');
    await page.click('[data-testid="calendar-view-link"]');
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    const iCalEvent = page.locator('[data-testid="calendar-event"][data-format="ical"]').first();
    await expect(iCalEvent).toBeVisible();
    const iCalEventTime = await iCalEvent.getAttribute('data-event-time');

    // Create a new appointment that conflicts with an imported iCal event (same date/time)
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();
    
    await page.fill('[data-testid="appointment-title"]', 'Conflicting Test Appointment');
    await page.fill('[data-testid="appointment-datetime"]', iCalEventTime || '');
    await page.fill('[data-testid="appointment-duration"]', '60');

    // Attempt to save the conflicting appointment
    await page.click('[data-testid="save-appointment-button"]');

    // Review conflict details showing both the new appointment and the conflicting iCal event
    await expect(page.locator('[data-testid="conflict-detection-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('conflict');
    
    const conflictDetails = page.locator('[data-testid="conflict-details-panel"]');
    await expect(conflictDetails).toBeVisible();
    await expect(conflictDetails.locator('[data-testid="conflicting-event-1"]')).toContainText('Conflicting Test Appointment');
    await expect(conflictDetails.locator('[data-testid="conflicting-event-2"]')).toHaveAttribute('data-format', 'ical');

    // Verify format-specific metadata is preserved by viewing iCal event properties
    await page.click('[data-testid="view-ical-event-details"]');
    await expect(page.locator('[data-testid="event-metadata-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="event-format-type"]')).toContainText('iCal');
    await expect(page.locator('[data-testid="event-metadata-uid"]')).toBeVisible();
    await expect(page.locator('[data-testid="event-metadata-dtstamp"]')).toBeVisible();
  });

  test('Parse and detect conflicts from Google Calendar format (happy-path)', async ({ page }) => {
    // Navigate to calendar sync section and select 'Connect Google Calendar' option
    await page.click('[data-testid="calendar-sync-section"]');
    await page.click('[data-testid="connect-google-calendar-button"]');
    await expect(page.locator('[data-testid="google-calendar-connection-modal"]')).toBeVisible();

    // Click 'Authorize' button to initiate OAuth authentication flow
    const [popup] = await Promise.all([
      page.waitForEvent('popup'),
      page.click('[data-testid="authorize-google-button"]')
    ]);

    // Grant calendar read permissions and complete OAuth authorization
    await popup.waitForLoadState();
    await popup.fill('[data-testid="oauth-email"]', 'test.scheduler@example.com');
    await popup.fill('[data-testid="oauth-password"]', 'TestPassword123!');
    await popup.click('[data-testid="oauth-signin-button"]');
    await popup.click('[data-testid="oauth-grant-permissions"]');
    await popup.waitForEvent('close', { timeout: 10000 });

    // Click 'Sync Now' button to retrieve Google Calendar events via API
    await expect(page.locator('[data-testid="oauth-success-indicator"]')).toBeVisible({ timeout: 5000 });
    await page.click('[data-testid="sync-now-button"]');

    // Monitor sync process and wait for completion
    await expect(page.locator('[data-testid="sync-progress-indicator"]')).toBeVisible();
    await expect(page.locator('[data-testid="sync-status"]')).toContainText('Syncing');
    await expect(page.locator('[data-testid="sync-complete-message"]')).toBeVisible({ timeout: 15000 });
    
    const syncedCount = await page.locator('[data-testid="synced-events-count"]').textContent();
    expect(parseInt(syncedCount || '0')).toBeGreaterThan(0);

    // Navigate to calendar view and verify Google Calendar events are displayed
    await page.click('[data-testid="close-sync-modal"]');
    await page.click('[data-testid="calendar-view-link"]');
    await expect(page.locator('[data-testid="calendar-grid"]')).toBeVisible();
    
    const googleEvent = page.locator('[data-testid="calendar-event"][data-format="google"]').first();
    await expect(googleEvent).toBeVisible();

    // Verify Google Calendar-specific metadata is preserved by viewing event details
    await googleEvent.click();
    await expect(page.locator('[data-testid="event-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="event-format-type"]')).toContainText('Google Calendar');
    await expect(page.locator('[data-testid="event-metadata-google-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="event-metadata-google-etag"]')).toBeVisible();
    
    const googleEventTime = await googleEvent.getAttribute('data-event-time');
    const eventCountBefore = await page.locator('[data-testid="calendar-event"]').count();
    await page.click('[data-testid="close-event-details"]');

    // Create a new appointment with date/time that conflicts with a synced Google Calendar event
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();
    
    await page.fill('[data-testid="appointment-title"]', 'New Conflicting Appointment');
    await page.fill('[data-testid="appointment-datetime"]', googleEventTime || '');
    await page.fill('[data-testid="appointment-duration"]', '90');
    await page.fill('[data-testid="appointment-location"]', 'Conference Room B');

    // Attempt to save the conflicting appointment
    await page.click('[data-testid="save-appointment-button"]');

    // Review conflict resolution options and verify accuracy of conflict detection
    await expect(page.locator('[data-testid="conflict-detection-alert"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="conflict-message"]')).toContainText('conflict detected');
    
    const conflictPanel = page.locator('[data-testid="conflict-resolution-panel"]');
    await expect(conflictPanel).toBeVisible();
    await expect(conflictPanel.locator('[data-testid="new-appointment-details"]')).toContainText('New Conflicting Appointment');
    await expect(conflictPanel.locator('[data-testid="existing-event-details"]')).toHaveAttribute('data-format', 'google');
    
    const resolutionOptions = conflictPanel.locator('[data-testid="resolution-option"]');
    await expect(resolutionOptions).toHaveCount(3);
    await expect(resolutionOptions.nth(0)).toContainText('Override');
    await expect(resolutionOptions.nth(1)).toContainText('Reschedule');
    await expect(resolutionOptions.nth(2)).toContainText('Cancel');

    // Verify no data loss by comparing event count before and after sync
    await page.click('[data-testid="cancel-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).not.toBeVisible();
    
    const eventCountAfter = await page.locator('[data-testid="calendar-event"]').count();
    expect(eventCountAfter).toBe(eventCountBefore);
    
    // Verify all Google Calendar events are still present
    const googleEventsAfter = await page.locator('[data-testid="calendar-event"][data-format="google"]').count();
    expect(googleEventsAfter).toBe(parseInt(syncedCount || '0'));
  });
});