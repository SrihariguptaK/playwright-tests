import { test, expect } from '@playwright/test';

test.describe('View Detailed Conflict Information', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduler dashboard
    await page.goto('/scheduler/dashboard');
    // Wait for the page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('View detailed conflict information (happy-path)', async ({ page }) => {
    // Step 1: User receives a conflict alert notification and clicks on it to open conflict details
    const conflictAlert = page.getByTestId('conflict-alert-notification');
    await expect(conflictAlert).toBeVisible();
    
    const startTime = Date.now();
    await conflictAlert.click();
    
    // Expected Result: Conflict details load within 2 seconds
    await page.waitForSelector('[data-testid="conflict-details-view"]', { timeout: 2000 });
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);
    
    const conflictDetailsView = page.getByTestId('conflict-details-view');
    await expect(conflictDetailsView).toBeVisible();

    // Step 2: User reviews the displayed conflict information including event names, dates, times, and descriptions
    const eventNames = page.getByTestId('conflict-event-names');
    await expect(eventNames).toBeVisible();
    await expect(eventNames).not.toBeEmpty();
    
    const eventDates = page.getByTestId('conflict-event-dates');
    await expect(eventDates).toBeVisible();
    await expect(eventDates).not.toBeEmpty();
    
    const eventTimes = page.getByTestId('conflict-event-times');
    await expect(eventTimes).toBeVisible();
    await expect(eventTimes).not.toBeEmpty();
    
    const eventDescriptions = page.getByTestId('conflict-event-descriptions');
    await expect(eventDescriptions).toBeVisible();
    
    // Expected Result: All relevant conflict information is displayed clearly
    const conflictInfo = page.getByTestId('conflict-information-section');
    await expect(conflictInfo).toBeVisible();

    // Step 3: User reviews the resource allocation information shown in the conflict details
    const resourceAllocation = page.getByTestId('conflict-resource-allocation');
    await expect(resourceAllocation).toBeVisible();
    
    const resourceDetails = page.getByTestId('resource-details');
    await expect(resourceDetails).toBeVisible();
    await expect(resourceDetails).not.toBeEmpty();
    
    // Verify resource names and allocation status are displayed
    const resourceNames = page.locator('[data-testid="resource-name"]');
    await expect(resourceNames.first()).toBeVisible();
    const resourceCount = await resourceNames.count();
    expect(resourceCount).toBeGreaterThan(0);

    // Step 4: User reviews the participant information for all conflicting events
    const participantSection = page.getByTestId('conflict-participants-section');
    await expect(participantSection).toBeVisible();
    
    const participantList = page.getByTestId('participant-list');
    await expect(participantList).toBeVisible();
    
    const participants = page.locator('[data-testid="participant-item"]');
    await expect(participants.first()).toBeVisible();
    const participantCount = await participants.count();
    expect(participantCount).toBeGreaterThan(0);
    
    // Verify participant details are complete
    const participantNames = page.locator('[data-testid="participant-name"]');
    await expect(participantNames.first()).not.toBeEmpty();

    // Step 5: User examines the suggested resolution options provided by the system
    const resolutionOptions = page.getByTestId('suggested-resolution-options');
    await expect(resolutionOptions).toBeVisible();
    
    const resolutionList = page.locator('[data-testid="resolution-option"]');
    await expect(resolutionList.first()).toBeVisible();
    const resolutionCount = await resolutionList.count();
    expect(resolutionCount).toBeGreaterThan(0);
    
    // Verify resolution options have descriptions
    const resolutionDescriptions = page.locator('[data-testid="resolution-description"]');
    await expect(resolutionDescriptions.first()).toBeVisible();

    // Step 6: User clicks on the navigation link to view the first conflicting event
    const firstEventLink = page.getByTestId('conflicting-event-link-1');
    await expect(firstEventLink).toBeVisible();
    await firstEventLink.click();
    
    // Expected Result: User is taken to event scheduling page
    await page.waitForURL(/.*\/events\/.*/);
    const eventSchedulingPage = page.getByTestId('event-scheduling-page');
    await expect(eventSchedulingPage).toBeVisible();
    
    const eventDetailsSection = page.getByTestId('event-details-section');
    await expect(eventDetailsSection).toBeVisible();

    // Step 7: User navigates back to conflict details and clicks on the second conflicting event link
    await page.goBack();
    await page.waitForSelector('[data-testid="conflict-details-view"]');
    await expect(conflictDetailsView).toBeVisible();
    
    const secondEventLink = page.getByTestId('conflicting-event-link-2');
    await expect(secondEventLink).toBeVisible();
    await secondEventLink.click();
    
    // Expected Result: User is taken to the second event scheduling page
    await page.waitForURL(/.*\/events\/.*/);
    await expect(eventSchedulingPage).toBeVisible();
    await expect(eventDetailsSection).toBeVisible();
  });

  test('Verify conflict details load within 2 seconds', async ({ page }) => {
    // User opens conflict details from alert
    const conflictAlert = page.getByTestId('conflict-alert-notification');
    await expect(conflictAlert).toBeVisible();
    
    const startTime = Date.now();
    await conflictAlert.click();
    
    // Expected Result: Conflict details load within 2 seconds
    await page.waitForSelector('[data-testid="conflict-details-view"]', { timeout: 2000 });
    const loadTime = Date.now() - startTime;
    
    expect(loadTime).toBeLessThan(2000);
    
    const conflictDetailsView = page.getByTestId('conflict-details-view');
    await expect(conflictDetailsView).toBeVisible();
  });

  test('Verify all relevant conflict information is displayed', async ({ page }) => {
    // Open conflict details
    const conflictAlert = page.getByTestId('conflict-alert-notification');
    await conflictAlert.click();
    await page.waitForSelector('[data-testid="conflict-details-view"]');
    
    // User reviews event, resource, and participant details
    const eventDetails = page.getByTestId('conflict-event-details');
    await expect(eventDetails).toBeVisible();
    
    const resourceDetails = page.getByTestId('conflict-resource-allocation');
    await expect(resourceDetails).toBeVisible();
    
    const participantDetails = page.getByTestId('conflict-participants-section');
    await expect(participantDetails).toBeVisible();
    
    // Expected Result: All relevant conflict information is displayed clearly
    const conflictInformation = page.getByTestId('conflict-information-section');
    await expect(conflictInformation).toBeVisible();
    
    // Verify completeness of information
    await expect(page.getByTestId('conflict-event-names')).toBeVisible();
    await expect(page.getByTestId('conflict-event-dates')).toBeVisible();
    await expect(page.getByTestId('conflict-event-times')).toBeVisible();
    await expect(page.getByTestId('resource-details')).toBeVisible();
    await expect(page.getByTestId('participant-list')).toBeVisible();
  });

  test('Verify navigation to conflicting event from details view', async ({ page }) => {
    // Open conflict details
    const conflictAlert = page.getByTestId('conflict-alert-notification');
    await conflictAlert.click();
    await page.waitForSelector('[data-testid="conflict-details-view"]');
    
    // User navigates to conflicting event
    const conflictingEventLink = page.getByTestId('conflicting-event-link-1');
    await expect(conflictingEventLink).toBeVisible();
    await conflictingEventLink.click();
    
    // Expected Result: User is taken to event scheduling page
    await page.waitForURL(/.*\/events\/.*/);
    
    const eventSchedulingPage = page.getByTestId('event-scheduling-page');
    await expect(eventSchedulingPage).toBeVisible();
    
    const eventDetailsSection = page.getByTestId('event-details-section');
    await expect(eventDetailsSection).toBeVisible();
    
    // Verify event information is loaded
    const eventTitle = page.getByTestId('event-title');
    await expect(eventTitle).toBeVisible();
    await expect(eventTitle).not.toBeEmpty();
  });
});