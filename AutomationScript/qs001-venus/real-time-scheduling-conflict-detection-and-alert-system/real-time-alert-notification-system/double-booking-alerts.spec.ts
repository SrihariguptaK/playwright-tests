import { test, expect } from '@playwright/test';

test.describe('Double Booking Alerts for Resource Manager', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const RESOURCE_MANAGER_EMAIL = 'resource.manager@example.com';
  const RESOURCE_MANAGER_PASSWORD = 'SecurePass123!';
  const ALERT_DELIVERY_TIMEOUT = 5000; // 5 seconds

  test.beforeEach(async ({ page }) => {
    // Login as Resource Manager
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', RESOURCE_MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', RESOURCE_MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Verify alert delivery to Resource Manager within 5 seconds', async ({ page, request }) => {
    // Navigate to resource booking page
    await page.goto(`${BASE_URL}/bookings`);
    await expect(page.locator('[data-testid="bookings-page"]')).toBeVisible();

    // Create first booking for a resource
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.fill('[data-testid="requester-name-input"]', 'John Doe');
    await page.click('[data-testid="submit-booking-button"]');
    
    // Verify first booking is created
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();
    const firstBookingId = await page.locator('[data-testid="booking-id"]').textContent();

    // Start timer before creating double booking conflict
    const startTime = Date.now();

    // Create second booking for the same resource and time slot (double booking)
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    await page.fill('[data-testid="requester-name-input"]', 'Jane Smith');
    await page.click('[data-testid="submit-booking-button"]');

    // Conflict should be detected
    await expect(page.locator('[data-testid="conflict-detected-message"]')).toBeVisible({ timeout: 2000 });

    // Monitor for alert notification
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible({ timeout: ALERT_DELIVERY_TIMEOUT });

    // Calculate delivery time
    const endTime = Date.now();
    const deliveryTime = endTime - startTime;

    // Verify alert was delivered within 5 seconds
    expect(deliveryTime).toBeLessThanOrEqual(5000);

    // Verify alert delivery confirmation via API
    const alertStatusResponse = await request.get(`${BASE_URL}/api/alerts/status`, {
      headers: {
        'Authorization': `Bearer ${await page.evaluate(() => localStorage.getItem('authToken'))}`
      }
    });
    expect(alertStatusResponse.ok()).toBeTruthy();
    const alertStatus = await alertStatusResponse.json();
    expect(alertStatus.delivered).toBe(true);
    expect(alertStatus.deliveryTime).toBeLessThanOrEqual(5000);
  });

  test('Validate alert content and acknowledgment by Resource Manager', async ({ page }) => {
    // Setup: Create a double booking conflict to trigger alert
    await page.goto(`${BASE_URL}/bookings`);
    
    // Create first booking
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.fill('[data-testid="requester-name-input"]', 'Alice Johnson');
    await page.click('[data-testid="submit-booking-button"]');
    await expect(page.locator('[data-testid="booking-success-message"]')).toBeVisible();
    const firstBookingId = await page.locator('[data-testid="booking-id"]').textContent();

    // Create second booking (double booking)
    await page.click('[data-testid="create-booking-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="booking-date-input"]', '2024-02-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.fill('[data-testid="requester-name-input"]', 'Bob Williams');
    await page.click('[data-testid="submit-booking-button"]');

    // Locate and open the received double booking alert notification
    const alertNotification = page.locator('[data-testid="alert-notification"]');
    await expect(alertNotification).toBeVisible({ timeout: 5000 });
    await alertNotification.click();

    // Review alert content for detailed conflict information
    const alertModal = page.locator('[data-testid="alert-modal"]');
    await expect(alertModal).toBeVisible();

    // Verify resource name is displayed
    const resourceName = alertModal.locator('[data-testid="alert-resource-name"]');
    await expect(resourceName).toContainText('Meeting Room B');

    // Verify booking IDs are displayed
    const bookingIds = alertModal.locator('[data-testid="alert-booking-ids"]');
    await expect(bookingIds).toBeVisible();
    await expect(bookingIds).toContainText(firstBookingId || '');

    // Verify time slots are displayed
    const timeSlot = alertModal.locator('[data-testid="alert-time-slot"]');
    await expect(timeSlot).toContainText('14:00');
    await expect(timeSlot).toContainText('15:00');

    // Verify parties involved are displayed
    const partiesInvolved = alertModal.locator('[data-testid="alert-parties-involved"]');
    await expect(partiesInvolved).toContainText('Alice Johnson');
    await expect(partiesInvolved).toContainText('Bob Williams');

    // Verify alert includes actionable elements
    const bookingDetailsLink = alertModal.locator('[data-testid="view-booking-details-link"]');
    await expect(bookingDetailsLink).toBeVisible();
    
    const resolutionOptionsButton = alertModal.locator('[data-testid="resolution-options-button"]');
    await expect(resolutionOptionsButton).toBeVisible();

    // Click the 'Acknowledge' button on the alert
    const acknowledgeButton = alertModal.locator('[data-testid="acknowledge-alert-button"]');
    await expect(acknowledgeButton).toBeVisible();
    await acknowledgeButton.click();

    // Verify alert status is updated to acknowledged
    await expect(alertModal.locator('[data-testid="alert-status"]')).toContainText('Acknowledged');

    // Click the 'Dismiss' button to remove alert from active view
    const dismissButton = alertModal.locator('[data-testid="dismiss-alert-button"]');
    await expect(dismissButton).toBeVisible();
    await dismissButton.click();

    // Verify alert is dismissed and modal is closed
    await expect(alertModal).not.toBeVisible();

    // Navigate to alert history section
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="alert-history-link"]');
    await expect(page.locator('[data-testid="alert-history-page"]')).toBeVisible();

    // Verify the dismissed alert is preserved in history
    const alertHistoryTable = page.locator('[data-testid="alert-history-table"]');
    await expect(alertHistoryTable).toBeVisible();

    const dismissedAlert = alertHistoryTable.locator('[data-testid="alert-row"]').filter({
      hasText: 'Meeting Room B'
    });
    await expect(dismissedAlert).toBeVisible();

    // Verify alert history entry shows acknowledged and dismissed status
    await expect(dismissedAlert.locator('[data-testid="alert-status-cell"]')).toContainText('Acknowledged');
    await expect(dismissedAlert.locator('[data-testid="alert-dismissed-cell"]')).toContainText('Yes');

    // Verify alert history entry is searchable
    const searchInput = page.locator('[data-testid="alert-history-search-input"]');
    await searchInput.fill('Meeting Room B');
    await page.click('[data-testid="search-button"]');

    // Verify search results contain the dismissed alert
    const searchResults = page.locator('[data-testid="alert-history-table"] [data-testid="alert-row"]');
    await expect(searchResults).toHaveCount(1);
    await expect(searchResults.first()).toContainText('Meeting Room B');

    // Verify alert is accessible by clicking on it
    await searchResults.first().click();
    const alertDetailsModal = page.locator('[data-testid="alert-details-modal"]');
    await expect(alertDetailsModal).toBeVisible();
    await expect(alertDetailsModal.locator('[data-testid="alert-resource-name"]')).toContainText('Meeting Room B');
  });
});