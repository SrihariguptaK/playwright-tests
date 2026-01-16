import { test, expect } from '@playwright/test';

test.describe('Multi-Time Zone Scheduling', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to application and ensure logged in as scheduler
    await page.goto(baseURL);
    // Assuming login is required
    await page.fill('[data-testid="username-input"]', 'scheduler@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
  });

  test('Verify appointment creation with time zone data (happy-path)', async ({ page }) => {
    // Navigate to the appointment creation page
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page).toHaveURL(/.*\/appointments\/create/);
    
    // Enter appointment title as 'Global Team Meeting'
    await page.fill('[data-testid="appointment-title-input"]', 'Global Team Meeting');
    
    // Select date as current date + 7 days
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    const dateString = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date-input"]', dateString);
    
    // Set appointment start time to 10:00 AM
    await page.fill('[data-testid="appointment-start-time-input"]', '10:00');
    
    // Set appointment end time to 11:00 AM
    await page.fill('[data-testid="appointment-end-time-input"]', '11:00');
    
    // Select time zone A (e.g., America/New_York - EST) from the time zone dropdown
    await page.click('[data-testid="timezone-dropdown"]');
    await page.click('[data-testid="timezone-option-America/New_York"]');
    
    // Click 'Save' or 'Create Appointment' button
    await page.click('[data-testid="save-appointment-button"]');
    
    // Wait for success message or redirect
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Navigate to appointment details page to verify stored data
    await page.click('[data-testid="view-appointment-details"]');
    
    // Verify appointment saved with correct time zone metadata
    await expect(page.locator('[data-testid="appointment-title"]')).toHaveText('Global Team Meeting');
    await expect(page.locator('[data-testid="appointment-timezone"]')).toContainText('America/New_York');
    await expect(page.locator('[data-testid="appointment-start-time"]')).toContainText('10:00');
    
    // Change user profile time zone to time zone B (e.g., America/Los_Angeles - PST)
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="timezone-settings-dropdown"]');
    await page.click('[data-testid="timezone-option-America/Los_Angeles"]');
    await page.click('[data-testid="save-settings-button"]');
    await expect(page.locator('[data-testid="settings-saved-message"]')).toBeVisible();
    
    // View the same appointment in the calendar or appointment list
    await page.click('[data-testid="appointments-link"]');
    await page.click('[data-testid="appointment-Global-Team-Meeting"]');
    
    // Verify time zone conversion calculation manually (EST to PST = -3 hours)
    // Appointment time displayed correctly in local time (10:00 AM EST = 7:00 AM PST)
    await expect(page.locator('[data-testid="appointment-start-time"]')).toContainText('07:00');
    await expect(page.locator('[data-testid="appointment-timezone-display"]')).toContainText('America/Los_Angeles');
  });

  test('Detect conflicts across different time zones (happy-path)', async ({ page }) => {
    // Navigate to appointment creation page
    await page.click('[data-testid="create-appointment-button"]');
    
    // Create first appointment: Title='Meeting A', Date=current date + 5 days, Time=2:00 PM - 3:00 PM, Time Zone=America/New_York (EST)
    const appointmentDate = new Date();
    appointmentDate.setDate(appointmentDate.getDate() + 5);
    const dateString = appointmentDate.toISOString().split('T')[0];
    
    await page.fill('[data-testid="appointment-title-input"]', 'Meeting A');
    await page.fill('[data-testid="appointment-date-input"]', dateString);
    await page.fill('[data-testid="appointment-start-time-input"]', '14:00');
    await page.fill('[data-testid="appointment-end-time-input"]', '15:00');
    await page.click('[data-testid="timezone-dropdown"]');
    await page.click('[data-testid="timezone-option-America/New_York"]');
    await page.click('[data-testid="save-appointment-button"]');
    
    // Verify first appointment is displayed in calendar
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await page.click('[data-testid="calendar-link"]');
    await expect(page.locator('[data-testid="appointment-Meeting-A"]')).toBeVisible();
    
    // Navigate to create a second appointment
    await page.click('[data-testid="create-appointment-button"]');
    
    // Create second appointment with overlapping time in different time zone
    // Title='Meeting B', Date=same date as Meeting A, Time=11:00 AM - 12:00 PM, Time Zone=America/Los_Angeles (PST)
    // 11:00 AM PST = 2:00 PM EST (overlaps with Meeting A)
    await page.fill('[data-testid="appointment-title-input"]', 'Meeting B');
    await page.fill('[data-testid="appointment-date-input"]', dateString);
    await page.fill('[data-testid="appointment-start-time-input"]', '11:00');
    await page.fill('[data-testid="appointment-end-time-input"]', '12:00');
    await page.click('[data-testid="timezone-dropdown"]');
    await page.click('[data-testid="timezone-option-America/Los_Angeles"]');
    
    // Click 'Save' or 'Create Appointment' button
    await page.click('[data-testid="save-appointment-button"]');
    
    // Observe system response to conflict detection
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    
    // Review conflict details provided by the system
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('Meeting A');
    await expect(page.locator('[data-testid="conflict-details"]')).toContainText('overlaps');
    
    // Cancel the conflicting appointment
    await page.click('[data-testid="cancel-appointment-button"]');
    
    // Attempt to create third appointment with partial overlap
    await page.click('[data-testid="create-appointment-button"]');
    // Title='Meeting C', Date=same date, Time=11:30 AM - 12:30 PM, Time Zone=America/Los_Angeles (PST)
    // 11:30 AM PST = 2:30 PM EST (partially overlaps with Meeting A which ends at 3:00 PM EST)
    await page.fill('[data-testid="appointment-title-input"]', 'Meeting C');
    await page.fill('[data-testid="appointment-date-input"]', dateString);
    await page.fill('[data-testid="appointment-start-time-input"]', '11:30');
    await page.fill('[data-testid="appointment-end-time-input"]', '12:30');
    await page.click('[data-testid="timezone-dropdown"]');
    await page.click('[data-testid="timezone-option-America/Los_Angeles"]');
    await page.click('[data-testid="save-appointment-button"]');
    
    // System should detect partial overlap conflict
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await page.click('[data-testid="cancel-appointment-button"]');
    
    // Create fourth appointment with no overlap
    await page.click('[data-testid="create-appointment-button"]');
    // Title='Meeting D', Date=same date, Time=12:00 PM - 1:00 PM, Time Zone=America/Los_Angeles (PST)
    // 12:00 PM PST = 3:00 PM EST (no overlap with Meeting A which ends at 3:00 PM EST)
    await page.fill('[data-testid="appointment-title-input"]', 'Meeting D');
    await page.fill('[data-testid="appointment-date-input"]', dateString);
    await page.fill('[data-testid="appointment-start-time-input"]', '12:00');
    await page.fill('[data-testid="appointment-end-time-input"]', '13:00');
    await page.click('[data-testid="timezone-dropdown"]');
    await page.click('[data-testid="timezone-option-America/Los_Angeles"]');
    await page.click('[data-testid="save-appointment-button"]');
    
    // No conflict should be detected
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).not.toBeVisible();
    
    // Verify all appointments in calendar view with user time zone set to GMT
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-link"]');
    await page.click('[data-testid="timezone-settings-dropdown"]');
    await page.click('[data-testid="timezone-option-GMT"]');
    await page.click('[data-testid="save-settings-button"]');
    
    await page.click('[data-testid="calendar-link"]');
    
    // Verify appointments are displayed with correct GMT conversions
    await expect(page.locator('[data-testid="appointment-Meeting-A"]')).toBeVisible();
    await expect(page.locator('[data-testid="appointment-Meeting-D"]')).toBeVisible();
    
    // Meeting A: 2:00 PM EST = 7:00 PM GMT
    await page.click('[data-testid="appointment-Meeting-A"]');
    await expect(page.locator('[data-testid="appointment-start-time"]')).toContainText('19:00');
    
    await page.click('[data-testid="calendar-link"]');
    
    // Meeting D: 12:00 PM PST = 8:00 PM GMT
    await page.click('[data-testid="appointment-Meeting-D"]');
    await expect(page.locator('[data-testid="appointment-start-time"]')).toContainText('20:00');
  });
});