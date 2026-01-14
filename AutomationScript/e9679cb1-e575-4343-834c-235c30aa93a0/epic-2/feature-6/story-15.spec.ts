import { test, expect, Page } from '@playwright/test';

// Types
interface ConflictDetails {
  id: string;
  conflictType: string;
  overlapDuration: number;
  appointments: Array<{
    id: string;
    startTime: string;
    endTime: string;
    resources: string[];
  }>;
}

interface AlternativeSlot {
  id: string;
  startTime: string;
  endTime: string;
  resources: string[];
}

// Test Data Fixtures
const testData = {
  scheduler: {
    username: 'scheduler@hospital.com',
    password: 'Scheduler123!',
    role: 'scheduler'
  },
  unauthorizedUser: {
    username: 'nurse@hospital.com',
    password: 'Nurse123!',
    role: 'nurse'
  },
  conflict: {
    id: 'CONF-001',
    type: 'RESOURCE_OVERLAP',
    overlapDuration: 30,
    appointments: [
      {
        id: 'APT-101',
        patientName: 'John Doe',
        startTime: '2024-02-15T10:00:00Z',
        endTime: '2024-02-15T11:00:00Z',
        resources: ['Dr. Smith', 'Room 201']
      },
      {
        id: 'APT-102',
        patientName: 'Jane Smith',
        startTime: '2024-02-15T10:30:00Z',
        endTime: '2024-02-15T11:30:00Z',
        resources: ['Dr. Smith', 'Room 202']
      }
    ]
  },
  alternativeSlots: [
    {
      id: 'SLOT-001',
      startTime: '2024-02-15T11:30:00Z',
      endTime: '2024-02-15T12:30:00Z',
      resources: ['Dr. Smith', 'Room 202']
    },
    {
      id: 'SLOT-002',
      startTime: '2024-02-15T14:00:00Z',
      endTime: '2024-02-15T15:00:00Z',
      resources: ['Dr. Smith', 'Room 202']
    },
    {
      id: 'SLOT-003',
      startTime: '2024-02-15T15:30:00Z',
      endTime: '2024-02-15T16:30:00Z',
      resources: ['Dr. Smith', 'Room 202']
    }
  ]
};

// Page Object Model
class LoginPage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/login');
    await this.page.waitForLoadState('networkidle');
  }

  async login(username: string, password: string) {
    await this.page.fill('[data-testid="username-input"]', username);
    await this.page.fill('[data-testid="password-input"]', password);
    await this.page.click('[data-testid="login-button"]');
    await this.page.waitForLoadState('networkidle');
  }
}

class ConflictDetailsPage {
  constructor(private page: Page) {}

  async navigateToConflict(conflictId: string) {
    await this.page.goto(`/conflicts/${conflictId}`);
    await this.page.waitForLoadState('networkidle');
  }

  async openFromNotification(conflictId: string) {
    await this.page.click(`[data-testid="notification-conflict-${conflictId}"]`);
    await this.page.waitForSelector('[data-testid="conflict-details-panel"]', { timeout: 2000 });
  }

  async getConflictType(): Promise<string> {
    const element = await this.page.locator('[data-testid="conflict-type"]');
    return await element.textContent() || '';
  }

  async getOverlapDuration(): Promise<string> {
    const element = await this.page.locator('[data-testid="overlap-duration"]');
    return await element.textContent() || '';
  }

  async getConflictingAppointments(): Promise<Array<any>> {
    const appointments = await this.page.locator('[data-testid^="appointment-card-"]').all();
    const appointmentData = [];
    
    for (const apt of appointments) {
      const id = await apt.getAttribute('data-appointment-id');
      const startTime = await apt.locator('[data-testid="start-time"]').textContent();
      const endTime = await apt.locator('[data-testid="end-time"]').textContent();
      const resources = await apt.locator('[data-testid="resource-item"]').allTextContents();
      
      appointmentData.push({ id, startTime, endTime, resources });
    }
    
    return appointmentData;
  }

  async isDetailsPanelVisible(): Promise<boolean> {
    return await this.page.locator('[data-testid="conflict-details-panel"]').isVisible();
  }

  async getLoadTime(): Promise<number> {
    const performanceTiming = await this.page.evaluate(() => {
      const entries = performance.getEntriesByType('navigation');
      if (entries.length > 0) {
        const navEntry = entries[0] as PerformanceNavigationTiming;
        return navEntry.loadEventEnd - navEntry.fetchStart;
      }
      return 0;
    });
    return performanceTiming;
  }
}

class ConflictResolutionPage {
  constructor(private page: Page) {}

  async openAlternativeSlotsPanel() {
    await this.page.click('[data-testid="view-alternatives-button"]');
    await this.page.waitForSelector('[data-testid="alternative-slots-panel"]', { timeout: 3000 });
  }

  async getAlternativeSlots(): Promise<AlternativeSlot[]> {
    const slots = await this.page.locator('[data-testid^="alternative-slot-"]').all();
    const slotData: AlternativeSlot[] = [];
    
    for (const slot of slots) {
      const id = await slot.getAttribute('data-slot-id') || '';
      const startTime = await slot.locator('[data-testid="slot-start-time"]').textContent() || '';
      const endTime = await slot.locator('[data-testid="slot-end-time"]').textContent() || '';
      const resources = await slot.locator('[data-testid="slot-resource"]').allTextContents();
      
      slotData.push({ id, startTime, endTime, resources });
    }
    
    return slotData;
  }

  async getSuggestionLoadTime(): Promise<number> {
    const startTime = Date.now();
    await this.openAlternativeSlotsPanel();
    const endTime = Date.now();
    return endTime - startTime;
  }

  async selectAlternativeSlot(slotId: string) {
    await this.page.click(`[data-testid="alternative-slot-${slotId}"] [data-testid="select-slot-button"]`);
  }

  async confirmReschedule() {
    await this.page.click('[data-testid="confirm-reschedule-button"]');
    await this.page.waitForSelector('[data-testid="reschedule-success-message"]', { timeout: 2000 });
  }

  async initiateRescheduling(appointmentId: string) {
    await this.page.click(`[data-testid="reschedule-button-${appointmentId}"]`);
    await this.page.waitForSelector('[data-testid="reschedule-modal"]');
  }

  async selectNewTimeSlot(slotId: string) {
    await this.page.click(`[data-testid="time-slot-${slotId}"]`);
    await this.page.waitForSelector(`[data-testid="time-slot-${slotId}"][data-selected="true"]`);
  }

  async saveReschedule(): Promise<number> {
    const startTime = Date.now();
    await this.page.click('[data-testid="save-reschedule-button"]');
    await this.page.waitForSelector('[data-testid="reschedule-success-notification"]', { timeout: 2000 });
    const endTime = Date.now();
    return endTime - startTime;
  }

  async isConflictCleared(conflictId: string): Promise<boolean> {
    const conflictStatus = await this.page.locator(`[data-testid="conflict-${conflictId}-status"]`);
    const status = await conflictStatus.textContent();
    return status?.toLowerCase().includes('resolved') || status?.toLowerCase().includes('cleared') || false;
  }
}

class NotificationsPage {
  constructor(private page: Page) {}

  async openNotificationsPanel() {
    await this.page.click('[data-testid="notifications-icon"]');
    await this.page.waitForSelector('[data-testid="notifications-panel"]');
  }

  async getConflictNotification(conflictId: string) {
    return await this.page.locator(`[data-testid="notification-conflict-${conflictId}"]`);
  }

  async clickConflictNotification(conflictId: string) {
    await this.page.click(`[data-testid="notification-conflict-${conflictId}"]`);
  }
}

// Test Suite for Story 15: View Detailed Conflict Information
test.describe('Story-15: As Scheduler, I want to view detailed conflict information to understand and resolve scheduling issues', () => {
  let loginPage: LoginPage;
  let conflictDetailsPage: ConflictDetailsPage;
  let notificationsPage: NotificationsPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    conflictDetailsPage = new ConflictDetailsPage(page);
    notificationsPage = new NotificationsPage(page);
    
    // Login as scheduler
    await loginPage.navigate();
    await loginPage.login(testData.scheduler.username, testData.scheduler.password);
  });

  test('TC-15.1: Scheduler views complete conflict details including all conflicting appointments', async ({ page }) => {
    // Navigate to conflict details page
    await conflictDetailsPage.navigateToConflict(testData.conflict.id);
    
    // Verify conflict details panel is visible
    const isPanelVisible = await conflictDetailsPage.isDetailsPanelVisible();
    expect(isPanelVisible).toBeTruthy();
    
    // Verify conflict type is displayed
    const conflictType = await conflictDetailsPage.getConflictType();
    expect(conflictType).toBeTruthy();
    expect(conflictType.length).toBeGreaterThan(0);
    
    // Verify overlap duration is displayed
    const overlapDuration = await conflictDetailsPage.getOverlapDuration();
    expect(overlapDuration).toBeTruthy();
    expect(overlapDuration).toContain('30');
    
    // Verify all conflicting appointments are displayed
    const appointments = await conflictDetailsPage.getConflictingAppointments();
    expect(appointments.length).toBeGreaterThanOrEqual(2);
    
    // Verify each appointment has start/end times and resources
    for (const appointment of appointments) {
      expect(appointment.id).toBeTruthy();
      expect(appointment.startTime).toBeTruthy();
      expect(appointment.endTime).toBeTruthy();
      expect(appointment.resources.length).toBeGreaterThan(0);
    }
  });

  test('TC-15.2: Conflict details display resource and time overlap information clearly', async ({ page }) => {
    await conflictDetailsPage.navigateToConflict(testData.conflict.id);
    
    // Verify overlap duration section exists
    const overlapSection = await page.locator('[data-testid="overlap-details-section"]');
    await expect(overlapSection).toBeVisible();
    
    // Verify overlap duration value
    const overlapDuration = await conflictDetailsPage.getOverlapDuration();
    expect(overlapDuration).toMatch(/\d+\s*(minute|min|minutes)/i);
    
    // Verify conflict type is clearly labeled
    const conflictTypeLabel = await page.locator('[data-testid="conflict-type-label"]');
    await expect(conflictTypeLabel).toBeVisible();
    await expect(conflictTypeLabel).toContainText('Conflict Type');
    
    // Verify resource overlap is displayed
    const resourceOverlapSection = await page.locator('[data-testid="resource-overlap-section"]');
    await expect(resourceOverlapSection).toBeVisible();
    
    // Verify conflicting resources are highlighted
    const conflictingResources = await page.locator('[data-testid="conflicting-resource"]').all();
    expect(conflictingResources.length).toBeGreaterThan(0);
  });

  test('TC-15.3: Conflict details load within 2 seconds performance requirement', async ({ page }) => {
    const startTime = Date.now();
    
    // Navigate to conflict details
    await conflictDetailsPage.navigateToConflict(testData.conflict.id);
    
    // Wait for details panel to be visible
    await page.waitForSelector('[data-testid="conflict-details-panel"]', { timeout: 2000 });
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Verify load time is under 2 seconds (2000ms)
    expect(loadTime).toBeLessThanOrEqual(2000);
    
    // Verify all critical elements are loaded
    await expect(page.locator('[data-testid="conflict-type"]')).toBeVisible();
    await expect(page.locator('[data-testid="overlap-duration"]')).toBeVisible();
    const appointments = await page.locator('[data-testid^="appointment-card-"]').all();
    expect(appointments.length).toBeGreaterThan(0);
  });

  test('TC-15.4: Access to conflict details is restricted to authorized scheduler roles', async ({ page }) => {
    // Logout current user
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL('**/login');
    
    // Login as unauthorized user
    await loginPage.login(testData.unauthorizedUser.username, testData.unauthorizedUser.password);
    
    // Attempt to access conflict details
    await page.goto(`/conflicts/${testData.conflict.id}`);
    
    // Verify access is denied
    const accessDeniedMessage = await page.locator('[data-testid="access-denied-message"]');
    await expect(accessDeniedMessage).toBeVisible({ timeout: 5000 });
    
    // Verify redirect to unauthorized page or dashboard
    await page.waitForURL(/\/(unauthorized|dashboard)/, { timeout: 5000 });
    
    // Verify conflict details panel is NOT visible
    const isPanelVisible = await page.locator('[data-testid="conflict-details-panel"]').isVisible();
    expect(isPanelVisible).toBeFalsy();
  });

  test('TC-15.5: Scheduler can access conflict details from notification alert', async ({ page }) => {
    // Open notifications panel
    await notificationsPage.openNotificationsPanel();
    
    // Verify conflict notification is present
    const notification = await notificationsPage.getConflictNotification(testData.conflict.id);
    await expect(notification).toBeVisible();
    
    // Click on conflict notification
    await notificationsPage.clickConflictNotification(testData.conflict.id);
    
    // Verify conflict details page opens within 2 seconds
    await page.waitForSelector('[data-testid="conflict-details-panel"]', { timeout: 2000 });
    
    // Verify correct conflict details are displayed
    const conflictIdElement = await page.locator('[data-testid="conflict-id"]');
    await expect(conflictIdElement).toContainText(testData.conflict.id);
  });

  test('TC-15.6: Conflict details show appointment history and audit logs', async ({ page }) => {
    await conflictDetailsPage.navigateToConflict(testData.conflict.id);
    
    // Expand audit log section
    await page.click('[data-testid="audit-log-toggle"]');
    await page.waitForSelector('[data-testid="audit-log-section"]');
    
    // Verify audit log is visible
    const auditLogSection = await page.locator('[data-testid="audit-log-section"]');
    await expect(auditLogSection).toBeVisible();
    
    // Verify audit entries exist
    const auditEntries = await page.locator('[data-testid^="audit-entry-"]').all();
    expect(auditEntries.length).toBeGreaterThan(0);
    
    // Verify each audit entry has timestamp and action
    for (const entry of auditEntries) {
      const timestamp = await entry.locator('[data-testid="audit-timestamp"]');
      const action = await entry.locator('[data-testid="audit-action"]');
      await expect(timestamp).toBeVisible();
      await expect(action).toBeVisible();
    }
  });
});

// Test Suite for Story 16: System Suggests Alternative Time Slots
test.describe('Story-16: As Scheduler, I want the system to suggest alternative time slots to resolve scheduling conflicts efficiently', () => {
  let loginPage: LoginPage;
  let conflictDetailsPage: ConflictDetailsPage;
  let conflictResolutionPage: ConflictResolutionPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    conflictDetailsPage = new ConflictDetailsPage(page);
    conflictResolutionPage = new ConflictResolutionPage(page);
    
    // Login as scheduler
    await loginPage.navigate();
    await loginPage.login(testData.scheduler.username, testData.scheduler.password);
    
    // Navigate to conflict details
    await conflictDetailsPage.navigateToConflict(testData.conflict.id);
  });

  test('TC-16.1: System generates at least three alternative time slots for conflicting appointments', async ({ page }) => {
    // Open alternative slots panel
    await conflictResolutionPage.openAlternativeSlotsPanel();
    
    // Get all alternative slots
    const alternativeSlots = await conflictResolutionPage.getAlternativeSlots();
    
    // Verify at least 3 alternative slots are suggested
    expect(alternativeSlots.length).toBeGreaterThanOrEqual(3);
    
    // Verify each slot has required information
    for (const slot of alternativeSlots) {
      expect(slot.id).toBeTruthy();
      expect(slot.startTime).toBeTruthy();
      expect(slot.endTime).toBeTruthy();
      expect(slot.resources.length).toBeGreaterThan(0);
    }
  });

  test('TC-16.2: Suggested slots are based on real-time resource availability', async ({ page }) => {
    await conflictResolutionPage.openAlternativeSlotsPanel();
    
    // Get suggested slots
    const suggestedSlots = await conflictResolutionPage.getAlternativeSlots();
    expect(suggestedSlots.length).toBeGreaterThan(0);
    
    // Verify each slot shows availability status
    for (let i = 0; i < suggestedSlots.length; i++) {
      const slotElement = page.locator(`[data-testid="alternative-slot-${suggestedSlots[i].id}"]`);
      
      // Verify availability indicator is present
      const availabilityIndicator = slotElement.locator('[data-testid="availability-status"]');
      await expect(availabilityIndicator).toBeVisible();
      
      const availabilityText = await availabilityIndicator.textContent();
      expect(availabilityText?.toLowerCase()).toContain('available');
      
      // Verify all required resources are shown as available
      const resourceStatuses = await slotElement.locator('[data-testid="resource-status"]').all();
      expect(resourceStatuses.length).toBeGreaterThan(0);
      
      for (const resourceStatus of resourceStatuses) {
        const statusText = await resourceStatus.textContent();
        expect(statusText?.toLowerCase()).toContain('available');
      }
    }
  });

  test('TC-16.3: Suggestion generation completes within 3 seconds performance requirement', async ({ page }) => {
    // Measure time to generate and display suggestions
    const startTime = Date.now();
    
    await conflictResolutionPage.openAlternativeSlotsPanel();
    
    // Wait for at least one alternative slot to appear
    await page.waitForSelector('[data-testid^="alternative-slot-"]', { timeout: 3000 });
    
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Verify load time is under 3 seconds (3000ms)
    expect(loadTime).toBeLessThanOrEqual(3000);
    
    // Verify suggestions are actually displayed
    const slots = await page.locator('[data-testid^="alternative-slot-"]').all();
    expect(slots.length).toBeGreaterThan(0);
  });

  test('TC-16.4: Scheduler can select and apply suggested time slots to reschedule appointments', async ({ page }) => {
    await conflictResolutionPage.openAlternativeSlotsPanel();
    
    // Get suggested slots
    const suggestedSlots = await conflictResolutionPage.getAlternativeSlots();
    expect(suggestedSlots.length).toBeGreaterThan(0);
    
    // Select first alternative slot
    const firstSlotId = suggestedSlots[0].id;
    await conflictResolutionPage.selectAlternativeSlot(firstSlotId);
    
    // Verify slot is marked as selected
    const selectedSlot = page.locator(`[data-testid="alternative-slot-${firstSlotId}"]`);
    await expect(selectedSlot).toHaveAttribute('data-selected', 'true');
    
    // Apply the selection
    await page.click('[data-testid="apply-selected-slot-button"]');
    
    // Verify confirmation dialog appears
    await page.waitForSelector('[data-testid="reschedule-confirmation-dialog"]');
    
    // Confirm rescheduling
    await page.click('[data-testid="confirm-apply-button"]');
    
    // Verify success message
    await page.waitForSelector('[data-testid="reschedule-success-message"]', { timeout: 2000 });
    const successMessage = await page.locator('[data-testid="reschedule-success-message"]');
    await expect(successMessage).toBeVisible();
  });

  test('TC-16.5: Alternative slots are prioritized by earliest available time', async ({ page }) => {
    await conflictResolutionPage.openAlternativeSlotsPanel();
    
    const alternativeSlots = await conflictResolutionPage.getAlternativeSlots();
    expect(alternativeSlots.length).toBeGreaterThanOrEqual(2);
    
    // Verify slots are ordered by start time (earliest first)
    for (let i = 0; i < alternativeSlots.length - 1; i++) {
      const currentSlotTime = new Date(alternativeSlots[i].startTime).getTime();
      const nextSlotTime = new Date(alternativeSlots[i + 1].startTime).getTime();
      
      // Current slot should be earlier than or equal to next slot
      expect(currentSlotTime).toBeLessThanOrEqual(nextSlotTime);
    }
    
    // Verify earliest slot is marked as recommended
    const firstSlot = page.locator('[data-testid="alternative-slot-' + alternativeSlots[0].id + '"]');
    const recommendedBadge = firstSlot.locator('[data-testid="recommended-badge"]');
    await expect(recommendedBadge).toBeVisible();
  });

  test('TC-16.6: System validates slot availability before suggesting', async ({ page }) => {
    await conflictResolutionPage.openAlternativeSlotsPanel();
    
    // Get all suggested slots
    const suggestedSlots = await conflictResolutionPage.getAlternativeSlots();
    
    // For each suggested slot, verify it passes availability validation
    for (const slot of suggestedSlots) {
      const slotElement = page.locator(`[data-testid="alternative-slot-${slot.id}"]`);
      
      // Verify validation indicator shows passed
      const validationStatus = slotElement.locator('[data-testid="validation-status"]');
      const statusText = await validationStatus.getAttribute('data-validation');
      expect(statusText).toBe('passed');
      
      // Verify no booking conflicts exist
      const conflictIndicator = slotElement.locator('[data-testid="conflict-indicator"]');
      const hasConflict = await conflictIndicator.isVisible();
      expect(hasConflict).toBeFalsy();
    }
  });
});

// Test Suite for Story 17: Reschedule Conflicting Appointments from Alert Interface
test.describe('Story-17: As Scheduler, I want to reschedule conflicting appointments directly from the alert interface to streamline conflict resolution', () => {
  let loginPage: LoginPage;
  let notificationsPage: NotificationsPage;
  let conflictResolutionPage: ConflictResolutionPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    notificationsPage = new NotificationsPage(page);
    conflictResolutionPage = new ConflictResolutionPage(page);
    
    // Login as scheduler
    await loginPage.navigate();
    await loginPage.login(testData.scheduler.username, testData.scheduler.password);
  });

  test('TC-17.1: Scheduler can initiate rescheduling from conflict alert interface', async ({ page }) => {
    // Open notifications panel
    await notificationsPage.openNotificationsPanel();
    
    // Verify conflict alert is present
    const conflictNotification = await notificationsPage.getConflictNotification(testData.conflict.id);
    await expect(conflictNotification).toBeVisible();
    
    // Verify reschedule button exists in the notification
    const rescheduleButton = conflictNotification.locator('[data-testid="reschedule-from-alert-button"]');
    await expect(rescheduleButton).toBeVisible();
    
    // Click reschedule button
    await rescheduleButton.click();
    
    // Verify rescheduling modal opens
    await page.waitForSelector('[data-testid="reschedule-modal"]');
    const rescheduleModal = page.locator('[data-testid="reschedule-modal"]');
    await expect(rescheduleModal).toBeVisible();
    
    // Verify appointment details are pre-filled
    const appointmentDetails = page.locator('[data-testid="appointment-details-section"]');
    await expect(appointmentDetails).toBeVisible();
  });

  test('TC-17.2: System validates new time slot availability before saving', async ({ page }) => {
    // Navigate to conflict and open rescheduling
    await notificationsPage.openNotificationsPanel();
    const notification = await notificationsPage.getConflictNotification(testData.conflict.id);
    await notification.locator('[data-testid="reschedule-from-alert-button"]').click();
    
    await page.waitForSelector('[data-testid="reschedule-modal"]');
    
    // Select a time slot
    const timeSlotSelector = page.locator('[data-testid^="time-slot-"]').first();
    await timeSlotSelector.click();
    
    // Attempt to save
    const saveButton = page.locator('[data-testid="save-reschedule-button"]');
    await saveButton.click();
    
    // Verify validation is performed
    await page.waitForSelector('[data-testid="validation-in-progress"]', { timeout: 1000 });
    
    // Wait for validation to complete
    await page.waitForSelector('[data-testid="validation-complete"]', { timeout: 3000 });
    
    // Verify validation status
    const validationStatus = page.locator('[data-testid="validation-status"]');
    const statusText = await validationStatus.textContent();
    expect(statusText).toBeTruthy();
    
    // If validation passed, verify success message
    if (statusText?.toLowerCase().includes('valid') || statusText?.toLowerCase().includes('available')) {
      await expect(page.locator('[data-testid="reschedule-success-notification"]')).toBeVisible();
    }
  });

  test('TC-17.3: Appointment updates successfully clear the conflict status', async ({ page }) => {
    // Store initial conflict ID
    const conflictId = testData.conflict.id;
    const appointmentId = testData.conflict.appointments[0].id;
    
    // Open notification and initiate rescheduling
    await notificationsPage.openNotificationsPanel();
    const notification = await notificationsPage.getConflictNotification(conflictId);
    await notification.locator('[data-testid="reschedule-from-alert-button"]').click();
    
    await page.waitForSelector('[data-testid="reschedule-modal"]');
    
    // Select alternative time slot
    const availableSlot = page.locator('[data-testid^="time-slot-"]').first();
    await availableSlot.click();
    
    // Save rescheduling
    await page.click('[data-testid="save-reschedule-button"]');
    
    // Wait for success confirmation
    await page.waitForSelector('[data-testid="reschedule-success-notification"]', { timeout: 2000 });
    
    // Close modal/notification
    await page.click('[data-testid="close-modal-button"]');
    
    // Navigate to conflicts list or dashboard
    await page.goto('/conflicts');
    await page.waitForLoadState('networkidle');
    
    // Verify conflict status is updated to resolved/cleared
    const conflictRow = page.locator(`[data-testid="conflict-row-${conflictId}"]`);
    const conflictStatus = conflictRow.locator('[data-testid="conflict-status"]');
    
    const statusText = await conflictStatus.textContent();
    expect(statusText?.toLowerCase()).toMatch(/resolved|cleared|completed/);
    
    // Verify conflict no longer appears in active conflicts
    const activeConflictsSection = page.locator('[data-testid="active-conflicts-section"]');
    const activeConflictExists = await activeConflictsSection.locator(`[data-testid="conflict-row-${conflictId}"]`).isVisible();
    expect(activeConflictExists).toBeFalsy();
  });

  test('TC-17.4: Rescheduling operation completes within 2 seconds performance requirement', async ({ page }) => {
    // Open notification and initiate rescheduling
    await notificationsPage.openNotificationsPanel();
    const notification = await notificationsPage.getConflictNotification(testData.conflict.id);
    await notification.locator('[data-testid="reschedule-from-alert-button"]').click();
    
    await page.waitForSelector('[data-testid="reschedule-modal"]');
    
    // Select alternative time slot
    const availableSlot = page.locator('[data-testid^="time-slot-"]').first();
    await availableSlot.click();
    
    // Measure time for save operation
    const startTime = Date.now();
    
    // Save rescheduling
    await page.click('[data-testid="save-reschedule-button"]');
    
    // Wait for success confirmation with 2 second timeout
    await page.waitForSelector('[data-testid="reschedule-success-notification"]', { timeout: 2000 });
    
    const endTime = Date.now();
    const operationTime = endTime - startTime;
    
    // Verify operation completed within 2 seconds
    expect(operationTime).toBeLessThanOrEqual(2000);
    
    // Verify success notification is displayed
    const successNotification = page.locator('[data-testid="reschedule-success-notification"]');
    await expect(successNotification).toBeVisible();
  });

  test('TC-17.5: Scheduler can reschedule multiple conflicting appointments in sequence', async ({ page }) => {
    const appointments = testData.conflict.appointments;
    
    for (let i = 0; i < appointments.length && i < 2; i++) {
      const appointmentId = appointments[i].id;
      
      // Open notifications
      await notificationsPage.openNotificationsPanel();
      
      // Select conflict notification
      const notification = await notificationsPage.getConflictNotification(testData.conflict.id);
      
      // Check if reschedule button exists for this appointment
      const rescheduleButton = notification.locator(`[data-testid="reschedule-appointment-${appointmentId}"]`);
      
      if (await rescheduleButton.isVisible()) {
        await rescheduleButton.click();
        
        // Wait for modal
        await page.waitForSelector('[data-testid="reschedule-modal"]');
        
        // Select time slot
        const timeSlot = page.locator('[data-testid^="time-slot-"]').first();
        await timeSlot.click();
        
        // Save
        await page.click('[data-testid="save-reschedule-button"]');
        
        // Wait for success
        await page.waitForSelector('[data-testid="reschedule-success-notification"]', { timeout: 2000 });
        
        // Close modal
        await page.click('[data-testid="close-modal-button"]');
        
        // Brief pause between operations
        await page.waitForTimeout(500);
      }
    }
    
    // Verify conflict is resolved after all rescheduling
    await page.goto('/conflicts');
    const conflictStatus = page.locator(`[data-testid="conflict-row-${testData.conflict.id}"] [data-testid="conflict-status"]`);
    const statusText = await conflictStatus.textContent();
    expect(statusText?.toLowerCase()).toMatch(/resolved|cleared/);
  });

  test('TC-17.6: System displays validation errors for unavailable time slots', async ({ page }) => {
    // Open notification and initiate rescheduling
    await notificationsPage.openNotificationsPanel();
    const notification = await notificationsPage.getConflictNotification(testData.conflict.id);
    await notification.locator('[data-testid="reschedule-from-alert-button"]').click();
    
    await page.waitForSelector('[data-testid="reschedule-modal"]');
    
    // Attempt to select an unavailable or conflicting time slot if exists
    const unavailableSlot = page.locator('[data-testid^="time-slot-"][data-available="false"]').first();
    
    if (await unavailableSlot.isVisible()) {
      await unavailableSlot.click();
      
      // Verify error message is displayed
      const errorMessage = page.locator('[data-testid="slot-unavailable-error"]');
      await expect(errorMessage).toBeVisible();
      
      // Verify save button is disabled
      const saveButton = page.locator('[data-testid="save-reschedule-button"]');
      await expect(saveButton).toBeDisabled();
    } else {
      // Manually input an invalid time that creates conflict
      await page.click('[data-testid="custom-time-input-toggle"]');
      
      // Use the original conflicting time
      await page.fill('[data-testid="start-time-input"]', '10:00');
      await page.fill('[data-testid="end-time-input"]', '11:00');
      
      // Trigger validation
      await page.click('[data-testid="validate-time-button"]');
      
      // Verify validation error
      await page.waitForSelector('[data-testid="validation-error-message"]', { timeout: 3000 });
      const validationError = page.locator('[data-testid="validation-error-message"]');
      await expect(validationError).toBeVisible();
      
      const errorText = await validationError.textContent();
      expect(errorText?.toLowerCase()).toMatch(/conflict|unavailable|already booked/);
    }
  });

  test('TC-17.7: Rescheduling interface provides appointment context and details', async ({ page }) => {
    // Open notification and initiate rescheduling
    await notificationsPage.openNotificationsPanel();
    const notification = await notificationsPage.getConflictNotification(testData.conflict.id);
    await notification.locator('[data-testid="reschedule-from-alert-button"]').click();
    
    await page.waitForSelector('[data-testid="reschedule-modal"]');
    
    // Verify appointment details are displayed
    const appointmentDetailsSection = page.locator('[data-testid="appointment-details-section"]');
    await expect(appointmentDetailsSection).toBeVisible();
    
    // Verify patient name is shown
    const patientName = page.locator('[data-testid="patient-name"]');
    await expect(patientName).toBeVisible();
    const patientNameText = await patientName.textContent();
    expect(patientNameText).toBeTruthy();
    
    // Verify current appointment time is shown
    const currentTime = page.locator('[data-testid="current-appointment-time"]');
    await expect(currentTime).toBeVisible();
    
    // Verify resources are listed
    const resources = page.locator('[data-testid="appointment-resources"]');
    await expect(resources).toBeVisible();
    const resourcesList = await resources.locator('[data-testid="resource-item"]').all();
    expect(resourcesList.length).toBeGreaterThan(0);
    
    // Verify conflict reason is explained
    const conflictReason = page.locator('[data-testid="conflict-reason"]');
    await expect(conflictReason).toBeVisible();
  });
});