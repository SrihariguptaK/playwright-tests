```typescript
import { test, expect, Page } from '@playwright/test';

// Test Data Fixtures
const testData = {
  scheduler: {
    username: 'scheduler@example.com',
    password: 'SecurePass123!',
    role: 'scheduler'
  },
  appointment: {
    resourceId: 'RES-001',
    resourceName: 'Conference Room A',
    originalDateTime: '2024-02-15T10:00:00',
    conflictingDateTime: '2024-02-15T14:00:00',
    patientName: 'John Doe',
    appointmentType: 'Consultation',
    duration: 60
  },
  alternatives: [
    { time: '2024-02-15T15:00:00', available: true },
    { time: '2024-02-15T16:00:00', available: true },
    { time: '2024-02-16T10:00:00', available: true }
  ],
  conflictHistory: {
    dateRange: {
      start: '2024-01-01',
      end: '2024-02-28'
    },
    resourceFilter: 'Conference Room A',
    conflictType: 'Double Booking'
  }
};

// Page Object Model - Scheduling Page
class SchedulingPage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/scheduling', { waitUntil: 'networkidle' });
    await this.page.waitForSelector('[data-testid="scheduling-container"]', { timeout: 10000 });
  }

  async createAppointment(resourceId: string, dateTime: string, patientName: string, appointmentType: string, duration: number) {
    await this.page.click('[data-testid="create-appointment-btn"]');
    await this.page.waitForSelector('[data-testid="appointment-form"]');
    
    await this.page.fill('[data-testid="resource-input"]', resourceId);
    await this.page.fill('[data-testid="datetime-input"]', dateTime);
    await this.page.fill('[data-testid="patient-name-input"]', patientName);
    await this.page.selectOption('[data-testid="appointment-type-select"]', appointmentType);
    await this.page.fill('[data-testid="duration-input"]', duration.toString());
    
    await this.page.click('[data-testid="submit-appointment-btn"]');
  }

  async waitForConflictDetection() {
    await this.page.waitForSelector('[data-testid="conflict-detected-modal"]', { timeout: 5000 });
  }

  async getAlternativeTimeSlots() {
    await this.page.waitForSelector('[data-testid="alternative-slots-container"]', { timeout: 3000 });
    return await this.page.locator('[data-testid="alternative-slot-item"]').all();
  }

  async selectAlternativeSlot(index: number) {
    const slots = await this.page.locator('[data-testid="alternative-slot-item"]').all();
    if (slots.length > index) {
      await slots[index].click();
      await this.page.click('[data-testid="apply-alternative-btn"]');
    } else {
      throw new Error(`Alternative slot at index ${index} not found`);
    }
  }

  async waitForConfirmation() {
    await this.page.waitForSelector('[data-testid="appointment-confirmation"]', { timeout: 5000 });
  }

  async getConfirmationMessage() {
    return await this.page.locator('[data-testid="confirmation-message"]').textContent();
  }

  async getUpdatedAppointmentTime() {
    return await this.page.locator('[data-testid="confirmed-appointment-time"]').textContent();
  }
}

// Page Object Model - Conflict History Page
class ConflictHistoryPage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/conflicts/history', { waitUntil: 'networkidle' });
    await this.page.waitForSelector('[data-testid="conflict-history-container"]', { timeout: 10000 });
  }

  async applyDateFilter(startDate: string, endDate: string) {
    await this.page.fill('[data-testid="start-date-filter"]', startDate);
    await this.page.fill('[data-testid="end-date-filter"]', endDate);
    await this.page.click('[data-testid="apply-date-filter-btn"]');
  }

  async applyResourceFilter(resourceName: string) {
    await this.page.fill('[data-testid="resource-filter-input"]', resourceName);
    await this.page.click('[data-testid="apply-resource-filter-btn"]');
  }

  async applyConflictTypeFilter(conflictType: string) {
    await this.page.selectOption('[data-testid="conflict-type-filter"]', conflictType);
  }

  async searchConflicts(searchTerm: string) {
    await this.page.fill('[data-testid="conflict-search-input"]', searchTerm);
    await this.page.click('[data-testid="search-btn"]');
  }

  async waitForResults() {
    await this.page.waitForSelector('[data-testid="conflict-results-table"]', { timeout: 3000 });
  }

  async getConflictRecords() {
    return await this.page.locator('[data-testid="conflict-record-row"]').all();
  }

  async exportReport(format: string) {
    await this.page.click('[data-testid="export-report-btn"]');
    await this.page.waitForSelector('[data-testid="export-format-modal"]');
    await this.page.click(`[data-testid="export-format-${format}"]`);
    await this.page.click('[data-testid="confirm-export-btn"]');
  }

  async waitForExportComplete() {
    await this.page.waitForSelector('[data-testid="export-success-message"]', { timeout: 5000 });
  }

  async getQueryResponseTime() {
    const startTime = Date.now();
    await this.waitForResults();
    return Date.now() - startTime;
  }
}

// Authentication Helper
class AuthHelper {
  constructor(private page: Page) {}

  async login(username: string, password: string) {
    await this.page.goto('/login', { waitUntil: 'networkidle' });
    await this.page.fill('[data-testid="username-input"]', username);
    await this.page.fill('[data-testid="password-input"]', password);
    await this.page.click('[data-testid="login-btn"]');
    await this.page.waitForURL('**/dashboard', { timeout: 10000 });
  }

  async logout() {
    await this.page.click('[data-testid="user-menu"]');
    await this.page.click('[data-testid="logout-btn"]');
    await this.page.waitForURL('**/login', { timeout: 5000 });
  }
}

test.describe('Story-14: As Scheduler, I want to view alternative time slots when conflicts occur to reschedule efficiently', () => {
  let schedulingPage: SchedulingPage;
  let authHelper: AuthHelper;

  test.beforeEach(async ({ page }) => {
    schedulingPage = new SchedulingPage(page);
    authHelper = new AuthHelper(page);
    
    // Login as scheduler
    await authHelper.login(testData.scheduler.username, testData.scheduler.password);
  });

  test.afterEach(async ({ page }) => {
    await authHelper.logout();
  });

  test('TC-14-01: System detects conflict and displays at least three alternative time slots', async ({ page }) => {
    // Step 1: Navigate to scheduling page
    await schedulingPage.navigate();
    await expect(page.locator('[data-testid="scheduling-container"]')).toBeVisible