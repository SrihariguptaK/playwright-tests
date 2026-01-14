import { test, expect, Page } from '@playwright/test';
import { WebSocket } from 'ws';

// Test Data Fixtures
const testData = {
  employee: {
    username: 'john.doe@company.com',
    password: 'Test@1234',
    employeeId: 'EMP001',
    name: 'John Doe'
  },
  scheduleChanges: {
    newShift: {
      id: 'SHIFT001',
      date: '2024-02-15',
      startTime: '09:00',
      endTime: '17:00',
      location: 'Main Office',
      type: 'new'
    },
    modifiedShift: {
      id: 'SHIFT002',
      date: '2024-02-16',
      startTime: '10:00',
      endTime: '18:00',
      location: 'Branch Office',
      type: 'modified',
      previousStartTime: '09:00',
      previousEndTime: '17:00'
    },
    canceledShift: {
      id: 'SHIFT003',
      date: '2024-02-17',
      startTime: '08:00',
      endTime: '16:00',
      location: 'Remote',
      type: 'canceled'
    }
  }
};

// Page Object Model - Login Page
class LoginPage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/login', { waitUntil: 'networkidle' });
  }

  async login(username: string, password: string) {
    await this.page.fill('[data-testid="username-input"]', username);
    await this.page.fill('[data-testid="password-input"]', password);
    await this.page.click('[data-testid="login-button"]');
    await this.page.waitForURL('**/dashboard', { timeout: 10000 });
  }
}

// Page Object Model - Schedule Page
class SchedulePage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.click('[data-testid="schedule-nav-link"]');
    await this.page.waitForURL('**/schedule', { timeout: 10000 });
    await this.page.waitForSelector('[data-testid="schedule-container"]', { state: 'visible' });
  }

  async waitForNotificationPopup(timeout: number = 10000) {
    await this.page.waitForSelector('[data-testid="notification-popup"]', { 
      state: 'visible',
      timeout 
    });
  }

  async waitForNotificationBanner(timeout: number = 10000) {
    await this.page.waitForSelector('[data-testid="notification-banner"]', { 
      state: 'visible',
      timeout 
    });
  }

  async getNotificationCount(): Promise<number> {
    const badge = await this.page.locator('[data-testid="notification-badge"]');
    if (await badge.isVisible()) {
      const count = await badge.textContent();
      return parseInt(count || '0', 10);
    }
    return 0;
  }

  async getNotificationDetails() {
    const notification = this.page.locator('[data-testid="notification-popup"]').first();
    const title = await notification.locator('[data-testid="notification-title"]').textContent();
    const message = await notification.locator('[data-testid="notification-message"]').textContent();
    const timestamp = await notification.locator('[data-testid="notification-timestamp"]').textContent();
    const type = await notification.getAttribute('data-notification-type');
    
    return { title, message, timestamp, type };
  }

  async acknowledgeNotification() {
    await this.page.click('[data-testid="acknowledge-notification-button"]');
    await this.page.waitForSelector('[data-testid="notification-acknowledged"]', { 
      state: 'visible',
      timeout: 5000 
    });
  }

  async openNotificationHistory() {
    await this.page.click('[data-testid="notification-history-button"]');
    await this.page.waitForSelector('[data-testid="notification-history-panel"]', { 
      state: 'visible',
      timeout: 5000 
    });
  }

  async getNotificationHistoryItems() {
    const items = await this.page.locator('[data-testid="notification-history-item"]').all();
    const historyData = [];
    
    for (const item of items) {
      const title = await item.locator('[data-testid="history-item-title"]').textContent();
      const message = await item.locator('[data-testid="history-item-message"]').textContent();
      const timestamp = await item.locator('[data-testid="history-item-timestamp"]').textContent();
      const status = await item.getAttribute('data-status');
      
      historyData.push({ title, message, timestamp, status });
    }
    
    return historyData;
  }

  async closeNotification() {
    await this.page.click('[data-testid="close-notification-button"]');
  }
}

// Helper Functions
async function triggerScheduleChange(page: Page, changeType: string, shiftData: any) {
  // Simulate schedule change via API call
  const response = await page.request.post('/api/schedule/change', {
    data: {
      employeeId: testData.employee.employeeId,
      changeType: changeType,
      shiftDetails: shiftData,
      timestamp: new Date().toISOString()
    },
    headers: {
      'Content-Type': 'application/json'
    }
  });
  
  expect(response.ok()).toBeTruthy();
  return response;
}

async function waitForWebSocketNotification(page: Page, timeout: number = 300000) {
  // Wait for WebSocket connection and notification
  return page.waitForResponse(
    response => response.url().includes('/api/notifications') && response.status() === 200,
    { timeout }
  );
}

async function verifyNotificationDeliveryTime(triggerTime: Date, deliveryTime: Date): Promise<boolean> {
  const timeDifferenceMs = deliveryTime.getTime() - triggerTime.getTime();
  const timeDifferenceMinutes = timeDifferenceMs / 1000 / 60;
  return timeDifferenceMinutes <= 5;
}

// Test Suite
test.describe('Story-35: As Employee, I want to receive notifications about schedule changes to stay informed', () => {
  
  let loginPage: LoginPage;
  let schedulePage: SchedulePage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    schedulePage = new SchedulePage(page);
    
    // Login before each test
    await loginPage.navigate();
    await loginPage.login(testData.employee.username, testData.employee.password);
    
    // Navigate to schedule section
    await schedulePage.navigate();
  });

  test('TC001: Employee receives notification for new shift within 5 minutes', async ({ page }) => {
    // Record the time when schedule change is triggered
    const triggerTime = new Date();
    
    // Trigger a new shift schedule change
    await triggerScheduleChange(page, 'new', testData.scheduleChanges.newShift);
    
    // Wait for notification to appear
    await schedulePage.waitForNotificationPopup(300000); // 5 minutes timeout
    
    const deliveryTime = new Date();
    
    // Verify notification was delivered within 5 minutes
    const isWithinTimeLimit = await verifyNotificationDeliveryTime(triggerTime, deliveryTime);
    expect(isWithinTimeLimit).toBeTruthy();
    
    // Verify notification is visible
    const notificationPopup = page.locator('[data-testid="notification-popup"]');
    await expect(notificationPopup).toBeVisible();
    
    // Verify notification count badge is updated
    const notificationCount = await schedulePage.getNotificationCount();
    expect(not