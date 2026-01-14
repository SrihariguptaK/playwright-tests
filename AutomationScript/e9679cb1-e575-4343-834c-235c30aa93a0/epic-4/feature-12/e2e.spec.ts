```typescript
import { test, expect, Page } from '@playwright/test';
import { WebSocket } from 'ws';

// Test Data Fixtures
const testData = {
  admin: {
    username: 'admin@company.com',
    password: 'Admin@123'
  },
  employee: {
    username: 'employee@company.com',
    password: 'Employee@123',
    employeeId: 'EMP001',
    name: 'John Doe'
  },
  scheduleChange: {
    originalShift: {
      date: '2024-02-15',
      startTime: '09:00',
      endTime: '17:00',
      location: 'Office A'
    },
    updatedShift: {
      date: '2024-02-15',
      startTime: '10:00',
      endTime: '18:00',
      location: 'Office B'
    }
  }
};

// Page Object Model - Admin Schedule Page
class AdminSchedulePage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/admin/schedules');
    await this.page.waitForLoadState('networkidle');
  }

  async login(username: string, password: string) {
    await this.page.goto('/login');
    await this.page.fill('[data-testid="username-input"]', username);
    await this.page.fill('[data-testid="password-input"]', password);
    await this.page.click('[data-testid="login-button"]');
    await this.page.waitForURL('**/admin/**', { timeout: 10000 });
  }

  async searchEmployee(employeeId: string) {
    await this.page.fill('[data-testid="employee-search"]', employeeId);
    await this.page.click('[data-testid="search-button"]');
    await this.page.waitForSelector(`[data-employee-id="${employeeId}"]`, { timeout: 5000 });
  }

  async updateSchedule(employeeId: string, newSchedule: any) {
    await this.page.click(`[data-employee-id="${employeeId}"] [data-testid="edit-schedule-button"]`);
    await this.page.waitForSelector('[data-testid="schedule-modal"]');
    
    await this.page.fill('[data-testid="start-time-input"]', newSchedule.startTime);
    await this.page.fill('[data-testid="end-time-input"]', newSchedule.endTime);
    await this.page.fill('[data-testid="location-input"]', newSchedule.location);
    
    await this.page.click('[data-testid="save-schedule-button"]');
    await this.page.waitForSelector('[data-testid="success-message"]', { timeout: 5000 });
  }
}

// Page Object Model - Employee Notification Page
class EmployeeNotificationPage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/employee/dashboard');
    await this.page.waitForLoadState('networkidle');
  }

  async login(username: string, password: string) {
    await this.page.goto('/login');
    await this.page.fill('[data-testid="username-input"]', username);
    await this.page.fill('[data-testid="password-input"]', password);
    await this.page.click('[data-testid="login-button"]');
    await this.page.waitForURL('**/employee/**', { timeout: 10000 });
  }

  async waitForNotification(timeout: number = 60000) {
    await this.page.waitForSelector('[data-testid="notification-badge"]', { timeout });
  }

  async getNotificationCount(): Promise<number> {
    const badge = await this.page.locator('[data-testid="notification-badge"]');
    const count = await badge.textContent();
    return parseInt(count || '0', 10);
  }

  async openNotificationPanel() {
    await this.page.click('[data-testid="notification-icon"]');
    await this.page.waitForSelector('[data-testid="notification-panel"]', { state: 'visible' });
  }

  async getLatestNotification() {
    const notifications = await this.page.locator('[data-testid="notification-item"]').all();
    if (notifications.length === 0) {
      throw new Error('No notifications found');
    }
    return notifications[0];
  }

  async getNotificationText(notification: any): Promise<string> {
    return await notification.locator('[data-testid="notification-message"]').textContent();
  }

  async getNotificationTimestamp(notification: any): Promise<string> {
    return await notification.locator('[data-testid="notification-timestamp"]').textContent();
  }

  async acknowledgeNotification(notification: any) {
    await notification.locator('[data-testid="acknowledge-button"]').click();
    await this.page.waitForTimeout(500);
  }

  async isNotificationRead(notification: any): Promise<boolean> {
    const classes = await notification.getAttribute('class');
    return classes?.includes('read') || false;
  }

  async viewNotificationHistory() {
    await this.page.click('[data-testid="view-all-notifications"]');
    await this.page.waitForSelector('[data-testid="notification-history-page"]');
  }

  async getNotificationHistoryCount(): Promise<number> {
    const items = await this.page.locator('[data-testid="history-notification-item"]').all();
    return items.length;
  }

  async filterNotificationsByType(type: string) {
    await this.page.selectOption('[data-testid="notification-type-filter"]', type);
    await this.page.waitForTimeout(1000);
  }
}

// Helper Functions
class NotificationHelper {
  static async setupWebSocketListener(page: Page): Promise<any[]> {
    const notifications: any[] = [];
    
    await page.evaluate(() => {
      (window as any).capturedNotifications = [];
      const originalWebSocket = (window as any).WebSocket;
      
      (window as any).WebSocket = function(url: string, protocols?: string | string[]) {
        const ws = new originalWebSocket(url, protocols);
        
        ws.addEventListener('message', (event: MessageEvent) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'schedule_change') {
              (window as any).capturedNotifications.push({
                data: data,
                timestamp: new Date().toISOString()
              });
            }
          } catch (e) {
            console.error('Failed to parse WebSocket message', e);
          }
        });
        
        return ws;
      };
    });
    
    return notifications;
  }

  static async getCapturedNotifications(page: Page): Promise<any[]> {
    return await page.evaluate(() => {
      return (window as any).capturedNotifications || [];
    });
  }

  static calculateDeliveryTime(scheduleUpdateTime: Date, notificationReceivedTime: Date): number {
    return (notificationReceivedTime.getTime() - scheduleUpdateTime.getTime()) / 1000;
  }
}

// Test Suite
test.describe('Story-34: As Employee, I want to receive notifications of schedule changes to stay informed', () => {
  
  test.describe('Real-time Notification Delivery', () => {
    
    test('should send real-time notification to employee when admin updates schedule', async ({ page, context }) => {
      // Setup: Create two browser contexts - one for admin, one for employee
      const adminPage = page;
      const employeePage = await context.newPage();
      
      const adminSchedulePage = new AdminSchedulePage(adminPage);
      const employeeNotificationPage = new EmployeeNotificationPage(employeePage);
      
      try {
        // Step 1: Employee logs in and navigates to dashboard
        await employeeNotificationPage.login(testData.employee.username, testData.employee.password);