```typescript
import { test, expect, Page } from '@playwright/test';
import { chromium, Browser, BrowserContext } from '@playwright/test';

// Test Data Fixtures
const testData = {
  scheduler: {
    email: 'scheduler@example.com',
    password: 'SecurePass123!',
    name: 'John Scheduler'
  },
  conflicts: {
    conflict1: {
      id: 'conflict-001',
      type: 'Double Booking',
      resource: 'Conference Room A',
      timeSlot: '2024-01-15 14:00-15:00',
      description: 'Room booked for two meetings simultaneously'
    },
    conflict2: {
      id: 'conflict-002',
      type: 'Resource Unavailable',
      resource: 'Projector #5',
      timeSlot: '2024-01-16 10:00-11:00',
      description: 'Equipment scheduled during maintenance window'
    }
  },
  alerts: {
    alert1: {
      id: 'alert-001',
      title: 'Scheduling Conflict Detected',
      message: 'Double booking detected for Conference Room A',
      severity: 'high',
      timestamp: new Date().toISOString()
    },
    alert2: {
      id: 'alert-002',
      title: 'Resource Conflict',
      message: 'Projector #5 unavailable during requested time',
      severity: 'medium',
      timestamp: new Date().toISOString()
    }
  },
  apiEndpoints: {
    login: '/api/auth/login',
    sendAlert: '/api/alerts/send',
    acknowledgeAlert: '/api/alerts/acknowledge',
    dismissAlert: '/api/alerts/dismiss',
    getAlerts: '/api/alerts'
  }
};

// Page Object Model - Login Page
class LoginPage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/login', { waitUntil: 'networkidle' });
  }

  async login(email: string, password: string) {
    await this.page.fill('[data-testid="email-input"]', email);
    await this.page.fill('[data-testid="password-input"]', password);
    await this.page.click('[data-testid="login-button"]');
    await this.page.waitForNavigation({ waitUntil: 'networkidle' });
  }

  async isLoggedIn(): Promise<boolean> {
    try {
      await this.page.waitForSelector('[data-testid="dashboard"]', { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }
}

// Page Object Model - Alert Management Page
class AlertManagementPage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/alerts', { waitUntil: 'networkidle' });
  }

  async waitForAlert(alertId: string, timeout: number = 5000) {
    await this.page.waitForSelector(`[data-testid="alert-${alertId}"]`, { timeout });
  }

  async getAlertCount(): Promise<number> {
    const alerts = await this.page.locator('[data-testid^="alert-"]').count();
    return alerts;
  }

  async getAlertById(alertId: string) {
    return this.page.locator(`[data-testid="alert-${alertId}"]`);
  }

  async acknowledgeAlert(alertId: string) {
    const alert = await this.getAlertById(alertId);
    await alert.locator('[data-testid="acknowledge-button"]').click();
  }

  async dismissAlert(alertId: string) {
    const alert = await this.getAlertById(alertId);
    await alert.locator('[data-testid="dismiss-button"]').click();
  }

  async getAlertStatus(alertId: string): Promise<string> {
    const alert = await this.getAlertById(alertId);
    const statusElement = alert.locator('[data-testid="alert-status"]');
    return await statusElement.textContent() || '';
  }

  async isAlertVisible(alertId: string): Promise<boolean> {
    try {
      await this.page.waitForSelector(`[data-testid="alert-${alertId}"]`, { timeout: 2000 });
      return true;
    } catch {
      return false;
    }
  }

  async getInAppNotificationCount(): Promise<number> {
    const notificationBadge = this.page.locator('[data-testid="notification-badge"]');
    const count = await notificationBadge.textContent();
    return parseInt(count || '0');
  }

  async openNotificationPanel() {
    await this.page.click('[data-testid="notification-icon"]');
    await this.page.waitForSelector('[data-testid="notification-panel"]', { state: 'visible' });
  }

  async getNotificationInPanel(alertId: string) {
    return this.page.locator(`[data-testid="notification-panel"] [data-testid="notification-${alertId}"]`);
  }

  async waitForUIUpdate(timeout: number = 1000) {
    await this.page.waitForTimeout(timeout);
  }
}

// Page Object Model - Email Verification Helper
class EmailVerificationHelper {
  constructor(private page: Page) {}

  async checkEmailReceived(recipientEmail: string, subject: string): Promise<boolean> {
    // Simulate checking email via test email API or mock service
    const response = await this.page.request.get('/api/test/emails', {
      params: {
        recipient: recipientEmail,
        subject: subject
      }
    });
    
    if (response.ok()) {
      const emails = await response.json();
      return emails.length > 0;
    }
    return false;
  }

  async getLatestEmail(recipientEmail: string) {
    const response = await this.page.request.get('/api/test/emails/latest', {
      params: {
        recipient: recipientEmail
      }
    });
    
    if (response.ok()) {
      return await response.json();
    }
    return null;
  }
}

// Helper function to create a scheduling conflict via API
async function createSchedulingConflict(page: Page, conflictData: any) {
  const response = await page.request.post('/api/test/conflicts/create', {
    data: conflictData
  });
  
  expect(response.ok()).toBeTruthy();
  return await response.json();
}

// Helper function to measure alert delivery latency
async function measureAlertLatency(startTime: number, endTime: number): number {
  return endTime - startTime;
}

// Story 13: Immediate Alerts for Scheduling Conflicts
test.describe('Story-13: As Scheduler, I want to receive immediate alerts when scheduling conflicts occur to take prompt action', () => {
  let loginPage: LoginPage;
  let alertPage: AlertManagementPage;
  let emailHelper: EmailVerificationHelper;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    alertPage = new AlertManagementPage(page);
    emailHelper = new EmailVerificationHelper(page);

    // Login as scheduler
    await loginPage.navigate();
    await loginPage.login(testData.scheduler.email, testData.scheduler.password);
    
    const isLoggedIn = await loginPage.isLoggedIn();
    expect(isLoggedIn).toBeTruthy();
  });

  test('TC-13.1: System generates and delivers in-app alert immediately upon conflict detection', async ({ page }) => {
    // Navigate to alerts page
    await alertPage.navigate();
    
    // Record start time for latency measurement
    const startTime = Date.now();
    
    // Create a scheduling conflict via API to trigger alert
    const conflict = await createSchedulingConflict(page, testData.conflicts.conflict1);
    
    // Wait for in-app notification to appear
    await alertPage.waitForAlert(