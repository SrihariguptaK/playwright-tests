import { test, expect } from '@playwright/test';

test.describe('Story-11: Real-time Overlapping Appointment Detection', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    // Navigate to application and login as scheduler
    await page.goto(baseURL);
    await page.fill('[data-testid="username-input"]', 'scheduler@test.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate detection of overlapping appointments - happy path', async ({ page }) => {
    // Navigate to the appointment creation page
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Enter appointment details: Date: Today's date, Start time: 10:00 AM, End time: 11:00 AM
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date-input"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '10:00');
    await page.fill('[data-testid="appointment-end-time"]', '11:00');
    await page.selectOption('[data-testid="appointment-resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="appointment-client-input"]', 'Test Client 1');

    // Click 'Save' button to create the appointment
    await page.click('[data-testid="save-appointment-button"]');
    
    // Expected Result: Appointment is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Appointment created successfully');

    // Navigate to create a new appointment
    await page.click('[data-testid="create-appointment-button"]');
    await expect(page.locator('[data-testid="appointment-form"]')).toBeVisible();

    // Enter overlapping appointment details: Date: Today's date, Start time: 10:30 AM, End time: 11:30 AM
    await page.fill('[data-testid="appointment-date-input"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '10:30');
    await page.fill('[data-testid="appointment-end-time"]', '11:30');
    await page.selectOption('[data-testid="appointment-resource-select"]', 'Conference Room A');
    await page.fill('[data-testid="appointment-client-input"]', 'Test Client 2');

    // Click 'Save' button or tab out of the time field to trigger validation
    await page.click('[data-testid="appointment-end-time"]');
    await page.keyboard.press('Tab');
    
    // Wait for conflict detection (should be under 1 second)
    await page.waitForSelector('[data-testid="conflict-warning"]', { timeout: 1000 });
    
    // Expected Result: System detects conflict and flags overlapping appointment
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('overlapping');

    // Attempt to save overlapping appointment without providing override justification
    await page.click('[data-testid="save-appointment-button"]');
    
    // Expected Result: System prevents saving and displays conflict error
    await expect(page.locator('[data-testid="conflict-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-error"]')).toContainText('Cannot save appointment with conflicts');
    
    // Verify the conflicting appointment details are displayed
    await expect(page.locator('[data-testid="conflict-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-original-time"]')).toContainText('10:00');
    await expect(page.locator('[data-testid="conflict-original-time"]')).toContainText('11:00');
    await expect(page.locator('[data-testid="conflict-resource"]')).toContainText('Conference Room A');
    await expect(page.locator('[data-testid="conflict-client"]')).toContainText('Test Client 1');
  });

  test('Verify configurable conflict detection rules - happy path', async ({ page }) => {
    // Navigate to Settings > Conflict Detection Rules configuration page
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="conflict-detection-rules-link"]');
    await expect(page.locator('[data-testid="conflict-rules-page"]')).toBeVisible();

    // Click 'Add New Rule' button
    await page.click('[data-testid="add-new-rule-button"]');
    await expect(page.locator('[data-testid="rule-form"]')).toBeVisible();

    // Configure a new conflict rule
    await page.fill('[data-testid="rule-name-input"]', 'VIP Client Rule');
    await page.selectOption('[data-testid="appointment-type-select"]', 'VIP Consultation');
    await page.fill('[data-testid="overlap-allowed-input"]', '0');
    await page.selectOption('[data-testid="priority-select"]', 'High');
    await page.check('[data-testid="status-active-checkbox"]');

    // Click 'Save Rule' button
    await page.click('[data-testid="save-rule-button"]');
    
    // Expected Result: Rules are saved and active
    await expect(page.locator('[data-testid="rule-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="rule-list"]')).toContainText('VIP Client Rule');

    // Navigate to appointment creation page
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="create-appointment-button"]');

    // Create first appointment: Type: 'VIP Consultation', Date: Tomorrow, Time: 2:00 PM - 3:00 PM
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowDate = tomorrow.toISOString().split('T')[0];
    
    await page.selectOption('[data-testid="appointment-type-select"]', 'VIP Consultation');
    await page.fill('[data-testid="appointment-date-input"]', tomorrowDate);
    await page.fill('[data-testid="appointment-start-time"]', '14:00');
    await page.fill('[data-testid="appointment-end-time"]', '15:00');
    await page.selectOption('[data-testid="appointment-resource-select"]', 'Room 1');
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Create second appointment: Type: 'VIP Consultation', Date: Tomorrow, Time: 2:30 PM - 3:30 PM
    await page.click('[data-testid="create-appointment-button"]');
    await page.selectOption('[data-testid="appointment-type-select"]', 'VIP Consultation');
    await page.fill('[data-testid="appointment-date-input"]', tomorrowDate);
    await page.fill('[data-testid="appointment-start-time"]', '14:30');
    await page.fill('[data-testid="appointment-end-time"]', '15:30');
    await page.selectOption('[data-testid="appointment-resource-select"]', 'Room 1');
    await page.keyboard.press('Tab');
    
    // Expected Result: System applies rules and detects conflicts accordingly
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText('VIP Client Rule');

    // Navigate back to Conflict Detection Rules configuration
    await page.click('[data-testid="settings-menu"]');
    await page.click('[data-testid="conflict-detection-rules-link"]');

    // Modify 'VIP Client Rule': Change Overlap Allowed from 0 minutes to 15 minutes
    await page.click('[data-testid="edit-rule-VIP Client Rule"]');
    await page.fill('[data-testid="overlap-allowed-input"]', '15');
    await page.click('[data-testid="save-rule-button"]');
    await expect(page.locator('[data-testid="rule-success-message"]')).toBeVisible();

    // Return to appointment creation and attempt to create the same overlapping appointment
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="create-appointment-button"]');
    await page.selectOption('[data-testid="appointment-type-select"]', 'VIP Consultation');
    await page.fill('[data-testid="appointment-date-input"]', tomorrowDate);
    await page.fill('[data-testid="appointment-start-time"]', '14:30');
    await page.fill('[data-testid="appointment-end-time"]', '15:30');
    await page.selectOption('[data-testid="appointment-resource-select"]', 'Room 1');
    await page.keyboard.press('Tab');
    
    // Expected Result: System updates conflict detection based on new rules (15 min overlap allowed)
    // This should now be allowed since overlap is within 15 minutes
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Create a different overlapping appointment that exceeds 15 minutes
    await page.click('[data-testid="create-appointment-button"]');
    await page.selectOption('[data-testid="appointment-type-select"]', 'VIP Consultation');
    await page.fill('[data-testid="appointment-date-input"]', tomorrowDate);
    await page.fill('[data-testid="appointment-start-time"]', '14:50');
    await page.fill('[data-testid="appointment-end-time"]', '15:50');
    await page.selectOption('[data-testid="appointment-resource-select"]', 'Room 1');
    await page.keyboard.press('Tab');
    
    // This should trigger conflict as overlap exceeds 15 minutes
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible({ timeout: 1000 });
  });

  test('Ensure conflict detection latency is under 1 second - boundary', async ({ page, context }) => {
    // Open browser developer tools and navigate to Network tab to monitor API response times
    const cdpSession = await context.newCDPSession(page);
    await cdpSession.send('Network.enable');
    
    const apiResponseTimes: number[] = [];
    
    cdpSession.on('Network.responseReceived', (params) => {
      if (params.response.url.includes('/api/appointments') || params.response.url.includes('conflict')) {
        const timing = params.response.timing;
        if (timing) {
          const responseTime = timing.receiveHeadersEnd - timing.sendStart;
          apiResponseTimes.push(responseTime);
        }
      }
    });

    // Navigate to appointment creation page and create a baseline appointment
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="create-appointment-button"]');
    
    const today = new Date().toISOString().split('T')[0];
    await page.fill('[data-testid="appointment-date-input"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '15:00');
    await page.fill('[data-testid="appointment-end-time"]', '16:00');
    await page.selectOption('[data-testid="appointment-resource-select"]', 'Room A');
    await page.fill('[data-testid="appointment-client-input"]', 'Baseline Client');
    await page.click('[data-testid="save-appointment-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Start timer and create a conflicting appointment
    await page.click('[data-testid="create-appointment-button"]');
    await page.fill('[data-testid="appointment-date-input"]', today);
    await page.fill('[data-testid="appointment-start-time"]', '15:30');
    await page.fill('[data-testid="appointment-end-time"]', '16:30');
    await page.selectOption('[data-testid="appointment-resource-select"]', 'Room A');
    await page.fill('[data-testid="appointment-client-input"]', 'Conflict Client');
    
    // Measure the time from clicking 'Save' or tabbing out of time field until conflict warning appears
    const startTime = Date.now();
    await page.keyboard.press('Tab');
    await page.waitForSelector('[data-testid="conflict-warning"]', { timeout: 1000 });
    const detectionLatency = Date.now() - startTime;
    
    // Expected Result: System detects conflicts within 1 second
    expect(detectionLatency).toBeLessThan(1000);
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();

    // Update an existing appointment to create a conflict
    await page.click('[data-testid="appointments-menu"]');
    await page.click('[data-testid="appointment-list-link"]');
    await page.click('[data-testid="edit-appointment-15:00"]');
    
    const updateStartTime = Date.now();
    await page.fill('[data-testid="appointment-end-time"]', '17:00');
    await page.keyboard.press('Tab');
    await page.waitForSelector('[data-testid="conflict-warning"]', { timeout: 1000 });
    const updateLatency = Date.now() - updateStartTime;
    
    // Expected Result: Latency meets SLA requirements
    expect(updateLatency).toBeLessThan(1000);

    // Simulate high load: Open 5 browser tabs/windows with appointment creation forms
    const pages = [page];
    for (let i = 0; i < 4; i++) {
      const newPage = await context.newPage();
      await newPage.goto(baseURL);
      await newPage.fill('[data-testid="username-input"]', 'scheduler@test.com');
      await newPage.fill('[data-testid="password-input"]', 'password123');
      await newPage.click('[data-testid="login-button"]');
      await newPage.click('[data-testid="appointments-menu"]');
      await newPage.click('[data-testid="create-appointment-button"]');
      pages.push(newPage);
    }

    // Simultaneously create 5 appointments with overlapping times
    const appointmentTimes = [
      { start: '17:00', end: '18:00' },
      { start: '17:15', end: '18:15' },
      { start: '17:30', end: '18:30' },
      { start: '17:45', end: '18:45' },
      { start: '17:50', end: '18:50' }
    ];

    const concurrentLatencies: number[] = [];
    
    // Create all appointments concurrently
    await Promise.all(pages.map(async (p, index) => {
      await p.fill('[data-testid="appointment-date-input"]', today);
      await p.fill('[data-testid="appointment-start-time"]', appointmentTimes[index].start);
      await p.fill('[data-testid="appointment-end-time"]', appointmentTimes[index].end);
      await p.selectOption('[data-testid="appointment-resource-select"]', 'Room B');
      await p.fill('[data-testid="appointment-client-input"]', `Concurrent Client ${index + 1}`);
      
      const concurrentStartTime = Date.now();
      await p.keyboard.press('Tab');
      
      if (index > 0) {
        await p.waitForSelector('[data-testid="conflict-warning"]', { timeout: 1000 });
        const concurrentLatency = Date.now() - concurrentStartTime;
        concurrentLatencies.push(concurrentLatency);
      }
    }));

    // Expected Result: System maintains detection latency under 1 second even under high load
    concurrentLatencies.forEach((latency, index) => {
      expect(latency).toBeLessThan(1000);
    });

    // Verify all concurrent requests met the latency requirement
    const maxLatency = Math.max(...concurrentLatencies);
    expect(maxLatency).toBeLessThan(1000);
    
    // Close additional pages
    for (let i = 1; i < pages.length; i++) {
      await pages[i].close();
    }
  });
});