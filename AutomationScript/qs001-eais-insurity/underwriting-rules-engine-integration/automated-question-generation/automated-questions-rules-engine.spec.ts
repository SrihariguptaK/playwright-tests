import { test, expect } from '@playwright/test';

test.describe('Story-23: Automated Questions from Rules Engine', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const testApplication = {
    applicantName: 'John Doe',
    applicationId: `APP-${Date.now()}`,
    businessType: 'Manufacturing',
    coverageAmount: '1000000'
  };
  const analystCredentials = {
    username: 'analyst@underwriting.com',
    password: 'AnalystPass123!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Validate automated question generation and delivery', async ({ page }) => {
    // Step 1: Submit application triggering question generation
    await page.goto(`${baseURL}/applications/submit`);
    await page.fill('[data-testid="applicant-name"]', testApplication.applicantName);
    await page.fill('[data-testid="business-type"]', testApplication.businessType);
    await page.fill('[data-testid="coverage-amount"]', testApplication.coverageAmount);
    
    // Select options that trigger rules engine questions
    await page.selectOption('[data-testid="risk-category"]', 'high-risk');
    await page.check('[data-testid="hazardous-materials"]');
    
    await page.click('[data-testid="submit-application-btn"]');
    
    // Expected Result: System receives questions from rules engine
    await expect(page.locator('[data-testid="submission-success"]')).toBeVisible({ timeout: 5000 });
    const applicationId = await page.locator('[data-testid="application-id"]').textContent();
    expect(applicationId).toBeTruthy();
    
    // Wait for rules engine processing
    await page.waitForTimeout(3000);
    
    // Step 2: Underwriting analyst accesses question list
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', analystCredentials.username);
    await page.fill('[data-testid="password-input"]', analystCredentials.password);
    await page.click('[data-testid="login-btn"]');
    
    // Expected Result: Login successful
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 5000 });
    
    // Navigate to question management interface
    await page.click('[data-testid="questions-menu"]');
    await page.waitForURL('**/questions');
    
    // Expected Result: Generated questions are visible and actionable
    await expect(page.locator('[data-testid="questions-list"]')).toBeVisible();
    
    // Filter or search for the specific application
    await page.fill('[data-testid="search-application"]', applicationId || testApplication.applicantName);
    await page.click('[data-testid="search-btn"]');
    
    const questionItems = page.locator('[data-testid="question-item"]');
    await expect(questionItems.first()).toBeVisible({ timeout: 5000 });
    
    // Verify questions are actionable
    const firstQuestion = questionItems.first();
    await expect(firstQuestion.locator('[data-testid="response-input"]')).toBeVisible();
    await expect(firstQuestion.locator('[data-testid="submit-response-btn"]')).toBeVisible();
    
    // Step 3: Analyst submits responses
    const questionCount = await questionItems.count();
    
    for (let i = 0; i < questionCount; i++) {
      const question = questionItems.nth(i);
      const questionText = await question.locator('[data-testid="question-text"]').textContent();
      
      // Enter valid response based on question type
      const responseInput = question.locator('[data-testid="response-input"]');
      const inputType = await responseInput.getAttribute('type');
      
      if (inputType === 'textarea' || !inputType) {
        await responseInput.fill(`Response to: ${questionText}. All safety protocols are in place.`);
      } else if (inputType === 'checkbox') {
        await responseInput.check();
      } else {
        await responseInput.fill('Yes');
      }
      
      // Submit response
      await question.locator('[data-testid="submit-response-btn"]').click();
      
      // Verify response submitted successfully
      await expect(question.locator('[data-testid="response-submitted"]')).toBeVisible({ timeout: 3000 });
    }
    
    // Expected Result: Application status updates accordingly
    await page.click('[data-testid="applications-menu"]');
    await page.fill('[data-testid="search-application"]', applicationId || testApplication.applicantName);
    await page.click('[data-testid="search-btn"]');
    
    const applicationRow = page.locator('[data-testid="application-row"]').first();
    await applicationRow.click();
    
    // Verify application details page
    await expect(page.locator('[data-testid="application-details"]')).toBeVisible();
    
    // Verify status has been updated
    const statusElement = page.locator('[data-testid="application-status"]');
    const status = await statusElement.textContent();
    expect(status).toMatch(/Questions Answered|Under Review|In Progress/);
    
    // Verify response data is stored
    await page.click('[data-testid="view-responses-tab"]');
    const responses = page.locator('[data-testid="response-item"]');
    await expect(responses.first()).toBeVisible();
    expect(await responses.count()).toBeGreaterThan(0);
  });

  test('Verify notification alerts for new questions', async ({ page }) => {
    // Step 1: Ensure analyst is logged in with notifications enabled
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', analystCredentials.username);
    await page.fill('[data-testid="password-input"]', analystCredentials.password);
    await page.click('[data-testid="login-btn"]');
    
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible({ timeout: 5000 });
    
    // Verify notifications are enabled
    await page.click('[data-testid="user-profile-menu"]');
    await page.click('[data-testid="settings-option"]');
    
    const notificationToggle = page.locator('[data-testid="notification-toggle"]');
    const isEnabled = await notificationToggle.isChecked();
    if (!isEnabled) {
      await notificationToggle.check();
      await page.click('[data-testid="save-settings-btn"]');
    }
    
    await page.goto(`${baseURL}/dashboard`);
    
    // Step 2: Trigger question generation
    // Open new tab/window to submit application or use admin tools
    const adminPage = await page.context().newPage();
    await adminPage.goto(`${baseURL}/admin/generate-questions`);
    
    // Login as admin if needed
    if (await adminPage.locator('[data-testid="login-btn"]').isVisible()) {
      await adminPage.fill('[data-testid="username-input"]', 'admin@underwriting.com');
      await adminPage.fill('[data-testid="password-input"]', 'AdminPass123!');
      await adminPage.click('[data-testid="login-btn"]');
    }
    
    // Generate questions for the analyst
    await adminPage.fill('[data-testid="assign-to-analyst"]', analystCredentials.username);
    await adminPage.fill('[data-testid="application-reference"]', testApplication.applicationId);
    await adminPage.click('[data-testid="generate-questions-btn"]');
    
    // Expected Result: Notification alert is sent
    await expect(adminPage.locator('[data-testid="generation-success"]')).toBeVisible({ timeout: 5000 });
    
    await adminPage.close();
    
    // Step 3: Observe notification system for alert delivery
    // Wait for notification to appear
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    await expect(notificationBadge).toBeVisible({ timeout: 10000 });
    
    // Verify notification count increased
    const badgeCount = await notificationBadge.textContent();
    expect(parseInt(badgeCount || '0')).toBeGreaterThan(0);
    
    // Step 4: Verify notification content
    await page.click('[data-testid="notification-icon"]');
    
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    await expect(notificationPanel).toBeVisible();
    
    const latestNotification = notificationPanel.locator('[data-testid="notification-item"]').first();
    await expect(latestNotification).toBeVisible();
    
    // Expected Result: Notification content includes relevant information
    const notificationText = await latestNotification.locator('[data-testid="notification-message"]').textContent();
    expect(notificationText).toContain('question');
    expect(notificationText?.toLowerCase()).toMatch(/new|assigned|pending/);
    
    // Verify notification has application reference
    const notificationDetails = await latestNotification.locator('[data-testid="notification-details"]').textContent();
    expect(notificationDetails).toBeTruthy();
    
    // Step 5: Click notification to view details
    await latestNotification.click();
    
    // Expected Result: Notification is cleared upon viewing
    await page.waitForTimeout(1000);
    
    // Verify redirected to questions page
    await expect(page).toHaveURL(/.*questions.*/);
    
    // Step 6: Check notification status
    await page.click('[data-testid="notification-icon"]');
    
    const viewedNotification = notificationPanel.locator('[data-testid="notification-item"]').first();
    
    // Verify notification is marked as read
    await expect(viewedNotification).toHaveAttribute('data-status', 'read');
    
    // Or verify badge count decreased
    const updatedBadgeCount = await notificationBadge.textContent();
    expect(parseInt(updatedBadgeCount || '0')).toBeLessThanOrEqual(parseInt(badgeCount || '1'));
    
    // Step 7: Verify notification history
    await page.click('[data-testid="view-all-notifications"]');
    await expect(page).toHaveURL(/.*notifications.*/);
    
    // Expected Result: Notification record is maintained in history
    const notificationHistory = page.locator('[data-testid="notification-history-list"]');
    await expect(notificationHistory).toBeVisible();
    
    const historyItems = notificationHistory.locator('[data-testid="history-item"]');
    await expect(historyItems.first()).toBeVisible();
    
    // Verify the notification we just viewed is in history
    const firstHistoryItem = historyItems.first();
    const historyText = await firstHistoryItem.locator('[data-testid="history-message"]').textContent();
    expect(historyText).toContain('question');
    
    // Verify timestamp is recorded
    const timestamp = await firstHistoryItem.locator('[data-testid="notification-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
  });
});