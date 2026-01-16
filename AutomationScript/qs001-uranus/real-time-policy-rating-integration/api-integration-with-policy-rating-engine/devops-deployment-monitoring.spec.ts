import { test, expect } from '@playwright/test';

test.describe('DevOps Deployment and Monitoring - Story 18', () => {
  const CI_CD_DASHBOARD_URL = process.env.CI_CD_DASHBOARD_URL || 'https://cicd.example.com/dashboard';
  const MONITORING_DASHBOARD_URL = process.env.MONITORING_DASHBOARD_URL || 'https://monitoring.example.com/dashboard';
  const API_ENDPOINT_URL = process.env.API_ENDPOINT_URL || 'https://api.example.com/rating-engine';
  
  test.beforeEach(async ({ page }) => {
    // Set longer timeout for deployment operations
    test.setTimeout(300000);
  });

  test('Validate automated deployment pipeline - happy path', async ({ page }) => {
    // Step 1: Access the CI/CD pipeline interface and trigger deployment
    await page.goto(CI_CD_DASHBOARD_URL);
    await expect(page.locator('[data-testid="cicd-dashboard"]')).toBeVisible();
    
    // Navigate to rating integration pipeline
    await page.click('[data-testid="pipelines-menu"]');
    await page.click('text=Rating Integration Components');
    await expect(page.locator('[data-testid="pipeline-details"]')).toBeVisible();
    
    // Trigger deployment pipeline
    await page.click('[data-testid="trigger-deployment-btn"]');
    await expect(page.locator('[data-testid="deployment-started-notification"]')).toBeVisible();
    
    // Step 2: Monitor pipeline execution stages
    await page.waitForSelector('[data-testid="build-stage"]', { state: 'visible', timeout: 60000 });
    await expect(page.locator('[data-testid="build-stage-status"]')).toContainText('Running');
    
    // Wait for build stage completion
    await page.waitForSelector('[data-testid="build-stage-status"]:has-text("Completed")', { timeout: 120000 });
    await expect(page.locator('[data-testid="build-stage-status"]')).toContainText('Completed');
    
    // Monitor test stage
    await expect(page.locator('[data-testid="test-stage-status"]')).toContainText('Running');
    await page.waitForSelector('[data-testid="test-stage-status"]:has-text("Completed")', { timeout: 120000 });
    await expect(page.locator('[data-testid="test-stage-status"]')).toContainText('Completed');
    
    // Monitor deploy stage
    await expect(page.locator('[data-testid="deploy-stage-status"]')).toContainText('Running');
    await page.waitForSelector('[data-testid="deploy-stage-status"]:has-text("Completed")', { timeout: 120000 });
    await expect(page.locator('[data-testid="deploy-stage-status"]')).toContainText('Completed');
    
    // Expected Result: Integration components deployed without errors
    await expect(page.locator('[data-testid="deployment-status"]')).toContainText('Success');
    await expect(page.locator('[data-testid="deployment-errors"]')).toHaveCount(0);
    
    // Step 3: Verify integration components deployed to target environment
    await page.click('[data-testid="deployment-details-tab"]');
    await expect(page.locator('[data-testid="target-environment"]')).toContainText('Production');
    await expect(page.locator('[data-testid="deployed-components"]')).toContainText('rating-integration-api');
    await expect(page.locator('[data-testid="deployed-components"]')).toContainText('rating-engine-connector');
    
    // Step 4: Test system functionality by sending test API request
    await page.click('[data-testid="test-deployment-btn"]');
    await page.fill('[data-testid="test-request-endpoint"]', '/api/rating/quote');
    await page.fill('[data-testid="test-request-payload"]', '{"quoteId": "TEST-12345", "product": "auto-insurance"}');
    await page.click('[data-testid="send-test-request-btn"]');
    
    // Expected Result: All services operational
    await page.waitForSelector('[data-testid="test-response"]', { state: 'visible', timeout: 30000 });
    await expect(page.locator('[data-testid="test-response-status"]')).toContainText('200');
    await expect(page.locator('[data-testid="test-response-body"]')).toContainText('ratingResult');
    
    // Step 5: Verify all integration services operational by checking service status
    await page.click('[data-testid="service-status-tab"]');
    await expect(page.locator('[data-testid="rating-api-status"]')).toContainText('Healthy');
    await expect(page.locator('[data-testid="connector-status"]')).toContainText('Healthy');
    await expect(page.locator('[data-testid="database-connection-status"]')).toContainText('Healthy');
    
    // Step 6: Access deployment logs
    await page.click('[data-testid="deployment-logs-tab"]');
    await expect(page.locator('[data-testid="deployment-logs-container"]')).toBeVisible();
    
    // Expected Result: Deployment steps logged successfully
    const logsContent = await page.locator('[data-testid="deployment-logs-content"]').textContent();
    expect(logsContent).toContain('Starting deployment pipeline');
    expect(logsContent).toContain('Build stage completed successfully');
    expect(logsContent).toContain('Test stage completed successfully');
    expect(logsContent).toContain('Deploy stage completed successfully');
    expect(logsContent).toContain('Deployment completed without errors');
    
    // Step 7: Verify deployment artifacts and configurations
    await page.click('[data-testid="artifacts-tab"]');
    await expect(page.locator('[data-testid="artifact-list"]')).toContainText('rating-integration-api.jar');
    await expect(page.locator('[data-testid="artifact-list"]')).toContainText('application.properties');
    await expect(page.locator('[data-testid="artifact-list"]')).toContainText('deployment-config.yaml');
    
    await page.click('[data-testid="configurations-tab"]');
    await expect(page.locator('[data-testid="config-target-directory"]')).toContainText('/opt/rating-integration');
    await expect(page.locator('[data-testid="config-status"]')).toContainText('Applied');
  });

  test('Test monitoring alert on API failure - error case', async ({ page }) => {
    // Step 1: Document current healthy status of API endpoint
    await page.goto(MONITORING_DASHBOARD_URL);
    await expect(page.locator('[data-testid="monitoring-dashboard"]')).toBeVisible();
    
    // Navigate to rating engine API monitoring
    await page.click('[data-testid="services-menu"]');
    await page.click('text=Rating Engine API');
    await expect(page.locator('[data-testid="service-monitoring-details"]')).toBeVisible();
    
    // Verify current healthy status
    await expect(page.locator('[data-testid="api-endpoint-status"]')).toContainText('Healthy');
    await expect(page.locator('[data-testid="health-check-indicator"]')).toHaveClass(/status-healthy/);
    const initialTimestamp = await page.locator('[data-testid="last-check-timestamp"]').textContent();
    
    // Step 2: Simulate API endpoint failure
    await page.click('[data-testid="admin-actions-menu"]');
    await page.click('[data-testid="simulate-failure-option"]');
    await page.selectOption('[data-testid="failure-type-select"]', 'service-down');
    await page.click('[data-testid="apply-simulation-btn"]');
    
    // Expected Result: Health check detects failure
    await expect(page.locator('[data-testid="simulation-active-banner"]')).toBeVisible();
    await expect(page.locator('[data-testid="simulation-active-banner"]')).toContainText('API failure simulation active');
    
    // Step 3: Wait for health check monitoring cycle (1-2 minutes)
    await page.waitForTimeout(30000); // Wait 30 seconds for first check
    await page.click('[data-testid="refresh-status-btn"]');
    
    // Step 4: Monitor dashboard for status change
    await page.waitForSelector('[data-testid="api-endpoint-status"]:has-text("Unhealthy")', { timeout: 90000 });
    await expect(page.locator('[data-testid="api-endpoint-status"]')).toContainText('Unhealthy');
    await expect(page.locator('[data-testid="health-check-indicator"]')).toHaveClass(/status-unhealthy/);
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Connection refused');
    
    // Step 5: Check alert notification channels
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="recent-alerts-tab"]');
    
    // Expected Result: Alert received within 5 minutes
    await page.waitForSelector('[data-testid="alert-item"]:has-text("Rating Engine API")', { timeout: 300000 });
    const alertItem = page.locator('[data-testid="alert-item"]').first();
    await expect(alertItem).toBeVisible();
    
    // Step 6: Verify alert contains necessary details
    await alertItem.click();
    await expect(page.locator('[data-testid="alert-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-endpoint-name"]')).toContainText('Rating Engine API');
    await expect(page.locator('[data-testid="alert-failure-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-error-description"]')).toContainText('endpoint failure');
    await expect(page.locator('[data-testid="alert-severity"]')).toContainText('Critical');
    
    // Verify alert sent to notification channels
    await expect(page.locator('[data-testid="alert-channels"]')).toContainText('Email');
    await expect(page.locator('[data-testid="alert-channels"]')).toContainText('Slack');
    await expect(page.locator('[data-testid="alert-delivery-status"]')).toContainText('Delivered');
    
    // Step 7: Restore API endpoint
    await page.click('[data-testid="close-alert-details-btn"]');
    await page.click('[data-testid="services-menu"]');
    await page.click('text=Rating Engine API');
    await page.click('[data-testid="admin-actions-menu"]');
    await page.click('[data-testid="stop-simulation-option"]');
    await page.click('[data-testid="confirm-stop-simulation-btn"]');
    
    // Expected Result: Health check returns to healthy status
    await expect(page.locator('[data-testid="simulation-active-banner"]')).not.toBeVisible();
    
    // Step 8: Wait for next health check cycle
    await page.waitForTimeout(30000);
    await page.click('[data-testid="refresh-status-btn"]');
    
    // Step 9: Verify monitoring dashboard shows healthy status
    await page.waitForSelector('[data-testid="api-endpoint-status"]:has-text("Healthy")', { timeout: 90000 });
    await expect(page.locator('[data-testid="api-endpoint-status"]')).toContainText('Healthy');
    await expect(page.locator('[data-testid="health-check-indicator"]')).toHaveClass(/status-healthy/);
    
    // Step 10: Check for recovery notification
    await page.click('[data-testid="alerts-menu"]');
    await page.click('[data-testid="recent-alerts-tab"]');
    await page.waitForSelector('[data-testid="alert-item"]:has-text("Recovered")', { timeout: 60000 });
    
    const recoveryAlert = page.locator('[data-testid="alert-item"]').filter({ hasText: 'Recovered' }).first();
    await expect(recoveryAlert).toBeVisible();
    await recoveryAlert.click();
    
    await expect(page.locator('[data-testid="alert-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="alert-type"]')).toContainText('Recovery');
    await expect(page.locator('[data-testid="alert-endpoint-name"]')).toContainText('Rating Engine API');
    await expect(page.locator('[data-testid="alert-resolution-message"]')).toContainText('Service restored to healthy status');
  });
});