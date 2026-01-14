import { test, expect } from '@playwright/test';

test.describe('Story-14: Escalation Alerts for Unresolved Scheduling Conflicts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling application
    await page.goto('/scheduling');
    // Login as scheduler
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Verify escalation alert after unresolved conflict threshold', async ({ page }) => {
    // Step 1: Create a scheduling conflict by double-booking a resource
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.fill('[data-testid="assigned-to-input"]', 'Team Alpha');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Create conflicting schedule for same resource and time
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Conference Room A');
    await page.fill('[data-testid="start-time-input"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-15T11:00');
    await page.fill('[data-testid="assigned-to-input"]', 'Team Beta');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Step 2: Verify that initial alert is sent to the scheduler
    await page.click('[data-testid="alerts-menu"]');
    await expect(page.locator('[data-testid="alert-notification"]').first()).toBeVisible();
    const initialAlert = page.locator('[data-testid="alert-notification"]').first();
    await expect(initialAlert).toContainText('Scheduling conflict detected');
    await expect(initialAlert).toContainText('Conference Room A');
    
    // Get conflict ID for tracking
    const conflictId = await initialAlert.getAttribute('data-conflict-id');
    
    // Step 3: Leave the conflict unresolved and wait until the escalation threshold time passes
    // Advance system time using API or wait for threshold (simulating time passage)
    await page.request.post('/api/system/advance-time', {
      data: { minutes: 31 } // Assuming 30-minute threshold
    });
    
    // Step 4: Monitor for escalation alert delivery within 1 minute of threshold
    await page.waitForTimeout(60000); // Wait up to 1 minute
    await page.reload();
    await page.click('[data-testid="alerts-menu"]');
    
    // Step 5: Verify escalation alert content received by higher-level users
    const escalationAlert = page.locator(`[data-testid="escalation-alert"][data-conflict-id="${conflictId}"]`);
    await expect(escalationAlert).toBeVisible({ timeout: 10000 });
    await expect(escalationAlert).toContainText('ESCALATED');
    await expect(escalationAlert).toContainText('Conference Room A');
    
    // Verify escalation was sent to designated users
    await escalationAlert.click();
    const escalationDetails = page.locator('[data-testid="escalation-details"]');
    await expect(escalationDetails.locator('[data-testid="escalated-to"]')).toContainText('Manager');
    
    // Step 6: Resolve the scheduling conflict by removing the double-booking
    await page.click('[data-testid="schedules-menu"]');
    const conflictingSchedule = page.locator(`[data-testid="schedule-item"][data-conflict="true"]`).first();
    await conflictingSchedule.click();
    await page.click('[data-testid="delete-schedule-button"]');
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Verify conflict is resolved
    await expect(page.locator('[data-testid="conflict-resolved-message"]')).toBeVisible();
    
    // Step 7: Monitor for any additional escalation alerts after conflict resolution
    await page.waitForTimeout(5000);
    await page.click('[data-testid="alerts-menu"]');
    const activeEscalations = page.locator(`[data-testid="escalation-alert"][data-conflict-id="${conflictId}"][data-status="active"]`);
    await expect(activeEscalations).toHaveCount(0);
  });

  test('Check audit logging of escalation events', async ({ page }) => {
    // Step 1: Create a scheduling conflict and wait for escalation threshold to pass
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-01-16T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-16T15:00');
    await page.fill('[data-testid="assigned-to-input"]', 'Project X');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Create conflicting schedule
    await page.click('[data-testid="create-schedule-button"]');
    await page.fill('[data-testid="resource-name-input"]', 'Meeting Room B');
    await page.fill('[data-testid="start-time-input"]', '2024-01-16T14:00');
    await page.fill('[data-testid="end-time-input"]', '2024-01-16T15:00');
    await page.fill('[data-testid="assigned-to-input"]', 'Project Y');
    await page.click('[data-testid="save-schedule-button"]');
    
    // Get conflict ID from alert
    await page.click('[data-testid="alerts-menu"]');
    const conflictAlert = page.locator('[data-testid="alert-notification"]').first();
    const conflictId = await conflictAlert.getAttribute('data-conflict-id');
    
    // Advance time to trigger escalation
    await page.request.post('/api/system/advance-time', {
      data: { minutes: 31 }
    });
    
    await page.waitForTimeout(60000);
    
    // Step 2: Verify that escalation alert is triggered and sent to designated users
    await page.reload();
    await page.click('[data-testid="alerts-menu"]');
    const escalationAlert = page.locator(`[data-testid="escalation-alert"][data-conflict-id="${conflictId}"]`);
    await expect(escalationAlert).toBeVisible({ timeout: 10000 });
    
    // Step 3: Navigate to the audit logs section of the system
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();
    
    // Step 4: Filter audit logs for escalation events related to the triggered conflict
    await page.fill('[data-testid="audit-log-search-input"]', conflictId);
    await page.selectOption('[data-testid="event-type-filter"]', 'escalation');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Step 5: Review the escalation event log entry details
    const escalationLogEntry = page.locator(`[data-testid="audit-log-entry"][data-event-type="escalation"]`).first();
    await expect(escalationLogEntry).toBeVisible();
    
    // Step 6: Verify the timestamp accuracy in the audit log
    const timestamp = await escalationLogEntry.locator('[data-testid="log-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    const timestampDate = new Date(timestamp);
    expect(timestampDate.getTime()).toBeGreaterThan(Date.now() - 120000); // Within last 2 minutes
    
    // Step 7: Check that all required fields are populated in the audit log entry
    await escalationLogEntry.click();
    const logDetails = page.locator('[data-testid="audit-log-details"]');
    await expect(logDetails.locator('[data-testid="conflict-id"]')).toContainText(conflictId);
    await expect(logDetails.locator('[data-testid="event-type"]')).toContainText('escalation');
    await expect(logDetails.locator('[data-testid="escalated-by"]')).not.toBeEmpty();
    await expect(logDetails.locator('[data-testid="escalated-to"]')).not.toBeEmpty();
    await expect(logDetails.locator('[data-testid="resource-name"]')).toContainText('Meeting Room B');
    await expect(logDetails.locator('[data-testid="timestamp"]')).not.toBeEmpty();
    
    // Step 8: Resolve the conflict and verify resolution is also logged
    await page.click('[data-testid="schedules-menu"]');
    const conflictingSchedule = page.locator(`[data-testid="schedule-item"][data-conflict="true"]`).first();
    await conflictingSchedule.click();
    await page.click('[data-testid="delete-schedule-button"]');
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Navigate back to audit logs
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="audit-logs-link"]');
    await page.fill('[data-testid="audit-log-search-input"]', conflictId);
    await page.selectOption('[data-testid="event-type-filter"]', 'resolution');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Verify resolution is logged
    const resolutionLogEntry = page.locator(`[data-testid="audit-log-entry"][data-event-type="resolution"]`).first();
    await expect(resolutionLogEntry).toBeVisible();
    await resolutionLogEntry.click();
    const resolutionDetails = page.locator('[data-testid="audit-log-details"]');
    await expect(resolutionDetails.locator('[data-testid="conflict-id"]')).toContainText(conflictId);
    await expect(resolutionDetails.locator('[data-testid="event-type"]')).toContainText('resolution');
  });
});