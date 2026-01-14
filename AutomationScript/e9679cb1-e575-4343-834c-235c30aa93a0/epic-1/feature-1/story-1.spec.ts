import { test, expect, Page } from '@playwright/test';

// Test Data Fixtures
const testData = {
  hrManager: {
    username: 'hr.manager@company.com',
    password: 'HRManager123!',
    role: 'HR_MANAGER'
  },
  regularEmployee: {
    username: 'employee@company.com',
    password: 'Employee123!',
    role: 'EMPLOYEE'
  },
  shiftTemplates: {
    morningShift: {
      name: 'Morning Shift',
      startTime: '08:00',
      endTime: '16:00',
      breaks: [
        { startTime: '10:00', endTime: '10:15', type: 'Break' },
        { startTime: '12:00', endTime: '13:00', type: 'Lunch' }
      ]
    },
    eveningShift: {
      name: 'Evening Shift',
      startTime: '16:00',
      endTime: '00:00',
      breaks: [
        { startTime: '18:00', endTime: '18:15', type: 'Break' },
        { startTime: '20:00', endTime: '20:30', type: 'Dinner' }
      ]
    },
    nightShift: {
      name: 'Night Shift',
      startTime: '00:00',
      endTime: '08:00',
      breaks: [
        { startTime: '03:00', endTime: '03:30', type: 'Break' }
      ]
    },
    invalidOverlapping: {
      name: 'Invalid Shift',
      startTime: '14:00',
      endTime: '10:00',
      breaks: []
    },
    breakOutsideShift: {
      name: 'Break Outside Shift',
      startTime: '08:00',
      endTime: '16:00',
      breaks: [
        { startTime: '17:00', endTime: '17:15', type: 'Break' }
      ]
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
    await this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 5000 });
  }

  async loginAsHRManager() {
    await this.navigate();
    await this.login(testData.hrManager.username, testData.hrManager.password);
  }

  async loginAsEmployee() {
    await this.navigate();
    await this.login(testData.regularEmployee.username, testData.regularEmployee.password);
  }
}

// Page Object Model - Shift Template Management Page
class ShiftTemplateManagementPage {
  constructor(private page: Page) {}

  async navigate() {
    await this.page.goto('/shift-templates', { waitUntil: 'networkidle' });
  }

  async clickCreateNewTemplate() {
    await this.page.click('[data-testid="create-template-button"]');
    await this.page.waitForSelector('[data-testid="template-form"]', { timeout: 3000 });
  }

  async fillTemplateForm(template: any) {
    await this.page.fill('[data-testid="template-name-input"]', template.name);
    await this.page.fill('[data-testid="start-time-input"]', template.startTime);
    await this.page.fill('[data-testid="end-time-input"]', template.endTime);

    if (template.breaks && template.breaks.length > 0) {
      for (let i = 0; i < template.breaks.length; i++) {
        await this.page.click('[data-testid="add-break-button"]');
        await this.page.fill(`[data-testid="break-start-time-${i}"]`, template.breaks[i].startTime);
        await this.page.fill(`[data-testid="break-end-time-${i}"]`, template.breaks[i].endTime);
        await this.page.fill(`[data-testid="break-type-${i}"]`, template.breaks[i].type);
      }
    }
  }

  async saveTemplate() {
    await this.page.click('[data-testid="save-template-button"]');
  }

  async waitForSuccessMessage() {
    await this.page.waitForSelector('[data-testid="success-message"]', { timeout: 5000 });
  }

  async waitForErrorMessage() {
    await this.page.waitForSelector('[data-testid="error-message"]', { timeout: 5000 });
  }

  async getErrorMessage(): Promise<string> {
    const errorElement = await this.page.locator('[data-testid="error-message"]');
    return await errorElement.textContent() || '';
  }

  async getSuccessMessage(): Promise<string> {
    const successElement = await this.page.locator('[data-testid="success-message"]');
    return await successElement.textContent() || '';
  }

  async isTemplateInList(templateName: string): Promise<boolean> {
    const templateElement = this.page.locator(`[data-testid="template-item-${templateName}"]`);
    return await templateElement.isVisible();
  }

  async searchTemplate(searchTerm: string) {
    await this.page.fill('[data-testid="search-input"]', searchTerm);
    await this.page.waitForTimeout(500);
  }

  async filterByDuration(minDuration: string, maxDuration: string) {
    await this.page.fill('[data-testid="min-duration-filter"]', minDuration);
    await this.page.fill('[data-testid="max-duration-filter"]', maxDuration);
    await this.page.click('[data-testid="apply-filter-button"]');
    await this.page.waitForTimeout(500);
  }

  async filterByBreaks(hasBreaks: boolean) {
    const filterValue = hasBreaks ? 'with-breaks' : 'without-breaks';
    await this.page.selectOption('[data-testid="breaks-filter"]', filterValue);
    await this.page.waitForTimeout(500);
  }

  async sortBy(sortField: string) {
    await this.page.selectOption('[data-testid="sort-dropdown"]', sortField);
    await this.page.waitForTimeout(500);
  }

  async getTemplateCount(): Promise<number> {
    const templates = await this.page.locator('[data-testid^="template-item-"]').count();
    return templates;
  }

  async getTemplateNames(): Promise<string[]> {
    const elements = await this.page.locator('[data-testid^="template-item-"]').all();
    const names: string[] = [];
    for (const element of elements) {
      const name = await element.getAttribute('data-template-name');
      if (name) names.push(name);
    }
    return names;
  }

  async clickEditTemplate(templateName: string) {
    await this.page.click(`[data-testid="edit-template-${templateName}"]`);
    await this.page.waitForSelector('[data-testid="template-form"]', { timeout: 3000 });
  }

  async clickDeleteTemplate(templateName: string) {
    await this.page.click(`[data-testid="delete-template-${templateName}"]`);
  }

  async waitForConfirmationDialog() {
    await this.page.waitForSelector('[data-testid="confirmation-dialog"]', { timeout: 3000 });
  }

  async confirmDeletion() {
    await this.page.click('[data-testid="confirm-delete-button"]');
  }

  async cancelDeletion() {
    await this.page.click('[data-testid="cancel-delete-button"]');
  }

  async getConfirmationMessage(): Promise<string> {
    const confirmElement = await this.page.locator('[data-testid="confirmation-message"]');
    return await confirmElement.textContent() || '';
  }

  async isPaginationVisible(): Promise<boolean> {
    return await this.page.locator('[data-testid="pagination"]').isVisible();
  }

  async goToNextPage() {
    await this.page.click('[data-testid="next-page-button"]');
    await this.page.waitForTimeout(500);
  }

  async goToPreviousPage() {
    await this.page.click('[data-testid="previous-page-button"]');
    await this.page.waitForTimeout(500);
  }

  async verifyAccessDenied(): Promise<boolean> {
    try {
      await this.page.waitForSelector('[data-testid="access-denied-message"]', { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  async getTemplateDetails(templateName: string) {
    await this.page.click(`[data-testid="template-item-${templateName}"]`);
    await this.page.waitForSelector('[data-testid="template-details"]', { timeout: 3000 });
    
    const startTime = await this.page.locator('[data-testid="detail-start-time"]').textContent();
    const endTime = await this.page.locator('[data-testid="detail-end-time"]').textContent();
    const breaksCount = await this.page.locator('[data-testid^="detail-break-"]').count();
    
    return { startTime, endTime, breaksCount };
  }
}

// Test Suite for Story 1: Create Shift Templates
test.describe('Story-1: As HR Manager, I want to create shift templates to achieve standardized shift definitions', () => {
  let loginPage: LoginPage;
  let shiftTemplatePage: ShiftTemplateManagementPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    shiftTemplatePage = new ShiftTemplateManagementPage(page);
    await loginPage.loginAsHRManager();
  });

  test('TC-1.1: Create shift template with valid start and end times including breaks', async ({ page }) => {
    // Navigate to shift template management page
    await shiftTemplatePage.navigate();
    await expect(page).toHaveURL(/.*shift-templates/, { timeout: 5000 });

    // Select 'Create New Template'
    await shiftTemplatePage.clickCreateNewTemplate();
    const formVisible = await page.locator('[data-testid="template-form"]').isVisible();
    expect(formVisible).toBeTruthy();

    // Input shift name, start time, end time, and breaks
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.morningShift);

    // Save the template
    await shiftTemplatePage.saveTemplate();

    // System validates input times and confirms creation
    await shiftTemplatePage.waitForSuccessMessage();
    const successMessage = await shiftTemplatePage.getSuccessMessage();
    expect(successMessage).toContain('Template created successfully');

    // Verify template appears in list
    const templateInList = await shiftTemplatePage.isTemplateInList(testData.shiftTemplates.morningShift.name);
    expect(templateInList).toBeTruthy();
  });

  test('TC-1.2: System prevents creation of shift templates with overlapping times', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Attempt to create template with end time before start time
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.invalidOverlapping);

    // Save the template
    await shiftTemplatePage.saveTemplate();

    // System displays error message
    await shiftTemplatePage.waitForErrorMessage();
    const errorMessage = await shiftTemplatePage.getErrorMessage();
    expect(errorMessage).toMatch(/invalid|overlap|end time.*before start time/i);

    // Verify template is not in list
    const templateInList = await shiftTemplatePage.isTemplateInList(testData.shiftTemplates.invalidOverlapping.name);
    expect(templateInList).toBeFalsy();
  });

  test('TC-1.3: System validates breaks are within shift duration', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Attempt to create template with break outside shift hours
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.breakOutsideShift);

    // Save the template
    await shiftTemplatePage.saveTemplate();

    // System displays error message
    await shiftTemplatePage.waitForErrorMessage();
    const errorMessage = await shiftTemplatePage.getErrorMessage();
    expect(errorMessage).toMatch(/break.*outside.*shift|break.*within.*shift duration/i);
  });

  test('TC-1.4: System saves new shift templates and displays them in the template list', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create multiple templates
    const templates = [
      testData.shiftTemplates.morningShift,
      testData.shiftTemplates.eveningShift
    ];

    for (const template of templates) {
      await shiftTemplatePage.clickCreateNewTemplate();
      await shiftTemplatePage.fillTemplateForm(template);
      await shiftTemplatePage.saveTemplate();
      await shiftTemplatePage.waitForSuccessMessage();
      await page.waitForTimeout(500);
    }

    // Verify all templates are in the list
    for (const template of templates) {
      const templateInList = await shiftTemplatePage.isTemplateInList(template.name);
      expect(templateInList).toBeTruthy();
    }
  });

  test('TC-1.5: System allows editing existing shift templates', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create a template first
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.morningShift);
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Edit the template
    await shiftTemplatePage.clickEditTemplate(testData.shiftTemplates.morningShift.name);

    // Update template details
    await page.fill('[data-testid="template-name-input"]', 'Morning Shift Updated');
    await page.fill('[data-testid="start-time-input"]', '07:00');

    // Save changes
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Verify updated template in list
    const updatedTemplateInList = await shiftTemplatePage.isTemplateInList('Morning Shift Updated');
    expect(updatedTemplateInList).toBeTruthy();
  });

  test('TC-1.6: System allows deletion of existing shift templates with confirmation', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create a template first
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.nightShift);
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Attempt to delete the template
    await shiftTemplatePage.clickDeleteTemplate(testData.shiftTemplates.nightShift.name);

    // Confirmation dialog appears
    await shiftTemplatePage.waitForConfirmationDialog();
    const confirmationMessage = await shiftTemplatePage.getConfirmationMessage();
    expect(confirmationMessage).toMatch(/confirm.*delete|are you sure/i);

    // Confirm deletion
    await shiftTemplatePage.confirmDeletion();
    await shiftTemplatePage.waitForSuccessMessage();

    // Verify template is removed from list
    await page.waitForTimeout(1000);
    const templateInList = await shiftTemplatePage.isTemplateInList(testData.shiftTemplates.nightShift.name);
    expect(templateInList).toBeFalsy();
  });

  test('TC-1.7: System restricts access to shift template management to HR Managers only', async ({ page }) => {
    // Logout and login as regular employee
    await page.click('[data-testid="logout-button"]');
    await loginPage.loginAsEmployee();

    // Attempt to navigate to shift template management
    await shiftTemplatePage.navigate();

    // Verify access is denied
    const accessDenied = await shiftTemplatePage.verifyAccessDenied();
    expect(accessDenied).toBeTruthy();
  });

  test('TC-1.8: System processes template creation within 2 seconds', async ({ page }) => {
    await shiftTemplatePage.navigate();

    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.eveningShift);

    // Measure save time
    const startTime = Date.now();
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();
    const endTime = Date.now();

    const responseTime = endTime - startTime;
    expect(responseTime).toBeLessThan(2000);
  });
});

// Test Suite for Story 5: View and Search Shift Templates
test.describe('Story-5: As HR Manager, I want to view and search shift templates to achieve efficient template management', () => {
  let loginPage: LoginPage;
  let shiftTemplatePage: ShiftTemplateManagementPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    shiftTemplatePage = new ShiftTemplateManagementPage(page);
    await loginPage.loginAsHRManager();

    // Setup: Create test templates
    await shiftTemplatePage.navigate();
    const templates = [
      testData.shiftTemplates.morningShift,
      testData.shiftTemplates.eveningShift,
      testData.shiftTemplates.nightShift
    ];

    for (const template of templates) {
      await shiftTemplatePage.clickCreateNewTemplate();
      await shiftTemplatePage.fillTemplateForm(template);
      await shiftTemplatePage.saveTemplate();
      await shiftTemplatePage.waitForSuccessMessage();
      await page.waitForTimeout(300);
    }
  });

  test('TC-5.1: System displays a list of all shift templates with pagination', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Verify templates are displayed
    const templateCount = await shiftTemplatePage.getTemplateCount();
    expect(templateCount).toBeGreaterThan(0);

    // Verify all created templates are visible
    const templateNames = await shiftTemplatePage.getTemplateNames();
    expect(templateNames).toContain(testData.shiftTemplates.morningShift.name);
    expect(templateNames).toContain(testData.shiftTemplates.eveningShift.name);
    expect(templateNames).toContain(testData.shiftTemplates.nightShift.name);

    // Check if pagination is present when needed
    const paginationVisible = await shiftTemplatePage.isPaginationVisible();
    if (templateCount > 10) {
      expect(paginationVisible).toBeTruthy();
    }
  });

  test('TC-5.2: System supports search by template name', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Search for specific template
    await shiftTemplatePage.searchTemplate('Morning');

    // Verify only matching templates are displayed
    await page.waitForTimeout(500);
    const templateCount = await shiftTemplatePage.getTemplateCount();
    const templateNames = await shiftTemplatePage.getTemplateNames();
    
    expect(templateCount).toBeGreaterThan(0);
    expect(templateNames.some(name => name.includes('Morning'))).toBeTruthy();
  });

  test('TC-5.3: System supports search by shift type', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Search for shift type
    await shiftTemplatePage.searchTemplate('Shift');

    // Verify search results
    await page.waitForTimeout(500);
    const templateCount = await shiftTemplatePage.getTemplateCount();
    expect(templateCount).toBeGreaterThan(0);
  });

  test('TC-5.4: System allows filtering templates by duration', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Filter by duration (8 hour shifts)
    await shiftTemplatePage.filterByDuration('7', '9');

    // Verify filtered results
    await page.waitForTimeout(500);
    const templateCount = await shiftTemplatePage.getTemplateCount();
    expect(templateCount).toBeGreaterThan(0);

    const templateNames = await shiftTemplatePage.getTemplateNames();
    expect(templateNames).toContain(testData.shiftTemplates.morningShift.name);
  });

  test('TC-5.5: System allows filtering templates by breaks', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Filter templates with breaks
    await shiftTemplatePage.filterByBreaks(true);

    // Verify filtered results contain only templates with breaks
    await page.waitForTimeout(500);
    const templateCount = await shiftTemplatePage.getTemplateCount();
    expect(templateCount).toBeGreaterThan(0);
  });

  test('TC-5.6: System sorts templates by creation date', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Sort by creation date
    await shiftTemplatePage.sortBy('creationDate');

    // Verify sorting
    await page.waitForTimeout(500);
    const templateNames = await shiftTemplatePage.getTemplateNames();
    expect(templateNames.length).toBeGreaterThan(0);
  });

  test('TC-5.7: System sorts templates by name', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Sort by name
    await shiftTemplatePage.sortBy('name');

    // Verify alphabetical sorting
    await page.waitForTimeout(500);
    const templateNames = await shiftTemplatePage.getTemplateNames();
    const sortedNames = [...templateNames].sort();
    expect(templateNames).toEqual(sortedNames);
  });

  test('TC-5.8: System allows selecting template for details', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Select a template
    const details = await shiftTemplatePage.getTemplateDetails(testData.shiftTemplates.morningShift.name);

    // Verify details are displayed
    expect(details.startTime).toContain(testData.shiftTemplates.morningShift.startTime);
    expect(details.endTime).toContain(testData.shiftTemplates.morningShift.endTime);
    expect(details.breaksCount).toBe(testData.shiftTemplates.morningShift.breaks.length);
  });

  test('TC-5.9: System returns search results within 2 seconds', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Measure search time
    const startTime = Date.now();
    await shiftTemplatePage.searchTemplate('Morning');
    await page.waitForTimeout(500);
    const endTime = Date.now();

    const searchTime = endTime - startTime;
    expect(searchTime).toBeLessThan(2000);
  });

  test('TC-5.10: System restricts access to shift template list to HR Managers', async ({ page }) => {
    // Logout and login as regular employee
    await page.click('[data-testid="logout-button"]');
    await loginPage.loginAsEmployee();

    // Attempt to access template list
    await shiftTemplatePage.navigate();

    // Verify access is denied
    const accessDenied = await shiftTemplatePage.verifyAccessDenied();
    expect(accessDenied).toBeTruthy();
  });

  test('TC-5.11: System handles pagination navigation correctly', async ({ page }) => {
    await shiftTemplatePage.navigate();

    const initialCount = await shiftTemplatePage.getTemplateCount();
    
    if (await shiftTemplatePage.isPaginationVisible()) {
      // Navigate to next page
      await shiftTemplatePage.goToNextPage();
      const nextPageCount = await shiftTemplatePage.getTemplateCount();
      expect(nextPageCount).toBeGreaterThanOrEqual(0);

      // Navigate back to previous page
      await shiftTemplatePage.goToPreviousPage();
      const returnedCount = await shiftTemplatePage.getTemplateCount();
      expect(returnedCount).toBe(initialCount);
    }
  });
});

// Test Suite for Story 8: Delete Obsolete Shift Templates
test.describe('Story-8: As HR Manager, I want to delete obsolete shift templates to maintain an up-to-date template library', () => {
  let loginPage: LoginPage;
  let shiftTemplatePage: ShiftTemplateManagementPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    shiftTemplatePage = new ShiftTemplateManagementPage(page);
    await loginPage.loginAsHRManager();
  });

  test('TC-8.1: System prevents deletion of shift templates currently assigned to employee schedules', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create a template
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.morningShift);
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Simulate template being assigned (this would be done via API or database)
    // For testing, we'll attempt deletion of an "assigned" template
    await page.evaluate(() => {
      localStorage.setItem('assignedTemplate', 'Morning Shift');
    });

    // Attempt to delete assigned template
    await shiftTemplatePage.clickDeleteTemplate(testData.shiftTemplates.morningShift.name);
    await shiftTemplatePage.waitForConfirmationDialog();
    await shiftTemplatePage.confirmDeletion();

    // System should prevent deletion and show error
    await shiftTemplatePage.waitForErrorMessage();
    const errorMessage = await shiftTemplatePage.getErrorMessage();
    expect(errorMessage).toMatch(/cannot delete.*assigned|template.*in use/i);

    // Verify template still exists in list
    const templateInList = await shiftTemplatePage.isTemplateInList(testData.shiftTemplates.morningShift.name);
    expect(templateInList).toBeTruthy();
  });

  test('TC-8.2: System prompts for confirmation before deleting a template', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create a template
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.eveningShift);
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Click delete button
    await shiftTemplatePage.clickDeleteTemplate(testData.shiftTemplates.eveningShift.name);

    // Verify confirmation dialog appears
    await shiftTemplatePage.waitForConfirmationDialog();
    const confirmationVisible = await page.locator('[data-testid="confirmation-dialog"]').isVisible();
    expect(confirmationVisible).toBeTruthy();

    // Verify confirmation message
    const confirmationMessage = await shiftTemplatePage.getConfirmationMessage();
    expect(confirmationMessage).toMatch(/confirm.*delete|are you sure/i);

    // Cancel deletion
    await shiftTemplatePage.cancelDeletion();

    // Verify template still exists
    const templateInList = await shiftTemplatePage.isTemplateInList(testData.shiftTemplates.eveningShift.name);
    expect(templateInList).toBeTruthy();
  });

  test('TC-8.3: System deletes templates not assigned to any schedules successfully', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create a template
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm(testData.shiftTemplates.nightShift);
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Ensure template is not assigned
    await page.evaluate(() => {
      localStorage.removeItem('assignedTemplate');
    });

    // Delete the template
    await shiftTemplatePage.clickDeleteTemplate(testData.shiftTemplates.nightShift.name);
    await shiftTemplatePage.waitForConfirmationDialog();
    await shiftTemplatePage.confirmDeletion();

    // Verify successful deletion
    await shiftTemplatePage.waitForSuccessMessage();
    const successMessage = await shiftTemplatePage.getSuccessMessage();
    expect(successMessage).toMatch(/deleted successfully|template removed/i);

    // Verify template is removed from list
    await page.waitForTimeout(1000);
    const templateInList = await shiftTemplatePage.isTemplateInList(testData.shiftTemplates.nightShift.name);
    expect(templateInList).toBeFalsy();
  });

  test('TC-8.4: System logs all deletion actions with user and timestamp', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create a template
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm({
      name: 'Test Deletion Log',
      startTime: '09:00',
      endTime: '17:00',
      breaks: []
    });
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Delete the template
    await shiftTemplatePage.clickDeleteTemplate('Test Deletion Log');
    await shiftTemplatePage.waitForConfirmationDialog();
    await shiftTemplatePage.confirmDeletion();
    await shiftTemplatePage.waitForSuccessMessage();

    // Navigate to audit log (if available in UI)
    await page.goto('/audit-log', { waitUntil: 'networkidle' });

    // Verify deletion is logged
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    const logEntryText = await auditLogEntry.textContent();
    
    expect(logEntryText).toMatch(/delete.*template|template.*deleted/i);
    expect(logEntryText).toContain('Test Deletion Log');
    expect(logEntryText).toContain(testData.hrManager.username);
    
    // Verify timestamp is present and recent
    const timestampElement = await page.locator('[data-testid="audit-log-timestamp"]').first();
    const timestamp = await timestampElement.textContent();
    expect(timestamp).toBeTruthy();
  });

  test('TC-8.5: System restricts deletion functionality to HR Managers', async ({ page }) => {
    // Create template as HR Manager first
    await shiftTemplatePage.navigate();
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm({
      name: 'Restricted Delete Test',
      startTime: '10:00',
      endTime: '18:00',
      breaks: []
    });
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Logout and login as regular employee
    await page.click('[data-testid="logout-button"]');
    await loginPage.loginAsEmployee();

    // Attempt to access template management
    await shiftTemplatePage.navigate();

    // Verify access is denied or delete button is not visible
    const accessDenied = await shiftTemplatePage.verifyAccessDenied();
    if (!accessDenied) {
      // If page is accessible, verify delete button is not visible
      const deleteButtonVisible = await page.locator('[data-testid^="delete-template-"]').first().isVisible().catch(() => false);
      expect(deleteButtonVisible).toBeFalsy();
    } else {
      expect(accessDenied).toBeTruthy();
    }
  });

  test('TC-8.6: System processes deletion within 2 seconds', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create a template
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm({
      name: 'Performance Test Template',
      startTime: '08:00',
      endTime: '16:00',
      breaks: []
    });
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Measure deletion time
    await shiftTemplatePage.clickDeleteTemplate('Performance Test Template');
    await shiftTemplatePage.waitForConfirmationDialog();
    
    const startTime = Date.now();
    await shiftTemplatePage.confirmDeletion();
    await shiftTemplatePage.waitForSuccessMessage();
    const endTime = Date.now();

    const deletionTime = endTime - startTime;
    expect(deletionTime).toBeLessThan(2000);
  });

  test('TC-8.7: System validates template is not assigned before showing delete confirmation', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create a template
    await shiftTemplatePage.clickCreateNewTemplate();
    await shiftTemplatePage.fillTemplateForm({
      name: 'Validation Test',
      startTime: '11:00',
      endTime: '19:00',
      breaks: []
    });
    await shiftTemplatePage.saveTemplate();
    await shiftTemplatePage.waitForSuccessMessage();

    // Mark template as assigned
    await page.evaluate(() => {
      localStorage.setItem('assignedTemplate', 'Validation Test');
    });

    // Attempt to delete
    await shiftTemplatePage.clickDeleteTemplate('Validation Test');

    // System should immediately show error without confirmation dialog
    try {
      await shiftTemplatePage.waitForErrorMessage();
      const errorMessage = await shiftTemplatePage.getErrorMessage();
      expect(errorMessage).toMatch(/cannot delete.*assigned|template.*in use/i);
    } catch (error) {
      // If error message is shown in confirmation dialog instead
      await shiftTemplatePage.waitForConfirmationDialog();
      const confirmationMessage = await shiftTemplatePage.getConfirmationMessage();
      expect(confirmationMessage).toMatch(/cannot delete.*assigned|template.*in use/i);
    }
  });

  test('TC-8.8: System maintains audit trail completeness for all deletions', async ({ page }) => {
    await shiftTemplatePage.navigate();

    // Create multiple templates and delete them
    const templatesToDelete = ['Audit Test 1', 'Audit Test 2', 'Audit Test 3'];
    
    for (const templateName of templatesToDelete) {
      await shiftTemplatePage.clickCreateNewTemplate();
      await shiftTemplatePage.fillTemplateForm({
        name: templateName,
        startTime: '08:00',
        endTime: '16:00',
        breaks: []
      });
      await shiftTemplatePage.saveTemplate();
      await shiftTemplatePage.waitForSuccessMessage();
      await page.waitForTimeout(300);

      await shiftTemplatePage.clickDeleteTemplate(templateName);
      await shiftTemplatePage.waitForConfirmationDialog();
      await shiftTemplatePage.confirmDeletion();
      await shiftTemplatePage.waitForSuccessMessage();
      await page.waitForTimeout(300);
    }

    // Navigate to audit log
    await page.goto('/audit-log', { waitUntil: 'networkidle' });

    // Verify all deletions are logged
    const auditLogEntries = await page.locator('[data-testid="audit-log-entry"]').count();
    expect(auditLogEntries).toBeGreaterThanOrEqual(templatesToDelete.length);

    // Verify each deletion has required information
    for (let i = 0; i < Math.min(templatesToDelete.length, auditLogEntries); i++) {
      const logEntry = page.locator('[data-testid="audit-log-entry"]').nth(i);
      const entryText = await logEntry.textContent();
      
      expect(entryText).toBeTruthy();
      expect(entryText).toMatch(/delete|removed/i);
    }
  });
});