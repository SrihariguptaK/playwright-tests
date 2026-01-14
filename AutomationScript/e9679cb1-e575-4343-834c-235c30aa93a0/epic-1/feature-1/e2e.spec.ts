import { test, expect, Page } from '@playwright/test';

// Test Data Fixtures
const testData = {
  shiftTemplates: {
    valid: {
      name: 'Morning Shift',
      startTime: '08:00',
      endTime: '16:00',
      breakStart: '12:00',
      breakEnd: '13:00',
      role: 'Nurse',
      department: 'Emergency'
    },
    evening: {
      name: 'Evening Shift',
      startTime: '16:00',
      endTime: '00:00',
      breakStart: '20:00',
      breakEnd: '20:30',
      role: 'Nurse',
      department: 'Emergency'
    },
    invalid: {
      name: 'Invalid Shift',
      startTime: '16:00',
      endTime: '08:00',
      breakStart: '12:00',
      breakEnd: '13:00',
      role: 'Doctor',
      department: 'ICU'
    },
    overlappingBreak: {
      name: 'Invalid Break Shift',
      startTime: '08:00',
      endTime: '16:00',
      breakStart: '06:00',
      breakEnd: '07:00',
      role: 'Technician',
      department: 'Radiology'
    },
    updated: {
      name: 'Morning Shift Updated',
      startTime: '07:00',
      endTime: '15:00',
      breakStart: '11:00',
      breakEnd: '12:00'
    }
  },
  hrManager: {
    username: 'hr.manager@hospital.com',
    password: 'HRManager123!'
  }
};

// Page Object Model for Shift Template Management
class ShiftTemplateManagementPage {
  constructor(private page: Page) {}

  // Locators
  get createTemplateButton() {
    return this.page.locator('[data-testid="create-template-button"]');
  }

  get templateNameInput() {
    return this.page.locator('[data-testid="template-name-input"]');
  }

  get startTimeInput() {
    return this.page.locator('[data-testid="start-time-input"]');
  }

  get endTimeInput() {
    return this.page.locator('[data-testid="end-time-input"]');
  }

  get breakStartInput() {
    return this.page.locator('[data-testid="break-start-input"]');
  }

  get breakEndInput() {
    return this.page.locator('[data-testid="break-end-input"]');
  }

  get roleSelect() {
    return this.page.locator('[data-testid="role-select"]');
  }

  get departmentSelect() {
    return this.page.locator('[data-testid="department-select"]');
  }

  get saveTemplateButton() {
    return this.page.locator('[data-testid="save-template-button"]');
  }

  get cancelButton() {
    return this.page.locator('[data-testid="cancel-button"]');
  }

  get confirmationMessage() {
    return this.page.locator('[data-testid="confirmation-message"]');
  }

  get errorMessage() {
    return this.page.locator('[data-testid="error-message"]');
  }

  get templateList() {
    return this.page.locator('[data-testid="template-list"]');
  }

  get validationError() {
    return this.page.locator('[data-testid="validation-error"]');
  }

  // Methods
  async navigateToShiftTemplates() {
    await this.page.goto('/shift-templates', { waitUntil: 'networkidle' });
    await this.page.waitForSelector('[data-testid="shift-templates-page"]', { timeout: 10000 });
  }

  async clickCreateTemplate() {
    await this.createTemplateButton.waitFor({ state: 'visible', timeout: 5000 });
    await this.createTemplateButton.click();
    await this.page.waitForSelector('[data-testid="template-form"]', { timeout: 5000 });
  }

  async fillTemplateForm(templateData: any) {
    await this.templateNameInput.fill(templateData.name);
    await this.startTimeInput.fill(templateData.startTime);
    await this.endTimeInput.fill(templateData.endTime);
    await this.breakStartInput.fill(templateData.breakStart);
    await this.breakEndInput.fill(templateData.breakEnd);
    await this.roleSelect.selectOption(templateData.role);
    await this.departmentSelect.selectOption(templateData.department);
  }

  async saveTemplate() {
    await this.saveTemplateButton.click();
  }

  async waitForConfirmation() {
    await this.confirmationMessage.waitFor({ state: 'visible', timeout: 5000 });
  }

  async waitForError() {
    await this.errorMessage.waitFor({ state: 'visible', timeout: 5000 });
  }

  async getTemplateByName(name: string) {
    return this.page.locator(`[data-testid="template-item"][data-template-name="${name}"]`);
  }

  async editTemplate(templateName: string) {
    const template = await this.getTemplateByName(templateName);
    await template.locator('[data-testid="edit-button"]').click();
    await this.page.waitForSelector('[data-testid="template-form"]', { timeout: 5000 });
  }

  async deleteTemplate(templateName: string) {
    const template = await this.getTemplateByName(templateName);
    await template.locator('[data-testid="delete-button"]').click();
  }

  async confirmDelete() {
    await this.page.locator('[data-testid="confirm-delete-button"]').click();
  }

  async getWarningMessage() {
    return this.page.locator('[data-testid="warning-message"]');
  }

  async getAuditLog(templateName: string) {
    const template = await this.getTemplateByName(templateName);
    await template.locator('[data-testid="audit-log-button"]').click();
    return this.page.locator('[data-testid="audit-log-panel"]');
  }
}

// Page Object Model for Login
class LoginPage {
  constructor(private page: Page) {}

  async login(username: string, password: string) {
    await this.page.goto('/login', { waitUntil: 'networkidle' });
    await this.page.locator('[data-testid="username-input"]').fill(username);
    await this.page.locator('[data-testid="password-input"]').fill(password);
    await this.page.locator('[data-testid="login-button"]').click();
    await this.page.waitForURL('**/dashboard', { timeout: 10000 });
  }
}

// Story 1: Create Shift Templates
test.describe('Story-1: As HR Manager, I want to create shift templates to achieve standardized scheduling', () => {
  let shiftTemplatePage: ShiftTemplateManagementPage;
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    shiftTemplatePage = new ShiftTemplateManagementPage(page);
    loginPage = new LoginPage(page);
    
    // Login as HR Manager
    await loginPage.login(testData.hrManager.username, testData.hrManager.password);
  });

  test('TC1: Successfully create a shift template with valid start and end times and break periods', async ({ page }) => {
    try {
      // Step 1: HR Manager navigates to shift template creation page
      await shiftTemplatePage.navigateToShiftTemplates();
      await expect(page).toHaveURL(/.*shift-templates/, { timeout: 5000 });
      
      // Step 2: Click create template button
      await shiftTemplat