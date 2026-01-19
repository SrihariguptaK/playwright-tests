# Manual Test Cases

## Story: As Employee, I want to view my assigned performance metrics and review schedule to prepare for evaluations
**Story ID:** story-18

### Test Case: Validate dashboard displays assigned metrics and review cycles
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee user account exists in the system
- Employee has at least one performance metric assigned
- Employee has at least one review cycle scheduled
- System is accessible and operational
- Valid employee credentials are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Employee is authenticated and redirected to the Performance Dashboard |
| 3 | Verify the Performance Dashboard loads completely | Dashboard loads successfully within 3 seconds showing metrics and review cycles sections |
| 4 | Review the list of assigned performance metrics displayed on the dashboard | All assigned metrics are displayed with metric names, targets, current values, and status indicators |
| 5 | Review the list of review cycles displayed on the dashboard | All upcoming and active review cycles are displayed with cycle names, start dates, end dates, and current status |
| 6 | Verify the accuracy of displayed metrics against expected assignments | All metrics match the employee's assigned metrics with correct details |
| 7 | Verify the accuracy of review cycle dates and status | Review cycle dates and status indicators are accurate and match scheduled information |
| 8 | Locate and click the Export to PDF button | Export dialog appears with PDF format selected |
| 9 | Confirm the export action | PDF file is generated and downloaded successfully |
| 10 | Open the downloaded PDF file | PDF contains all assigned metrics with targets and review schedules with accurate dates and status |

**Postconditions:**
- Employee remains logged into the system
- Dashboard data remains unchanged
- PDF export file is saved to local download folder
- No data modifications occurred during the test

---

### Test Case: Ensure dashboard access is restricted to logged-in employee
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Two employee user accounts exist in the system (Employee A and Employee B)
- Employee A is logged into the system
- Employee B's dashboard URL is known
- System security and authorization mechanisms are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Employee A with valid credentials | Employee A is successfully authenticated and redirected to their dashboard |
| 2 | Note the current dashboard URL for Employee A | URL is captured showing Employee A's user identifier or dashboard path |
| 3 | Manually modify the URL in the browser address bar to Employee B's dashboard URL | URL is changed in the address bar |
| 4 | Press Enter to navigate to Employee B's dashboard URL | Access is denied with an appropriate error message such as 'Access Denied' or 'Unauthorized Access' (HTTP 403 or 401) |
| 5 | Verify that no data from Employee B's dashboard is displayed | No performance metrics or review cycles belonging to Employee B are visible |
| 6 | Verify the user is redirected back to Employee A's dashboard or an error page | User is either redirected to their own dashboard or shown a proper error page without exposing unauthorized data |

**Postconditions:**
- Employee A remains logged in with access only to their own data
- No unauthorized access to Employee B's data occurred
- Security logs record the unauthorized access attempt
- System maintains data integrity and security

---

## Story: As Performance Manager, I want to receive automated notifications for upcoming review cycles to ensure timely evaluations
**Story ID:** story-19

### Test Case: Validate scheduled notification delivery
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Performance Manager account exists with appropriate permissions
- Email server is configured and operational
- In-app notification system is functional
- At least one review cycle exists in the system
- Manager is logged into the system
- Notification templates are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Performance Manager with valid credentials | Manager is successfully authenticated and redirected to the dashboard |
| 2 | Navigate to the Review Cycle Management section | Review Cycle Management page is displayed with list of existing review cycles |
| 3 | Select a specific review cycle for notification configuration | Review cycle details page opens showing cycle information and notification settings |
| 4 | Click on Configure Notifications button | Notification configuration interface is displayed with scheduling options |
| 5 | Set notification schedule to trigger in 5 minutes from current time | Notification schedule fields accept the time input |
| 6 | Select both Email and In-app notification delivery methods | Both delivery method checkboxes are checked |
| 7 | Click Save to save the notification schedule | Success message is displayed confirming schedule is saved successfully, and configuration is stored in the system |
| 8 | Wait for the scheduled notification time (5 minutes) | Time elapses and scheduled notification time is reached |
| 9 | Check the manager's email inbox for the notification | Email notification is received within 1 hour of scheduled time with correct review cycle information |
| 10 | Check the in-app notification center | In-app notification alert is displayed with review cycle details and unread status |
| 11 | Click on the in-app notification to acknowledge it | Notification is marked as read and acknowledgment timestamp is recorded |
| 12 | Navigate to notification logs or audit trail | Notification delivery log shows successful delivery status, delivery timestamp, and acknowledgment timestamp |

**Postconditions:**
- Notification schedule remains active for future cycles
- Notification delivery is logged in the system
- User acknowledgment is recorded with timestamp
- Email and in-app notifications are marked as delivered and read

---

### Test Case: Verify user can customize notification preferences
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User account exists in the system (Manager or Employee)
- User has access to notification preferences settings
- Default notification preferences are already configured
- User is logged into the system
- At least one notification type is available for configuration

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in with valid user credentials | User is successfully authenticated and redirected to the main dashboard |
| 2 | Navigate to user profile or settings menu | Settings menu is displayed with various configuration options |
| 3 | Click on Notification Preferences option | Notification Preferences page is displayed showing current notification settings |
| 4 | Review the current notification preferences displayed | Current settings show notification types, delivery methods (email/in-app), and opt-in/opt-out status |
| 5 | Change email notification setting from enabled to disabled for review cycle reminders | Email notification toggle switches to disabled state |
| 6 | Change in-app notification setting from disabled to enabled for performance metric updates | In-app notification toggle switches to enabled state |
| 7 | Modify notification frequency preference from immediate to daily digest | Frequency dropdown updates to show daily digest selected |
| 8 | Click Save or Update Preferences button | Success message is displayed confirming preferences are saved successfully |
| 9 | Log out and log back in to verify persistence | User is logged out and then successfully logs back in |
| 10 | Navigate back to Notification Preferences page | Notification Preferences page displays the updated settings matching the changes made |
| 11 | Trigger a test notification for review cycle reminders | No email notification is sent (as per disabled preference), confirming settings are applied |
| 12 | Trigger a test notification for performance metric updates | In-app notification is displayed (as per enabled preference), confirming settings are respected |
| 13 | Verify that suppressed notifications are not delivered | Email inbox shows no review cycle reminder emails, confirming opt-out is working |

**Postconditions:**
- User notification preferences are updated in the database
- Future notifications respect the updated preferences
- User remains logged into the system
- Notification preference changes are logged in audit trail

---

## Story: As Performance Analyst, I want to generate reports on performance metrics and review cycles to analyze trends and outcomes
**Story ID:** story-20

### Test Case: Validate report generation with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Performance Analyst
- Performance metrics data exists in the system
- At least one review cycle has been completed
- User has appropriate permissions to access reporting features
- Browser is supported (Chrome, Firefox, Safari, Edge)
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the Reporting page from the main navigation menu | Reporting page is displayed with options to select metrics, review cycles, and filters. Page loads within 3 seconds |
| 2 | Select desired performance metrics from the metrics dropdown (e.g., Goal Completion Rate, Performance Score) | Selected metrics are highlighted and displayed in the selection panel |
| 3 | Select one or more review cycles from the review cycle dropdown (e.g., Q1 2024, Q2 2024) | Selected review cycles are highlighted and displayed in the selection panel |
| 4 | Apply filters by selecting date range (e.g., January 1, 2024 to March 31, 2024) | Date range filter is applied and displayed in the active filters section |
| 5 | Apply additional filters by selecting department (e.g., Engineering, Sales) | Department filter is applied and displayed in the active filters section |
| 6 | Apply role filter by selecting specific roles (e.g., Manager, Individual Contributor) | Role filter is applied and displayed in the active filters section |
| 7 | Click the 'Generate Report' button | Report generation begins with a loading indicator displayed. Report completes generation within 5 seconds |
| 8 | Review the generated report display | Report displays trend charts showing performance metrics over time with proper axis labels and legends. Summary tables show aggregated data filtered by selected criteria. Data matches the applied filters (date, department, role) |
| 9 | Verify the accuracy of displayed data by comparing with source data | Report data is accurate with 95% or higher accuracy rate. All filtered data points are correctly represented in charts and tables |

**Postconditions:**
- Report is successfully generated and displayed on screen
- Report data reflects all applied filters
- System logs the report generation activity
- Report remains accessible for export or further analysis
- User session remains active

---

### Test Case: Validate report export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Performance Analyst
- User has successfully generated a report with metrics and filters
- Report is currently displayed on screen
- User has appropriate permissions to export reports
- Browser download settings allow automatic downloads
- Sufficient disk space available for file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify that a report is currently displayed on the Reporting page | Report is visible with trend charts and summary tables containing filtered performance data |
| 2 | Locate and click the 'Export' button or dropdown menu | Export options menu is displayed showing available formats (PDF and Excel) |
| 3 | Select 'Export to PDF' option from the export menu | PDF export process initiates with a progress indicator. PDF file is generated and downloaded to the default download location within 5 seconds |
| 4 | Open the downloaded PDF file using a PDF reader | PDF file opens successfully without errors. File contains all report elements including charts, tables, headers, and footers. Data in PDF matches the on-screen report exactly. Charts are rendered clearly with proper resolution. All applied filters are documented in the report header |
| 5 | Return to the Reporting page and click the 'Export' button again | Export options menu is displayed again |
| 6 | Select 'Export to Excel' option from the export menu | Excel export process initiates with a progress indicator. Excel file (.xlsx) is generated and downloaded to the default download location within 5 seconds |
| 7 | Open the downloaded Excel file using Microsoft Excel or compatible spreadsheet application | Excel file opens successfully without errors. File contains multiple sheets if applicable (Summary, Detailed Data, Charts). Data in Excel matches the on-screen report exactly. All numerical data is formatted correctly and editable. Charts are embedded as Excel chart objects. Column headers are properly labeled. All applied filters are documented in a summary sheet |
| 8 | Verify data integrity by spot-checking key metrics in both PDF and Excel exports against the on-screen report | All data points match across all three formats (on-screen, PDF, Excel) with 100% accuracy |

**Postconditions:**
- PDF file is successfully downloaded and contains accurate report data
- Excel file is successfully downloaded and contains accurate report data
- Both exported files are accessible and readable
- Original report remains displayed on screen
- Export activity is logged in the system
- User session remains active

---

## Story: As System Administrator, I want to manage user roles and permissions for performance monitoring features to ensure secure access control
**Story ID:** story-21

### Test Case: Validate role creation and assignment
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as System Administrator
- User has full administrative privileges
- User Management page is accessible
- At least one user account exists in the system for role assignment
- Performance monitoring features are configured and available
- Database connection is active and stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the User Management page from the admin dashboard or main navigation menu | User Management page is displayed showing existing users, roles, and management options. Page loads within 3 seconds |
| 2 | Click on the 'Roles' tab or 'Manage Roles' button | Roles management interface is displayed showing list of existing roles and a 'Create New Role' button |
| 3 | Click the 'Create New Role' button | Role creation form is displayed with fields for role name, description, and permissions checkboxes |
| 4 | Enter a unique role name (e.g., 'Performance Reviewer') in the role name field | Role name is accepted and displayed in the input field without validation errors |
| 5 | Enter a description for the role (e.g., 'Can view and review performance metrics but cannot generate reports') | Description is accepted and displayed in the description field |
| 6 | Select specific permissions from the available options by checking relevant checkboxes (e.g., 'View Performance Metrics', 'View Review Cycles', but not 'Generate Reports' or 'Export Data') | Selected permissions are checked and highlighted. Permission count updates to reflect selections |
| 7 | Click the 'Save Role' or 'Create Role' button | Role is created successfully. Success message is displayed (e.g., 'Role created successfully'). New role appears in the roles list. System logs the role creation with timestamp and admin user ID |
| 8 | Navigate to the 'Users' tab or section within User Management | Users list is displayed showing all user accounts with their current roles |
| 9 | Select a user from the list by clicking on their name or 'Edit' button | User details page or modal is displayed showing user information and current role assignments |
| 10 | Click on 'Assign Role' or 'Edit Roles' button | Role assignment interface is displayed with a dropdown or list of available roles including the newly created role |
| 11 | Select the newly created role (e.g., 'Performance Reviewer') from the available roles list | Role is selected and highlighted in the interface |
| 12 | Click 'Save' or 'Assign' button to assign the role to the user | Role is assigned successfully. Success message is displayed (e.g., 'Role assigned successfully'). User's role list is updated to include the new role. System logs the role assignment with timestamp and admin user ID |
| 13 | Verify that the role assignment takes effect immediately by checking the user's permissions | User's permissions are updated immediately without requiring logout or system restart. User now has access to features defined by the assigned role. Permission changes are reflected in real-time |
| 14 | Navigate to the audit log or activity log section | Audit log displays entries for role creation and role assignment with correct timestamps, admin user information, and details of changes made |

**Postconditions:**
- New role is created and stored in the database
- Role is visible in the roles management list
- User has been assigned the new role successfully
- User's permissions reflect the assigned role immediately
- All changes are logged in the audit trail
- System maintains data integrity and consistency
- Admin session remains active

---

### Test Case: Verify access restriction based on roles
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Two test user accounts exist in the system
- First user account has no role assigned or has a role without performance monitoring permissions
- Second user account has a role with specific performance monitoring permissions assigned
- Performance monitoring features are active and accessible
- Role-based access control is properly configured
- Test environment is isolated to prevent affecting production users

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log out from the System Administrator account if currently logged in | Successfully logged out and redirected to the login page |
| 2 | Log in using credentials of the user without the required role for performance monitoring | Login is successful. User is authenticated and redirected to their default dashboard or home page |
| 3 | Attempt to navigate to the Performance Metrics page by clicking on the navigation menu or entering the URL directly | Access is denied. User receives an error message (e.g., 'Access Denied: You do not have permission to view this page' or 'Unauthorized Access'). User is either redirected to their home page or shown a 403 Forbidden page. Navigation menu does not display restricted features |
| 4 | Attempt to navigate to the Review Cycles page | Access is denied with appropriate error message. User cannot access the restricted feature |
| 5 | Attempt to navigate to the Reporting page | Access is denied with appropriate error message. User cannot access the restricted feature |
| 6 | Attempt to access restricted API endpoints directly using browser developer tools or API testing tool (e.g., GET /api/reports/performance) | API returns 403 Forbidden or 401 Unauthorized status code. No sensitive data is returned. Error response includes appropriate message about insufficient permissions |
| 7 | Verify that the user can only access features appropriate to their role or default user permissions | User can access only non-restricted features. UI correctly hides or disables restricted menu items and buttons |
| 8 | Log out from the restricted user account | Successfully logged out and redirected to the login page |
| 9 | Log in using credentials of the user with the assigned role that includes performance monitoring permissions | Login is successful. User is authenticated and redirected to their dashboard |
| 10 | Navigate to the Performance Metrics page | Access is granted. Performance Metrics page loads successfully. User can view performance metrics data according to their role permissions. Page displays within 3 seconds |
| 11 | Navigate to the Review Cycles page | Access is granted. Review Cycles page loads successfully. User can view review cycle information according to their role permissions |
| 12 | Navigate to the Reporting page | Access is granted if role includes reporting permissions. User can access reporting features according to their specific role permissions. All permitted features are functional |
| 13 | Verify that the user can perform actions allowed by their role (e.g., view metrics, generate reports if permitted) | All actions permitted by the assigned role are functional and accessible. User can successfully complete tasks within their permission scope |
| 14 | Attempt to access features not included in the user's role permissions | Access to unpermitted features is denied even for users with some permissions. System enforces granular permission control. Appropriate error messages are displayed for denied actions |
| 15 | Check audit logs for access attempts | All access attempts (both successful and denied) are logged with timestamps, user information, and accessed resources. Unauthorized access attempts are clearly marked in the logs |

**Postconditions:**
- Users without required roles cannot access restricted performance monitoring features
- Users with assigned roles can access permitted features successfully
- No unauthorized access to sensitive performance data occurred
- All access attempts are logged in the audit trail
- System security and data integrity are maintained
- Role-based access control is functioning as designed
- Test users are logged out

---

## Story: As Performance Manager, I want to export performance metrics and review data to share with stakeholders
**Story ID:** story-24

### Test Case: Validate successful export of selected data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Performance Manager with export permissions
- Performance metrics and review data are available in the system
- Browser supports file downloads
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics or Review Data page | Metrics or Review Data page is displayed with available data sets and export option visible |
| 2 | Select specific data sets to export using checkboxes or selection controls | Selected data sets are highlighted and selection count is displayed |
| 3 | Choose export format from dropdown (PDF or Excel) | Export format is selected and displayed in the format selector |
| 4 | Click the 'Export' or 'Download' button to initiate export | Export process begins, progress indicator is shown, and file generation starts |
| 5 | Wait for file generation to complete | File is generated within 10 seconds and download prompt appears or file automatically downloads |
| 6 | Verify the downloaded file is saved to the local system | File is successfully downloaded with correct filename, format extension, and contains the selected data matching applied filters and criteria |

**Postconditions:**
- Export file is saved to user's download folder
- File contains accurate data matching the selected criteria
- Export action is logged in system audit trail
- User remains on the same page ready for additional operations

---

### Test Case: Verify access control for export functionality
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with unauthorized role (not Performance Manager)
- Export functionality exists in the system
- Access control rules are configured properly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to Metrics or Review Data page as unauthorized user | Page loads but export functionality is either hidden or disabled |
| 2 | Attempt to access export feature by clicking export button or using direct URL to export endpoint | Access is denied with appropriate error message (e.g., 'You do not have permission to export data' or 403 Forbidden), and no export file is generated |
| 3 | Verify that no export options or buttons are accessible to the unauthorized user | Export controls remain disabled or hidden, preventing any export attempts |

**Postconditions:**
- No data is exported
- Access denial is logged in security audit trail
- User remains on current page without system disruption
- System security integrity is maintained

---

