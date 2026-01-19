# Manual Test Cases

## Story: As Scheduling Manager, I want to create shift templates to achieve standardized shift definitions
**Story ID:** story-1

### Test Case: Validate successful creation of shift template with valid input
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with valid credentials
- User has permission to create shift templates
- Shift template creation page is accessible
- Database connection is active and ShiftTemplates table is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking on 'Shift Templates' menu and selecting 'Create New Template' | Shift template form is displayed with fields for template name, start time, end time, and break periods. All fields are empty and enabled for input |
| 2 | Enter template name as 'Morning Shift', start time as '08:00 AM', end time as '04:00 PM', and break period as '12:00 PM - 12:30 PM' | All entered values are displayed correctly in their respective fields. No validation errors are shown. Form remains in editable state |
| 3 | Click the 'Save Template' button to submit the form | Shift template is saved successfully to the ShiftTemplates table. A confirmation message 'Shift template created successfully' is displayed. The new template appears in the templates list with all entered details |

**Postconditions:**
- New shift template 'Morning Shift' is saved in the database
- Template is available for reuse in schedule creation
- User remains on the shift template management page
- Template count is incremented by one

---

### Test Case: Reject creation of shift template with invalid time ranges
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with valid credentials
- User has permission to create shift templates
- Shift template creation page is accessible
- Validation rules are configured: start time must be before end time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template creation page by clicking on 'Shift Templates' menu and selecting 'Create New Template' | Shift template form is displayed with empty fields for template name, start time, end time, and break periods |
| 2 | Enter template name as 'Invalid Shift', start time as '05:00 PM', and end time as '09:00 AM' (end time before start time) | Validation error message is displayed: 'End time must be after start time'. Error message appears in red text near the time fields. Save button may be disabled or highlighted as invalid |
| 3 | Attempt to submit the form by clicking the 'Save Template' button | Form submission is blocked. Error message persists: 'Please correct the errors before submitting'. No data is sent to the server. Template is not created in the database |

**Postconditions:**
- No new shift template is created in the database
- User remains on the shift template creation page with error messages visible
- Form fields retain the invalid values entered for correction
- Template count remains unchanged

---

### Test Case: Restrict template creation to authorized scheduling managers
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- A non-manager user account exists in the system (e.g., regular employee or staff member)
- Role-based access control is configured and active
- Shift template creation requires 'Scheduling Manager' role
- API endpoint POST /api/shifttemplates is protected with authorization

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-manager user credentials (username: 'employee01', password: 'password123') | User is successfully logged in with non-manager role. Dashboard or home page is displayed without scheduling management options |
| 2 | Attempt to access shift template creation page by navigating to the URL directly or through menu (if visible) | Access to shift template creation page is denied. System displays 'Access Denied' or '403 Forbidden' error message. User is redirected to unauthorized access page or remains on current page with error notification |
| 3 | Attempt to access the API endpoint directly by sending POST request to '/api/shifttemplates' with valid shift template data using the non-manager user's authentication token | API returns HTTP 401 Unauthorized or 403 Forbidden error response. Response body contains error message: 'You do not have permission to create shift templates'. No template is created in the database |

**Postconditions:**
- No shift template is created by the non-manager user
- Security audit log records the unauthorized access attempt
- User session remains active but without elevated privileges
- System security integrity is maintained

---

## Story: As Scheduling Manager, I want to edit existing shift templates to update shift details
**Story ID:** story-2

### Test Case: Edit shift template successfully with valid data
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with valid credentials
- At least one shift template exists in the system (e.g., 'Morning Shift' with start time 08:00 AM, end time 04:00 PM)
- The template to be edited is not assigned to any active schedules
- Version history tracking is enabled in the system
- Database connection is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management page by clicking on 'Shift Templates' menu and selecting 'View All Templates' | List of existing shift templates is displayed in a table or grid format showing template names, start times, end times, and version numbers. At least one template 'Morning Shift' is visible in the list |
| 2 | Select the 'Morning Shift' template by clicking on it or clicking the 'Edit' button associated with the template | Edit form is opened and populated with current template data: Name: 'Morning Shift', Start Time: '08:00 AM', End Time: '04:00 PM', Break: '12:00 PM - 12:30 PM'. All fields are editable. Current version number is displayed |
| 3 | Modify the end time from '04:00 PM' to '05:00 PM' and update break period to '12:30 PM - 01:00 PM', then click 'Save Changes' button | Template is saved as a new version (version incremented by 1). Confirmation message is displayed: 'Shift template updated successfully. New version created'. Updated template appears in the list with new end time '05:00 PM' and updated break period. Previous version is preserved in version history |

**Postconditions:**
- Shift template 'Morning Shift' is updated with new end time and break period
- New version of the template is created and stored in the database
- Previous version remains accessible in version history
- Template is available for schedule assignment with updated details
- User remains on the shift template management page

---

### Test Case: Prevent editing of templates assigned to active schedules
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with valid credentials
- A shift template exists that is currently assigned to one or more active schedules (e.g., 'Evening Shift' assigned to schedules for current week)
- Active schedule status is properly tracked in the system
- Business rule is configured to prevent editing of templates in use

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template management page and locate the 'Evening Shift' template that is assigned to active schedules | Template list is displayed. 'Evening Shift' template is visible with an indicator showing it is currently in use (e.g., badge or icon showing 'In Use' or 'Active') |
| 2 | Attempt to edit the 'Evening Shift' template by clicking on it or clicking the 'Edit' button | System displays error message: 'This template is currently assigned to active schedules and cannot be edited'. Edit form is not opened or is opened in read-only mode. Edit functionality is blocked with visual indication (disabled save button or warning banner) |

**Postconditions:**
- Template 'Evening Shift' remains unchanged in the database
- Active schedules using this template are not affected
- User remains on the template list page with error message visible
- No new version of the template is created
- System integrity is maintained

---

### Test Case: Reject invalid time updates during edit
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as a Scheduling Manager with valid credentials
- A shift template exists that is not assigned to active schedules (e.g., 'Afternoon Shift' with start time 12:00 PM, end time 08:00 PM)
- Validation rules are active: start time must be before end time, breaks must be within shift duration
- Edit form is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list, select 'Afternoon Shift' template, and open the edit form | Edit form is displayed with current values: Start Time: '12:00 PM', End Time: '08:00 PM'. All fields are editable |
| 2 | Change the start time to '09:00 PM' (after the current end time of 08:00 PM) and leave end time unchanged | Validation error message is displayed immediately or upon field blur: 'Start time must be before end time'. Error appears in red text near the time fields. Save button is disabled or highlighted as invalid |
| 3 | Attempt to save the changes by clicking the 'Save Changes' button | Save operation is blocked. Error message persists or is reinforced: 'Please correct the validation errors before saving'. No API call is made. No new version is created. Template data remains unchanged in the database |

**Postconditions:**
- Template 'Afternoon Shift' remains unchanged with original values
- No new version is created in the database
- User remains on the edit form with error messages visible
- Form fields retain the invalid values for correction
- Version count remains unchanged

---

## Story: As Scheduling Manager, I want to delete unused shift templates to maintain template list hygiene
**Story ID:** story-3

### Test Case: Delete unused shift template successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Scheduling Manager with delete permissions
- At least one shift template exists that is not assigned to any active or future schedules
- Shift template list page is accessible
- Database contains shift templates and schedule assignments data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page | Shift template list is displayed showing all available templates with usage status indicators and delete options visible for unused templates |
| 2 | Identify and select the delete button/icon on an unused shift template | Confirmation dialog appears with message asking 'Are you sure you want to delete this shift template?' with Cancel and Confirm buttons |
| 3 | Click the Confirm button in the confirmation dialog | Template is successfully deleted, confirmation dialog closes, success message is displayed, and the deleted template is immediately removed from the template list |

**Postconditions:**
- Deleted shift template no longer appears in the template list
- Template record is removed from the database
- Template list count is decremented by one
- Success notification is displayed to the user

---

### Test Case: Prevent deletion of templates assigned to active schedules
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 2 mins

**Preconditions:**
- User is logged in as Scheduling Manager with delete permissions
- At least one shift template exists that is assigned to an active or future schedule
- Shift template list page is accessible
- Database contains shift templates with active schedule assignments

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page and identify a template that is assigned to an active schedule | Shift template list is displayed with templates showing usage status indicating which templates are in use |
| 2 | Attempt to delete the template that is assigned to an active schedule by clicking the delete button/icon | System displays an error message stating 'Cannot delete template: This template is currently assigned to active or future schedules' and the deletion action is blocked without showing confirmation dialog |

**Postconditions:**
- Template remains in the template list unchanged
- Template assignment to active schedules remains intact
- Error message is displayed to the user
- No data is modified in the database

---

## Story: As Scheduling Manager, I want to categorize shift templates to organize them for easier selection
**Story ID:** story-9

### Test Case: Create and assign shift template categories
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as Scheduling Manager with category management permissions
- Category management interface is accessible
- At least one shift template exists in the system
- Database is configured to store shift template categories

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to category management section and click 'Create New Category' button | Category creation form is displayed with fields for category name and description |
| 2 | Enter 'Weekend' as the category name and click Save/Submit button | Category 'Weekend' is successfully created, saved to the database, and appears in the category list with success confirmation message |
| 3 | Navigate to shift template list or template details page and select a shift template to edit | Template edit interface is displayed with category assignment options showing available categories including 'Weekend' |
| 4 | Select 'Weekend' category from the available categories and save the template assignment | Shift template is successfully associated with 'Weekend' category, confirmation message is displayed, and the template now shows 'Weekend' as an assigned category |

**Postconditions:**
- Category 'Weekend' exists in the system and is visible in category list
- Selected shift template is associated with 'Weekend' category in the database
- Template displays category assignment in the template list view
- Category is available for filtering and future template assignments

---

### Test Case: Filter shift templates by category
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- Category 'Weekend' exists in the system
- At least one shift template is assigned to 'Weekend' category
- At least one shift template exists that is NOT assigned to 'Weekend' category
- Shift template list page with filtering capability is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to shift template list page | Complete list of all shift templates is displayed with category filter options visible in the UI |
| 2 | Locate the category filter dropdown/selector and select 'Weekend' category from the available options | Template list is immediately filtered and refreshed to display only templates that are categorized as 'Weekend', excluding all other templates. Filter indicator shows 'Weekend' as active filter |
| 3 | Verify the filtered results by checking each displayed template's category assignment | All displayed templates show 'Weekend' category assignment and no templates from other categories are visible in the list |

**Postconditions:**
- Template list shows only 'Weekend' categorized templates
- Filter state is maintained if user navigates within the page
- Template count reflects the number of filtered templates
- User can clear filter to return to full template list

---

## Story: As Scheduling Manager, I want to search shift templates by name or attributes to quickly find needed templates
**Story ID:** story-10

### Test Case: Search shift templates by name
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- Shift template management page is accessible
- Multiple shift templates exist in the system with various names
- At least one template contains the partial name to be searched

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template management page | Shift template management page loads successfully with search box visible |
| 2 | Locate the search box for template name | Search box is clearly visible and enabled for input |
| 3 | Enter partial template name in search box (e.g., 'Morn' for 'Morning Shift') | Text is entered successfully in the search box |
| 4 | Observe the template list as characters are typed | Matching templates are displayed dynamically without requiring a submit button, showing all templates containing 'Morn' in their name |
| 5 | Verify the displayed templates contain the searched partial name | All displayed templates have names that include the partial match 'Morn' and non-matching templates are filtered out |

**Postconditions:**
- Search results display only templates matching the partial name entered
- Original template list can be restored by clearing the search box
- System remains in a stable state ready for further searches

---

### Test Case: Filter search results by category
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as Scheduling Manager
- Shift template management page is accessible
- Multiple shift templates exist across different categories
- At least one template exists in the 'Morning' category
- Category filter option is available on the page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template management page | Shift template management page loads successfully with all templates displayed |
| 2 | Locate the category filter dropdown or selection control | Category filter control is visible and accessible with available category options |
| 3 | Click on the category filter control | Category filter expands showing all available categories including 'Morning' |
| 4 | Apply category filter by selecting 'Morning' from the available options | The 'Morning' category is selected and visually indicated as active |
| 5 | Observe the template list after applying the filter | Search results update dynamically to show only templates categorized as 'Morning' |
| 6 | Verify all displayed templates belong to the 'Morning' category | All visible templates have 'Morning' as their category and templates from other categories are not displayed |

**Postconditions:**
- Only 'Morning' category templates are displayed in the results
- Filter remains active until changed or cleared by the user
- User can remove filter to restore full template list
- System maintains filter state for subsequent operations

---

