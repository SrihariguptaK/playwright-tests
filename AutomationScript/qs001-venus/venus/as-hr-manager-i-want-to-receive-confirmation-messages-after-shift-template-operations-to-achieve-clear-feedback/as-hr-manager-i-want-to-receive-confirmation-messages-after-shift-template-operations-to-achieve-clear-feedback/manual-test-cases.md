# Manual Test Cases

## Story: As HR Manager, I want to receive confirmation messages after shift template operations to achieve clear feedback
**Story ID:** db-story-story-8

### Test Case: Verify success message displays after shift template creation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to create shift templates
- User is on the shift template management page
- All required fields for shift template creation are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template creation page | Shift template creation form is displayed with all required fields |
| 2 | Fill in all required fields (template name, shift hours, break times, etc.) | All fields accept valid input and display entered data correctly |
| 3 | Click the 'Create' or 'Save' button to submit the shift template | System processes the request and submits the data |
| 4 | Observe the notification area for confirmation message | A clear success message is displayed (e.g., 'Shift template created successfully') within 2 seconds |
| 5 | Verify the message content and visibility | Message is clearly visible, uses appropriate color coding (green for success), and contains specific details about the created template |

**Postconditions:**
- New shift template is saved in the system
- Success message is visible to the user
- User can proceed with other operations
- Template appears in the shift template list

---

### Test Case: Verify success message displays after shift template update
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to edit shift templates
- At least one shift template exists in the system
- User is on the shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select an existing shift template from the list | Shift template details are displayed |
| 2 | Click the 'Edit' button or icon | Shift template edit form opens with current values populated |
| 3 | Modify one or more fields (e.g., change shift hours, update template name) | Modified fields accept the new input and display changes |
| 4 | Click the 'Update' or 'Save Changes' button | System processes the update request |
| 5 | Observe the notification area for confirmation message | A clear success message is displayed (e.g., 'Shift template updated successfully') within 2 seconds |
| 6 | Verify the updated template reflects the changes | Template list shows the updated information |

**Postconditions:**
- Shift template is updated with new values
- Success message is displayed and visible
- Changes are persisted in the database
- User remains on the template management page

---

### Test Case: Verify success message displays after shift template deletion
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to delete shift templates
- At least one shift template exists that can be deleted
- User is on the shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate a shift template to delete from the list | Shift template is visible in the list with delete option available |
| 2 | Click the 'Delete' button or icon for the selected template | Confirmation dialog appears asking to confirm deletion |
| 3 | Click 'Confirm' or 'Yes' in the confirmation dialog | System processes the deletion request |
| 4 | Observe the notification area for confirmation message | A clear success message is displayed (e.g., 'Shift template deleted successfully') within 2 seconds |
| 5 | Verify the template is removed from the list | Deleted template no longer appears in the shift template list |

**Postconditions:**
- Shift template is permanently deleted from the system
- Success message is displayed to the user
- Template list is updated to reflect the deletion
- User can continue with other operations

---

### Test Case: Verify descriptive error message displays when shift template creation fails due to missing required fields
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to create shift templates
- User is on the shift template creation page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the shift template creation form | Creation form is displayed with all fields |
| 2 | Leave one or more required fields empty (e.g., template name) | Fields remain empty |
| 3 | Click the 'Create' or 'Save' button | System validates the form |
| 4 | Observe the notification area and form validation | A descriptive error message is displayed (e.g., 'Template name is required') with clear indication of which fields are missing |
| 5 | Verify the error message provides actionable guidance | Error message uses appropriate color coding (red), specifies the exact issue, and guides user on how to fix it |

**Postconditions:**
- No shift template is created
- User remains on the creation form
- Error message is clearly visible
- Form data is retained for correction

---

### Test Case: Verify descriptive error message displays when shift template update fails due to validation errors
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to edit shift templates
- At least one shift template exists in the system
- User is on the shift template edit page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open an existing shift template for editing | Edit form is displayed with current values |
| 2 | Enter invalid data in one or more fields (e.g., negative shift hours, invalid time format) | Invalid data is entered in the field |
| 3 | Click the 'Update' or 'Save Changes' button | System validates the input |
| 4 | Observe the notification area for error message | A descriptive error message is displayed (e.g., 'Shift hours must be a positive number') clearly indicating the validation issue |
| 5 | Verify the error message provides specific details | Error message specifies which field has the issue and what the valid format or range should be |

**Postconditions:**
- Shift template is not updated
- User remains on the edit form
- Error message is visible with actionable details
- Original template data remains unchanged

---

### Test Case: Verify descriptive error message displays when shift template deletion fails due to dependencies
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to delete shift templates
- A shift template exists that is currently in use or has dependencies
- User is on the shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate a shift template that has active dependencies (e.g., assigned to employees or schedules) | Template is visible in the list |
| 2 | Click the 'Delete' button for the template | Confirmation dialog appears |
| 3 | Confirm the deletion action | System attempts to process the deletion |
| 4 | Observe the notification area for error message | A descriptive error message is displayed (e.g., 'Cannot delete template: currently assigned to 5 employees') explaining why deletion failed |
| 5 | Verify the error message provides actionable guidance | Error message suggests next steps (e.g., 'Remove assignments before deleting') and uses appropriate error styling |

**Postconditions:**
- Shift template is not deleted
- Template remains in the system with all dependencies intact
- Error message is clearly displayed
- User can take corrective action based on the message

---

### Test Case: Verify error message displays when network or server error occurs during shift template operation
- **ID:** tc-007
- **Type:** error-case
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to perform shift template operations
- Network connectivity issues or server error condition can be simulated
- User is on the shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Initiate any shift template operation (create, update, or delete) | Operation form or confirmation is displayed |
| 2 | Simulate network disconnection or server error (e.g., disconnect network, simulate 500 error) | Network or server becomes unavailable |
| 3 | Submit the operation | System attempts to process the request |
| 4 | Observe the notification area for error message | A descriptive error message is displayed (e.g., 'Unable to connect to server. Please check your connection and try again') within a reasonable timeout period |
| 5 | Verify the error message provides helpful guidance | Error message explains the issue clearly and suggests troubleshooting steps |

**Postconditions:**
- Operation is not completed
- Error message is displayed with clear explanation
- User can retry the operation once connectivity is restored
- No partial data is saved

---

### Test Case: Verify confirmation messages are accessible and comply with WCAG standards
- **ID:** tc-008
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as HR Manager
- Screen reader software is available for testing
- User has permissions to perform shift template operations
- Accessibility testing tools are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Enable screen reader software (e.g., NVDA, JAWS) | Screen reader is active and functioning |
| 2 | Perform a shift template creation operation | Template is created successfully |
| 3 | Listen to the screen reader announcement of the success message | Screen reader announces the success message clearly and completely with appropriate ARIA labels |
| 4 | Verify the message has proper ARIA attributes (role='alert' or role='status') | Message container has appropriate ARIA attributes for accessibility |
| 5 | Check color contrast ratio of the message using accessibility tools | Message text has sufficient contrast ratio (minimum 4.5:1 for normal text) meeting WCAG AA standards |
| 6 | Navigate to the message using keyboard only (Tab key) | Message is keyboard accessible and can be focused if interactive |
| 7 | Verify message remains visible for adequate time or can be dismissed | Message stays visible long enough to be read (minimum 5 seconds) or has a dismiss button |

**Postconditions:**
- All confirmation messages meet WCAG 2.1 AA standards
- Messages are fully accessible via screen readers
- Keyboard navigation works properly
- Color contrast requirements are met

---

### Test Case: Verify error messages are accessible and comply with WCAG standards
- **ID:** tc-009
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as HR Manager
- Screen reader software is available for testing
- User has permissions to perform shift template operations
- Accessibility testing tools are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Enable screen reader software | Screen reader is active |
| 2 | Trigger an error condition (e.g., submit form with missing required fields) | Error condition is triggered |
| 3 | Listen to the screen reader announcement of the error message | Screen reader announces the error message with appropriate urgency and clarity, including ARIA live region announcements |
| 4 | Verify error message has proper ARIA attributes (role='alert', aria-live='assertive') | Error message container has appropriate ARIA attributes for immediate announcement |
| 5 | Check color contrast of error message text and icons | Error message meets WCAG contrast requirements (4.5:1 minimum) and does not rely solely on color to convey meaning |
| 6 | Verify error message is associated with the relevant form field using aria-describedby | Error message is programmatically linked to the field that caused the error |
| 7 | Navigate to error message and associated fields using keyboard only | All error elements are keyboard accessible and focus is managed appropriately |

**Postconditions:**
- All error messages meet WCAG 2.1 AA standards
- Error messages are fully accessible via assistive technologies
- Error indication does not rely solely on color
- Keyboard users can access and understand all error information

---

### Test Case: Verify notifications are displayed promptly after shift template creation
- **ID:** tc-010
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to create shift templates
- User is on the shift template creation page
- System performance is normal

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current time or start a timer | Timer is ready to measure response time |
| 2 | Fill in all required fields for shift template creation | All fields are populated with valid data |
| 3 | Click the 'Create' or 'Save' button | System begins processing the request |
| 4 | Measure the time until the success notification appears | Success notification is displayed within 2 seconds of clicking the submit button |
| 5 | Verify the notification appears without requiring page refresh | Notification appears dynamically without full page reload |

**Postconditions:**
- Shift template is created successfully
- Notification appears within acceptable time frame (≤2 seconds)
- User receives immediate feedback on the operation
- System performance meets responsiveness requirements

---

### Test Case: Verify notifications are displayed promptly after shift template update
- **ID:** tc-011
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to edit shift templates
- At least one shift template exists in the system
- User is on the shift template edit page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open an existing shift template for editing | Edit form is displayed with current values |
| 2 | Make changes to one or more fields | Changes are entered successfully |
| 3 | Start a timer and click the 'Update' or 'Save Changes' button | System begins processing the update |
| 4 | Measure the time until the success notification appears | Success notification is displayed within 2 seconds of clicking the update button |
| 5 | Verify the notification appears immediately without delay | Notification is displayed promptly and dynamically |

**Postconditions:**
- Shift template is updated successfully
- Notification appears within 2 seconds
- User receives timely feedback
- Updated data is reflected in the system

---

### Test Case: Verify notifications are displayed promptly after shift template deletion
- **ID:** tc-012
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to delete shift templates
- At least one deletable shift template exists
- User is on the shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a shift template to delete | Template is selected and delete option is available |
| 2 | Click the 'Delete' button | Confirmation dialog appears |
| 3 | Start a timer and confirm the deletion | System begins processing the deletion |
| 4 | Measure the time until the success notification appears | Success notification is displayed within 2 seconds of confirming deletion |
| 5 | Verify the notification appears immediately and the template is removed from the list | Notification is displayed promptly and template list is updated in real-time |

**Postconditions:**
- Shift template is deleted successfully
- Notification appears within 2 seconds
- Template is removed from the list
- User receives immediate confirmation of deletion

---

### Test Case: Verify notification messages comply with UI design standards and consistency
- **ID:** tc-013
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to perform shift template operations
- UI design standards documentation is available
- User is on the shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Perform a shift template creation and observe the success notification | Success notification appears with consistent styling (color, font, size, position) |
| 2 | Verify the notification uses the standard success color (typically green) and icon | Notification uses consistent success indicators matching UI standards |
| 3 | Perform a shift template update and observe the success notification | Update notification has the same styling, position, and format as creation notification |
| 4 | Trigger an error condition and observe the error notification | Error notification uses consistent error styling (typically red) with appropriate icon |
| 5 | Verify notification positioning is consistent across all operations | All notifications appear in the same location (e.g., top-right corner, top of page) |
| 6 | Check that notification text follows consistent formatting and tone | All messages use consistent language style, capitalization, and punctuation |
| 7 | Verify notification dismiss behavior is consistent (auto-dismiss or manual close) | All notifications have the same dismiss mechanism and timing |

**Postconditions:**
- All notifications follow UI design standards
- Consistent styling is maintained across all message types
- User experience is uniform across all operations
- Notifications meet brand and design guidelines

---

### Test Case: Verify notification messages use modal dialogs appropriately for critical operations
- **ID:** tc-014
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to perform shift template operations
- User is on the shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Initiate a shift template deletion operation | Delete button is clicked |
| 2 | Observe if a modal dialog appears for confirmation | Modal dialog appears asking for deletion confirmation, blocking other interactions |
| 3 | Verify the modal contains clear messaging about the action consequences | Modal displays warning message explaining that deletion is permanent or has specific consequences |
| 4 | Confirm the deletion in the modal | Modal closes and success notification appears |
| 5 | Perform a non-critical operation like template creation | Success notification appears as inline notification or toast, not as modal |
| 6 | Verify that modal dialogs are used only for operations requiring explicit confirmation | Modal dialogs are reserved for critical actions (delete, bulk operations), while inline notifications are used for standard operations |

**Postconditions:**
- Modal dialogs are used appropriately for critical operations
- Inline notifications are used for standard feedback
- User interaction patterns are intuitive and consistent
- Critical operations require explicit confirmation

---

### Test Case: Verify notification messages use inline notifications appropriately for standard operations
- **ID:** tc-015
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as HR Manager
- User has permissions to perform shift template operations
- User is on the shift template management page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a new shift template | Template creation form is submitted successfully |
| 2 | Observe the type of notification displayed | An inline notification or toast message appears (not a modal dialog) showing success message |
| 3 | Verify the inline notification does not block user interaction with the page | User can continue interacting with the page while notification is visible |
| 4 | Update an existing shift template | Template update is submitted successfully |
| 5 | Observe the notification type for update operation | Inline notification appears with update success message, allowing continued page interaction |
| 6 | Verify the notification auto-dismisses after appropriate time or has a close button | Notification either disappears automatically after 5-10 seconds or provides a close/dismiss button |
| 7 | Check that inline notifications appear in a consistent location | All inline notifications appear in the same designated area (e.g., top-right corner, banner area) |

**Postconditions:**
- Inline notifications are used for standard operations
- User workflow is not interrupted by notifications
- Notifications are dismissible or auto-dismiss
- Consistent notification placement is maintained

---

