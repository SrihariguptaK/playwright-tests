# Manual Test Cases

## Story: As HR Officer, I want to delete incorrect manual attendance records to maintain data integrity
**Story ID:** story-5

### Test Case: Delete manual attendance record with confirmation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- HR officer account with delete permissions exists in the system
- At least one manual attendance record exists in the database
- User has valid login credentials for authorized HR officer account
- Manual attendance records module is accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid HR officer credentials (username and password) | User is successfully authenticated and redirected to the HR dashboard |
| 2 | Navigate to the manual attendance records section from the main menu | Manual attendance records page is displayed with a list of existing records and search/filter options |
| 3 | Locate the specific manual attendance record to be deleted using search or browse functionality | Target manual attendance record is visible in the list with all relevant details (employee name, date, time, etc.) |
| 4 | Click on the delete button/icon associated with the selected manual attendance record | A confirmation dialog box appears with warning message asking 'Are you sure you want to delete this attendance record?' with options to Confirm or Cancel |
| 5 | Review the record details displayed in the confirmation prompt and click the 'Confirm' button | The record is successfully deleted from the system and a success confirmation message is displayed (e.g., 'Attendance record deleted successfully') |
| 6 | Verify the deleted record no longer appears in the manual attendance records list | The deleted record is removed from the list and is no longer visible in search results |
| 7 | Check the audit log for the deletion entry | Audit log contains an entry with deletion timestamp, HR officer username, and deleted record details |

**Postconditions:**
- Manual attendance record is permanently deleted from the database
- Deletion is logged in the audit trail with user and timestamp information
- Attendance reports reflect the updated data without the deleted record
- User remains logged in and can perform additional operations

---

### Test Case: Prevent unauthorized deletion attempts
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Unauthorized user account exists in the system without delete permissions
- At least one manual attendance record exists in the database
- User has valid login credentials for unauthorized account
- Role-based access control is properly configured in the system
- API endpoint DELETE /api/attendance/manual/{id} is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter credentials for an unauthorized user (non-HR officer role) | User is successfully authenticated and redirected to their respective dashboard without HR officer privileges |
| 2 | Attempt to navigate to the manual attendance records section or access the delete functionality through the UI | Access is denied - either the menu option is not visible, or an error message is displayed stating 'You do not have permission to access this feature' or similar authorization error |
| 3 | Open API testing tool (e.g., Postman) and construct a DELETE request to /api/attendance/manual/{id} endpoint using the unauthorized user's authentication token | API testing tool is ready with the DELETE request configured with valid record ID and unauthorized user token |
| 4 | Execute the DELETE API request with the unauthorized user's credentials | API returns HTTP 403 Forbidden or 401 Unauthorized status code with error message such as 'Access denied: Insufficient permissions to delete attendance records' |
| 5 | Verify the manual attendance record still exists in the database by querying through an authorized account | The attendance record remains intact and unchanged in the system, confirming no deletion occurred |
| 6 | Check the audit log for any unauthorized access attempts | Audit log contains an entry recording the failed deletion attempt with unauthorized user details and timestamp |

**Postconditions:**
- Manual attendance record remains unchanged in the database
- No deletion is logged in the audit trail
- Unauthorized access attempt is recorded in security logs
- System security integrity is maintained
- Unauthorized user remains unable to delete records

---

