# Manual Test Cases

## Story: As Administrator, I want to view conflict history logs to audit scheduling issues
**Story ID:** story-15

### Test Case: Verify all conflicts are logged with complete details
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator account with valid credentials exists
- Admin portal is accessible and operational
- Conflict event database is configured and running
- At least one schedulable resource exists in the system
- Test environment is in a clean state with no existing conflicts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by attempting to book the same resource for overlapping time slots | System detects the conflict and prevents the double booking |
| 2 | Create a second scheduling conflict by booking a resource that is already assigned to another event | System detects the second conflict and prevents the booking |
| 3 | Create a third scheduling conflict by attempting to schedule a user who is already scheduled elsewhere | System detects the third conflict and prevents the scheduling |
| 4 | Verify conflicts are recorded in the log database by checking database entries directly or via monitoring tools | All three conflicts are recorded in the conflict event database with timestamps, user details, resource information, and conflict type |
| 5 | Log into the admin portal using administrator credentials | Administrator successfully logs in and is redirected to the admin dashboard |
| 6 | Navigate to the conflict history section from the admin menu | Conflict history page loads successfully displaying the conflict logs interface |
| 7 | Query the conflict logs to retrieve all logged conflicts | All three triggered conflicts appear in the conflict logs with complete details including timestamp, user ID, resource ID, conflict type, and description |
| 8 | Verify each conflict entry contains all required fields: timestamp, user details, resource information, conflict type, and resolution status | Each conflict log entry displays all required fields with accurate and complete information |

**Postconditions:**
- All triggered conflicts remain logged in the database
- Conflict logs are accessible for future auditing
- Administrator session can be safely terminated
- System state is ready for subsequent tests

---

### Test Case: Test administrator access control to conflict logs
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Admin portal is accessible and operational
- Administrator account with valid credentials exists
- Non-administrator user account with valid credentials exists
- Role-based access control is configured and enabled
- Conflict logs contain at least one conflict entry
- API endpoint GET /api/admin/conflicts is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using non-administrator user credentials | Non-admin user successfully logs in and is redirected to the standard user dashboard |
| 2 | Attempt to navigate to the conflict logs section by entering the admin conflict history URL directly | Access is denied and user receives an appropriate error message indicating insufficient permissions |
| 3 | Attempt to access conflict logs via API by sending GET request to /api/admin/conflicts using non-admin user authentication token | API returns 403 Forbidden status code with error message indicating unauthorized access |
| 4 | Verify that no conflict log data is exposed in the error response | Error response contains no sensitive conflict log information |
| 5 | Log out the non-admin user from the system | Non-admin user is successfully logged out and session is terminated |
| 6 | Log into the admin portal using administrator credentials | Administrator successfully logs in and is redirected to the admin dashboard |
| 7 | Navigate to the conflict history section from the admin menu | Access is granted and conflict history page loads successfully |
| 8 | Verify conflict logs are displayed with all conflict entries visible | All conflict logs are displayed with complete details and administrator has full access to view, search, and filter functionality |
| 9 | Send GET request to /api/admin/conflicts using administrator authentication token | API returns 200 OK status code with complete conflict log data in JSON format |

**Postconditions:**
- Non-admin user access denial is logged in security audit logs
- Administrator access is logged in system audit logs
- All user sessions are properly terminated
- Access control mechanisms remain enforced
- System security posture is maintained

---

### Test Case: Validate export functionality for conflict logs
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Administrator account with valid credentials exists
- Admin portal is accessible and operational
- Conflict logs contain at least 5 conflict entries for meaningful export testing
- Export functionality is enabled in the system
- Administrator has necessary permissions to export data
- System supports CSV and PDF export formats

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin portal using administrator credentials | Administrator successfully logs in and is redirected to the admin dashboard |
| 2 | Navigate to the conflict history section from the admin menu | Conflict history page loads successfully displaying conflict logs with export options visible |
| 3 | Verify that conflict logs are displayed and contain multiple entries | At least 5 conflict log entries are visible in the interface |
| 4 | Locate and click the export option button in the conflict logs UI | Export options menu appears showing CSV and PDF format options |
| 5 | Select CSV format from the export options | System initiates CSV export process and download begins |
| 6 | Wait for CSV file download to complete and verify file is saved successfully | CSV file is downloaded successfully with appropriate filename containing timestamp |
| 7 | Open the downloaded CSV file using spreadsheet application | CSV file opens successfully and contains all conflict log entries with proper column headers and data formatting |
| 8 | Verify CSV content includes all required fields: timestamp, user details, resource information, conflict type, and description | All required fields are present in CSV with accurate data matching the displayed logs |
| 9 | Return to the conflict logs interface and click the export option button again | Export options menu appears showing CSV and PDF format options |
| 10 | Select PDF format from the export options | System initiates PDF export process and download begins |
| 11 | Wait for PDF file download to complete and verify file is saved successfully | PDF file is downloaded successfully with appropriate filename containing timestamp |
| 12 | Open the downloaded PDF file using PDF reader application | PDF file opens successfully and displays conflict logs in a well-formatted, readable layout |
| 13 | Verify PDF content includes all required fields and matches the data displayed in the interface | All conflict log entries are present in PDF with complete details, proper formatting, headers, and page layout |

**Postconditions:**
- CSV and PDF export files are successfully saved to local storage
- Exported files contain accurate and complete conflict log data
- Export actions are logged in system audit logs
- Administrator session remains active
- System is ready for additional export operations

---

## Story: As Scheduler, I want suggested resolution options for conflicts to resolve issues quickly
**Story ID:** story-16

### Test Case: Verify generation of resolution suggestions for conflicts
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Scheduler account with valid credentials exists
- Scheduling system is accessible and operational
- At least one resource is available for booking
- Alternative time slots and resources exist in the system
- Suggestion generation engine is configured and running
- API endpoint GET /api/conflicts/suggestions is active
- System performance monitoring tools are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system using scheduler credentials | Scheduler successfully logs in and is redirected to the scheduling dashboard |
| 2 | Navigate to the booking creation interface | Booking creation form loads successfully with all required fields visible |
| 3 | Create an initial booking by selecting a resource, date, and time slot, then save the booking | Initial booking is created successfully and confirmed in the system |
| 4 | Start a timer and attempt to create a second booking with the same resource and overlapping time slot to trigger a scheduling conflict | System detects the scheduling conflict and displays a conflict alert |
| 5 | Stop the timer and verify the time elapsed for suggestion generation | System generates resolution suggestions within 2 seconds of conflict detection |
| 6 | Verify that the conflict alert interface displays the generated suggestions | Suggestions are displayed alongside the conflict alert in a clear, accessible format |
| 7 | Review the suggestions to verify they include alternative time slots | At least one suggestion provides an alternative time slot that does not conflict with existing bookings |
| 8 | Review the suggestions to verify they include alternative resources | At least one suggestion provides an alternative resource available for the requested time slot |
| 9 | Verify each suggested alternative time slot by checking against existing bookings | All suggested time slots are verified to be conflict-free and available |
| 10 | Verify each suggested alternative resource by checking availability status | All suggested resources are verified to be available and conflict-free for the proposed time |

**Postconditions:**
- Conflict remains unresolved until scheduler takes action
- Generated suggestions remain available for scheduler review
- Initial booking remains active in the system
- System is ready for scheduler to apply a suggestion
- Performance metrics for suggestion generation are logged

---

### Test Case: Test application of a suggested resolution
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Scheduler account with valid credentials exists and is logged in
- A scheduling conflict has been triggered
- System has generated at least one valid resolution suggestion
- Conflict alert with suggestions is displayed to the scheduler
- Original conflicting booking exists in the system
- Suggested alternatives have been verified as conflict-free

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Review the displayed resolution suggestions in the conflict alert interface | Multiple resolution suggestions are visible with clear descriptions of alternative time slots or resources |
| 2 | Select the first suggested resolution option by clicking on it | Selected suggestion is highlighted and an 'Apply' or 'Accept' button becomes active |
| 3 | Click the 'Apply' button to apply the selected suggestion | System processes the request and displays a confirmation message |
| 4 | Verify that the booking is updated according to the selected suggestion | Booking details are updated with the new time slot or resource as suggested, and changes are reflected in the booking interface |
| 5 | Navigate to the booking list or calendar view to verify the updated booking | Updated booking appears in the schedule with the new time slot or resource assignment |
| 6 | Verify that the original conflicting booking remains unchanged | Original booking is still present with its original time slot and resource assignment |
| 7 | Trigger the system's conflict validation process by refreshing the schedule or running a conflict check | System initiates validation process to check for any remaining conflicts |
| 8 | Review the validation results to confirm no conflicts are detected | System confirms that no conflicts exist between the updated booking and any other bookings in the schedule |
| 9 | Verify that no conflict alerts or warnings are displayed for the updated booking | No conflict indicators appear for either the original or updated booking |
| 10 | Check the booking status to ensure it is marked as confirmed and active | Updated booking status shows as confirmed with no pending conflicts |

**Postconditions:**
- Booking is successfully updated with the applied suggestion
- No scheduling conflicts exist in the system
- Both original and updated bookings are active and confirmed
- Conflict resolution action is logged in system audit logs
- Schedule integrity is maintained
- System is ready for new booking operations

---

### Test Case: Ensure suggestion generation performance under 2 seconds
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Scheduler account with valid credentials exists
- Scheduling system is accessible and operational
- Multiple resources and time slots are available in the system
- Performance monitoring tools are configured and active
- System is under normal load conditions
- Accurate time measurement capability is available
- Suggestion generation engine is running optimally

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling system using scheduler credentials | Scheduler successfully logs in and is redirected to the scheduling dashboard |
| 2 | Navigate to the booking creation interface | Booking creation form loads successfully |
| 3 | Create an initial booking to establish a conflict scenario | Initial booking is created and saved successfully |
| 4 | Prepare performance monitoring tool or timer to measure response time accurately | Timer is ready and synchronized with system clock |
| 5 | Start the timer immediately before triggering the conflict by attempting to create an overlapping booking | Timer starts recording and conflict is triggered simultaneously |
| 6 | Submit the conflicting booking request to the system | System receives the request and begins conflict detection and suggestion generation process |
| 7 | Monitor the system response and stop the timer when suggestions are displayed | Timer stops when resolution suggestions appear in the interface |
| 8 | Record the elapsed time from conflict trigger to suggestion display | Elapsed time is captured accurately in milliseconds or seconds |
| 9 | Verify that the elapsed time is less than or equal to 2 seconds | Measured time is 2.0 seconds or less, meeting the performance requirement |
| 10 | Verify that suggestions returned are valid and complete | All suggestions include necessary details such as alternative time slots or resources |
| 11 | Repeat the test by triggering another conflict with different parameters | Second conflict is triggered successfully |
| 12 | Measure the suggestion generation time for the second conflict | Second measurement also shows suggestion generation within 2 seconds |
| 13 | Trigger a third conflict scenario and measure performance | Third measurement confirms consistent performance under 2 seconds |
| 14 | Calculate the average suggestion generation time across all three tests | Average time is calculated and documented, confirming consistent performance under 2 seconds |

**Postconditions:**
- Performance metrics are documented and logged
- System demonstrates consistent suggestion generation within 2-second requirement
- All test conflicts remain in the system for potential cleanup
- Performance baseline is established for future monitoring
- System performance meets acceptance criteria

---

## Story: As Administrator, I want to override scheduling restrictions to resolve critical conflicts
**Story ID:** story-18

### Test Case: Verify administrator can override scheduling restrictions
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Administrator role
- Administrator has override permissions enabled
- At least one scheduling conflict exists in the system
- Admin interface is accessible
- Audit logging system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the admin interface and access the override functionality | Override UI is displayed with list of available conflicts and override controls |
| 2 | Select a specific scheduling conflict from the list | Conflict details are displayed including affected resources, users, and time slots |
| 3 | Click on the 'Override' button for the selected conflict | Justification input dialog appears with mandatory text field |
| 4 | Enter valid justification text (e.g., 'Critical business requirement - CEO meeting needs this room') in the justification field | Justification text is accepted and 'Confirm Override' button becomes enabled |
| 5 | Click 'Confirm Override' button to apply the override | Override action is accepted and confirmation message is displayed |
| 6 | Verify the conflict restriction is lifted in the scheduling system | Scheduling conflict is resolved and the restricted slot is now available |
| 7 | Check the audit log for the override entry | Audit log contains new entry with administrator username, timestamp, conflict ID, and justification text |

**Postconditions:**
- Scheduling restriction is successfully overridden
- Override action is logged in audit system with complete details
- Conflict status is updated to 'Overridden' in the database
- System reflects the override within 1 second

---

### Test Case: Ensure affected users receive notifications after override
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Administrator role
- Administrator has override permissions enabled
- Scheduling conflict exists with identified affected users/schedulers
- Notification system is operational
- Affected users have valid email addresses or notification preferences configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to admin interface and select a scheduling conflict that affects multiple users | Conflict details are displayed showing list of affected users/schedulers |
| 2 | Click 'Override' button and enter justification text (e.g., 'Emergency maintenance required') | Justification is accepted and override confirmation dialog appears |
| 3 | Confirm and apply the override action | Override is successfully applied and confirmation message states 'Override applied. Notifications will be sent to affected users.' |
| 4 | Wait for up to 5 minutes and check the notification queue/logs | Notification system shows notifications queued or sent to all affected users |
| 5 | Log in as one of the affected users and check notifications | Notification is received containing override details, justification, and administrator information within 5 minutes |
| 6 | Verify notification content includes conflict details, override reason, and timestamp | Notification contains complete information: conflict ID, affected schedule, override justification, administrator name, and timestamp |

**Postconditions:**
- All affected users have received notifications within 5 minutes
- Notification delivery is logged in the system
- Users are informed of the scheduling change and justification
- Notification status is marked as 'Delivered' in the system

---

### Test Case: Test override access control enforcement
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with non-administrator role (e.g., Regular User, Scheduler, Viewer)
- User does NOT have override permissions
- At least one scheduling conflict exists in the system
- Access control system is properly configured
- Role-based permissions are enforced

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As a non-admin user, attempt to navigate to the admin override interface URL directly | Access is denied and user is redirected to unauthorized access page or error page is displayed |
| 2 | Check if override controls are visible in the regular scheduling interface | Override buttons and controls are not visible to non-admin users |
| 3 | Attempt to send a direct API request to POST /api/admin/override endpoint with conflict ID and justification | API returns 403 Forbidden status code with error message 'Access denied: Administrator privileges required' |
| 4 | Verify the error message displayed to the user | Clear error message is shown: 'You do not have permission to override scheduling restrictions. Please contact an administrator.' |
| 5 | Check audit logs for the unauthorized access attempt | Audit log records the failed override attempt with user ID, timestamp, and 'Access Denied' status |
| 6 | Verify that no changes were made to the scheduling conflict | Scheduling conflict remains unchanged and restriction is still in place |

**Postconditions:**
- Override action is blocked for non-admin user
- Scheduling restrictions remain unchanged
- Unauthorized access attempt is logged in audit system
- No notifications are sent to affected users
- System security is maintained

---

