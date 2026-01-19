# Manual Test Cases

## Story: As Scheduler, I want to receive inline alerts for scheduling conflicts to correct issues immediately
**Story ID:** story-2

### Test Case: Display inline alert on scheduling conflict
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Scheduler
- Scheduling form is accessible and loaded
- At least one existing booking is present in the system
- Real-time conflict detection API is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling form interface | Scheduling form displays with all required fields (date, time, resource, etc.) |
| 2 | Enter scheduling details that conflict with an existing booking (e.g., same resource, overlapping time) | Inline alert appears next to the conflicting field with a clear conflict message indicating the nature of the conflict |
| 3 | Verify the visual highlighting of the conflicting field | Conflicting field is visually highlighted (e.g., red border, warning icon) and alert message is displayed inline |
| 4 | Modify the scheduling details to resolve the conflict (e.g., change time or resource) | Inline alert disappears automatically as soon as the conflict is resolved |
| 5 | Verify the visual highlighting is removed from the previously conflicting field | Field returns to normal state without highlighting or alert message |
| 6 | Re-enter conflicting scheduling details | Inline alert reappears next to the conflicting field |
| 7 | Attempt to submit the form with the unresolved conflict by clicking the Submit button | Form submission is blocked and an alert message is displayed indicating that conflicts must be resolved before submission |
| 8 | Resolve the conflict by modifying the scheduling details | Alert disappears and Submit button becomes enabled |
| 9 | Submit the corrected schedule | Form submits successfully and confirmation message is displayed |

**Postconditions:**
- Schedule is saved without conflicts
- No inline alerts are displayed on the form
- User remains on the scheduling interface or is redirected to confirmation page

---

### Test Case: Verify alert display latency under 500ms
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a Scheduler
- Scheduling form is loaded and ready for input
- Performance monitoring tools are available to measure latency
- Conflict detection API is responding normally
- At least one existing booking is present in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network or Performance tab | Developer tools are open and ready to monitor performance metrics |
| 2 | Start performance recording or timestamp tracking | Performance monitoring is active |
| 3 | Trigger a scheduling conflict by entering conflicting data (e.g., overlapping time slot with existing booking) | Inline alert is displayed next to the conflicting field within 500 milliseconds of data entry |
| 4 | Review the performance metrics or network timeline to verify alert display latency | Latency measurement shows alert displayed in less than 500ms from conflict detection |
| 5 | Resolve the conflict by modifying the scheduling details to non-conflicting values | Alert is removed promptly from the interface |
| 6 | Verify the alert removal latency | Alert disappears within acceptable time frame (ideally under 500ms) |
| 7 | Submit the corrected schedule by clicking the Submit button | Form submission succeeds and confirmation message is displayed |
| 8 | Verify the schedule is saved in the system | Schedule appears in the system with correct details and no conflicts |

**Postconditions:**
- Performance metrics confirm alert latency is under 500ms
- Schedule is successfully saved without conflicts
- System performance meets defined SLA requirements

---

### Test Case: Ensure alerts prevent form submission until resolved
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as a Scheduler
- Scheduling form is accessible and loaded
- At least one existing booking is present that can create a conflict
- Form validation is enabled and functioning

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling form | Scheduling form is displayed with all input fields and Submit button enabled |
| 2 | Enter conflicting schedule data (e.g., same resource and overlapping time as existing booking) | Inline alert is displayed next to the conflicting field and Submit button is disabled or visually indicates submission is not allowed |
| 3 | Verify the alert message content | Alert message clearly describes the conflict and provides guidance on resolution |
| 4 | Attempt to submit the form by clicking the Submit button | Form submission is blocked and an error message is displayed stating that conflicts must be resolved before submission |
| 5 | Verify that no data is sent to the backend | No API call is made to save the conflicting schedule (verify in Network tab) |
| 6 | Attempt to submit the form using keyboard shortcut (e.g., Enter key) | Form submission is still blocked with the same error message |
| 7 | Resolve the conflict by modifying the scheduling details to non-conflicting values | Inline alert disappears and Submit button becomes enabled |
| 8 | Submit the corrected schedule by clicking the Submit button | Form submission is accepted and schedule is saved successfully |
| 9 | Verify confirmation message is displayed | Success message confirms the schedule has been saved |

**Postconditions:**
- Schedule is saved only after conflict resolution
- No conflicting schedules exist in the system
- Form validation successfully prevented invalid submission

---

## Story: As Scheduler, I want to receive email notifications for scheduling conflicts to stay informed when not actively scheduling
**Story ID:** story-3

### Test Case: Verify email notification sent upon conflict detection
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is registered as a Scheduler with valid email address
- Email notification feature is enabled in system configuration
- User has email notifications enabled in their preferences
- Email server is configured and operational
- SMTP settings are correctly configured
- At least one existing booking is present in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as a Scheduler or Administrator | User is successfully logged in and has access to scheduling functionality |
| 2 | Trigger a scheduling conflict in the system by creating or modifying a booking that conflicts with an existing one | Conflict is detected by the system and email notification is generated and queued for sending |
| 3 | Wait for email processing (up to 30 seconds) | Email notification is sent to the affected scheduler's registered email address |
| 4 | Check the recipient's email inbox (or test email account) | Email is received with subject line indicating scheduling conflict |
| 5 | Open and review the email content | Email contains correct conflict details including date, time, resource, conflicting bookings, and suggested next steps |
| 6 | Verify the email formatting and readability | Email is properly formatted with clear sections, readable fonts, and professional appearance |
| 7 | Navigate to the system's email delivery logs or notification history | Email delivery log is accessible and displays recent notifications |
| 8 | Verify the email delivery status is logged in the system | Delivery status is recorded as 'Sent' or 'Delivered' with timestamp within 30 seconds of conflict detection |
| 9 | Check for any error logs related to email delivery | No errors are present in the email delivery logs |

**Postconditions:**
- Email notification is successfully delivered to scheduler
- Email delivery is logged with successful status
- Scheduler is informed of the conflict and can take action
- System maintains audit trail of notification

---

### Test Case: Test user notification preference settings
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 9 mins

**Preconditions:**
- User is registered as a Scheduler with valid email address
- User account has access to notification preference settings
- Email notification system is operational
- User is logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile or settings page | User settings page is displayed with notification preferences section |
| 2 | Locate the email notification preferences for scheduling conflicts | Email notification toggle or checkbox is visible and currently enabled |
| 3 | Disable email notifications by unchecking the option or toggling it off | Notification preference is updated and visual indicator shows notifications are disabled |
| 4 | Save the preference settings by clicking Save or Apply button | Preference is saved successfully and confirmation message is displayed |
| 5 | Verify the preference is persisted by refreshing the page or logging out and back in | Email notification setting remains disabled after page refresh or re-login |
| 6 | Trigger a conflict notification by creating a scheduling conflict | Conflict is detected by the system but no email is queued for this user |
| 7 | Wait for 30 seconds and check the user's email inbox | No email notification is sent to the user |
| 8 | Verify in the system logs that email was not sent due to user preference | System logs show notification was suppressed based on user preference settings |
| 9 | Navigate back to notification preferences | Notification preferences page is displayed |
| 10 | Enable email notifications by checking the option or toggling it on | Notification preference is updated and visual indicator shows notifications are enabled |
| 11 | Save the preference settings | Preference is saved successfully and confirmation message is displayed |
| 12 | Trigger another conflict notification | Conflict is detected and email notification is generated and sent |
| 13 | Check the user's email inbox | Email notification is received confirming that email notifications have resumed |

**Postconditions:**
- User notification preferences are correctly saved and applied
- Email notifications respect user preference settings
- System correctly handles both enabled and disabled notification states
- User has control over their notification settings

---

### Test Case: Ensure email delivery within 30 seconds
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is registered as a Scheduler with valid email address
- Email notifications are enabled for the user
- Email server is operational and responsive
- System time is synchronized and accurate
- Monitoring tools are available to track email delivery timing
- At least one existing booking is present in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare timing measurement tools (system logs, email server logs, or monitoring dashboard) | Timing measurement tools are ready and synchronized with system time |
| 2 | Note the current timestamp before triggering the conflict | Baseline timestamp is recorded for comparison |
| 3 | Trigger conflict detection by creating or modifying a booking that conflicts with an existing one | Conflict is detected by the system and timestamp of detection is logged |
| 4 | Monitor the email notification queue and processing | Email notification is queued immediately upon conflict detection |
| 5 | Track the time from conflict detection to email send initiation | Email is sent within 30 seconds of conflict detection |
| 6 | Monitor email server logs for send confirmation | Email server logs show successful send operation with timestamp |
| 7 | Review email server logs for any delays or failures | No delays, errors, or failures are recorded in the email server logs |
| 8 | Calculate the total time elapsed from conflict detection to email send completion | Total elapsed time is 30 seconds or less |
| 9 | Confirm the user receives the email promptly by checking the inbox | Email arrives in the user's inbox within the 30-second SLA window |
| 10 | Verify the email timestamp matches the expected delivery time | Email received timestamp is within 30 seconds of conflict detection time |
| 11 | Review system performance metrics and notification logs | All performance metrics confirm email delivery met the 30-second SLA requirement |

**Postconditions:**
- Email is delivered within the 30-second SLA
- No performance issues or delays are recorded
- System meets defined performance requirements
- Email delivery timing is logged and verifiable

---

## Story: As Scheduler, I want a dashboard widget summarizing current scheduling conflicts to monitor issues at a glance
**Story ID:** story-4

### Test Case: Verify dashboard widget displays active conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least 5 active scheduling conflicts exist in the system
- Conflicts have different resources, times, and statuses
- User has permission to access the dashboard
- Dashboard page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the dashboard page by clicking on 'Dashboard' in the main navigation menu | Dashboard page loads successfully and the scheduling conflicts widget is visible on the page |
| 2 | Locate the scheduling conflicts widget on the dashboard | Widget displays a count of active conflicts (e.g., '5 Active Conflicts') at the top of the widget |
| 3 | Review the list of conflicts displayed in the widget | Widget shows a list of conflicts with columns for resource name, time/date, and status for each conflict |
| 4 | Click on the filter dropdown and select a specific resource from the available options | Widget updates the list to display only conflicts associated with the selected resource, and the conflict count updates accordingly |
| 5 | Clear the resource filter by clicking 'Clear Filter' or selecting 'All Resources' | Widget returns to displaying all active conflicts with the original count restored |
| 6 | Click on the 'Time' column header to sort conflicts by time | Conflicts are reordered in ascending chronological order (earliest time first) |
| 7 | Click on the 'Time' column header again to reverse the sort order | Conflicts are reordered in descending chronological order (latest time first) |
| 8 | Click on the 'Status' column header to sort conflicts by status | Conflicts are reordered alphabetically by status (e.g., Active, Pending, Unresolved) |

**Postconditions:**
- Dashboard widget displays filtered and sorted conflicts correctly
- Widget remains functional for further interactions
- No errors are displayed on the page
- User remains on the dashboard page

---

### Test Case: Test widget data refresh every 30 seconds
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with Scheduler role
- Dashboard page is loaded with the conflicts widget visible
- At least 3 active conflicts exist in the system
- System clock is synchronized for accurate timing
- User has ability to create new conflicts for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current time and the number of conflicts displayed in the widget (e.g., '3 Active Conflicts') | Widget shows the initial count and list of conflicts with a timestamp or last updated indicator |
| 2 | Observe the widget without any interaction for 30 seconds using a timer | After 30 seconds, the widget automatically refreshes and displays updated data (refresh indicator may briefly appear) |
| 3 | Record the time taken for the refresh to complete from initiation to display of updated data | Refresh completes within 2 seconds, and the widget displays the same or updated conflict data |
| 4 | Open a new browser tab or use a separate session to create a new scheduling conflict in the system | New conflict is successfully created and saved in the system |
| 5 | Return to the dashboard tab and wait for the next automatic refresh cycle (up to 30 seconds) | Widget automatically refreshes and the conflict count increases by 1 (e.g., from '3 Active Conflicts' to '4 Active Conflicts') |
| 6 | Verify the newly created conflict appears in the widget list with correct resource, time, and status details | New conflict is visible in the list with accurate information matching the created conflict |
| 7 | Measure the refresh latency by noting the time from refresh initiation to completion | Refresh latency is under 2 seconds as indicated by the loading indicator duration or timestamp comparison |
| 8 | Continue observing for one more refresh cycle (30 seconds) to confirm consistent refresh behavior | Widget refreshes again after 30 seconds with latency under 2 seconds, maintaining data accuracy |

**Postconditions:**
- Widget continues to refresh every 30 seconds automatically
- All conflicts including newly created ones are displayed accurately
- Refresh latency remains under 2 seconds
- No performance degradation is observed
- User remains on the dashboard page

---

### Test Case: Ensure navigation from widget to conflict details
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Dashboard page is loaded with conflicts widget visible
- At least 2 active conflicts exist in the widget list
- Each conflict has complete details (resource, time, status)
- Conflict detail pages are accessible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify a specific conflict in the widget list and note its details (resource name, time, and status) | Conflict is clearly visible with all details displayed in the widget list |
| 2 | Click on the selected conflict row or conflict link in the widget list | Browser navigates to the conflict detail page, and the page loads successfully |
| 3 | Verify the conflict detail page displays the header with the conflict identifier or title | Page header shows the correct conflict identifier matching the selected conflict |
| 4 | Review the conflict details section to verify resource name matches the widget display | Resource name on the detail page matches exactly with the resource shown in the widget |
| 5 | Verify the time/date information displayed on the conflict detail page | Time and date information matches the time shown in the widget for this conflict |
| 6 | Verify the status information displayed on the conflict detail page | Status on the detail page matches the status shown in the widget (e.g., Active, Pending) |
| 7 | Check for additional conflict details that may not be visible in the widget summary | Detail page shows comprehensive information including description, affected parties, and resolution options |
| 8 | Click the browser back button or click 'Return to Dashboard' link/button | Browser navigates back to the dashboard page successfully |
| 9 | Verify the dashboard page loads completely with all widgets visible | Dashboard displays correctly with the conflicts widget showing the same list of conflicts as before |
| 10 | Verify the conflicts widget maintains any previously applied filters or sort orders | Widget displays conflicts in the same filtered/sorted state as before navigation, maintaining user preferences |

**Postconditions:**
- User is back on the dashboard page
- Conflicts widget displays correctly with accurate data
- Navigation history is preserved for back/forward browser actions
- No errors or broken links are encountered
- Widget functionality remains intact for further interactions

---

