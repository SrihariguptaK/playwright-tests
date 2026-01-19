# Manual Test Cases

## Story: As Employee, I want to receive notifications when tasks are assigned to achieve awareness of responsibilities
**Story ID:** story-15

### Test Case: Validate notification delivery upon task assignment
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user account is active and authenticated
- Employee user account is active and authenticated
- Notification service is running and operational
- Task database is accessible
- Employee has valid email address configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager logs into the system and navigates to task assignment page | Task assignment page loads successfully with option to create new task |
| 2 | Manager creates a new task with title, description, deadline, and priority, then assigns it to the employee | Task is successfully created and assigned to the employee |
| 3 | Wait and monitor notification delivery time using system timestamp | Notification is sent to the employee within 5 seconds of task assignment |
| 4 | Employee logs into the system and checks notification inbox | Notification inbox displays the new notification with task details visible |
| 5 | Employee verifies notification contains task title, description, deadline, and priority | All task details are present and accurate in the notification |
| 6 | Employee clicks on the acknowledge button for the notification | Acknowledgment confirmation message is displayed to the employee |
| 7 | Manager checks the notification acknowledgment status in the system | Acknowledgment is recorded in the system with timestamp and employee details |

**Postconditions:**
- Notification is marked as delivered in the system
- Notification is marked as acknowledged by the employee
- Notification history is updated with delivery and acknowledgment timestamps
- Task remains assigned to the employee

---

### Test Case: Verify notification content accuracy
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager user account is active and authenticated
- Employee user account is active and authenticated
- Notification service is running and operational
- Test task data is prepared with specific title, description, deadline, and priority

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager creates a task with specific details: Title='Q4 Budget Review', Description='Review and approve Q4 budget allocations', Deadline='2024-12-31', Priority='High' | Task is created successfully with all specified details |
| 2 | Manager assigns the task to the employee | Task assignment is completed and notification is triggered |
| 3 | Employee receives and opens the task assignment notification | Notification is displayed in employee's notification inbox |
| 4 | Employee verifies the task title in the notification matches 'Q4 Budget Review' | Task title is correctly displayed as 'Q4 Budget Review' |
| 5 | Employee verifies the task description in the notification matches 'Review and approve Q4 budget allocations' | Task description is correctly displayed as 'Review and approve Q4 budget allocations' |
| 6 | Employee verifies the deadline in the notification matches '2024-12-31' | Deadline is correctly displayed as '2024-12-31' |
| 7 | Employee verifies the priority in the notification is marked as 'High' | Priority is correctly displayed as 'High' with appropriate visual indicator |

**Postconditions:**
- Notification content accuracy is confirmed
- All task details are correctly transmitted from task creation to notification display
- Employee has complete information to act on the task

---

### Test Case: Ensure high notification delivery success rate
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Manager user account is active and authenticated
- 100 employee user accounts are active and authenticated
- Notification service is running with sufficient capacity
- Task database is accessible and has sufficient capacity
- Test automation script or bulk task assignment tool is available
- Monitoring tools are configured to track notification delivery

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager prepares 100 unique tasks with varying titles, descriptions, deadlines, and priorities | 100 tasks are prepared and ready for assignment |
| 2 | Manager assigns all 100 tasks to 100 different employees simultaneously or in rapid succession | All 100 task assignments are submitted to the system successfully |
| 3 | Monitor the notification service logs and delivery status for all 100 notifications | Notification delivery process is initiated for all 100 tasks |
| 4 | Wait for notification delivery completion and check delivery status for each notification | Notification delivery attempts are completed for all 100 notifications |
| 5 | Count the number of successfully delivered notifications from the delivery logs | Delivery count is recorded and available for verification |
| 6 | Calculate the delivery success rate: (successful deliveries / 100) * 100 | Delivery success rate is at least 99% (minimum 99 out of 100 notifications delivered successfully) |
| 7 | Review any failed notifications to identify failure reasons | Failed notifications (if any) are documented with failure reasons for analysis |

**Postconditions:**
- At least 99 notifications are successfully delivered
- Notification delivery success rate meets or exceeds 99% threshold
- All delivery attempts are logged in the system
- Any failures are documented for further investigation

---

## Story: As Manager, I want to view task assignment status to achieve monitoring of delegated work
**Story ID:** story-16

### Test Case: Validate dashboard displays assigned tasks with correct details
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager user account is active and authenticated
- At least 5 tasks have been created and assigned by the manager
- Tasks have varying statuses (e.g., Not Started, In Progress, Completed)
- Tasks have different priorities (Low, Medium, High)
- Tasks have different deadlines
- Dashboard service is running and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager opens the application and enters valid login credentials | Manager is successfully authenticated and redirected to the home page |
| 2 | Manager clicks on the 'Task Assignment Dashboard' menu option | Dashboard page loads and displays the task assignment dashboard interface |
| 3 | Manager verifies the dashboard displays all assigned tasks in a list or table format | Dashboard shows all tasks assigned by the manager with columns for task name, status, deadline, and priority |
| 4 | Manager verifies each task displays correct status information | Each task shows accurate status (Not Started, In Progress, Completed, etc.) |
| 5 | Manager verifies each task displays correct deadline information | Each task shows accurate deadline date in the expected format |
| 6 | Manager verifies each task displays correct priority information | Each task shows accurate priority level (Low, Medium, High) with appropriate visual indicators |
| 7 | Manager locates and clicks on the priority filter dropdown and selects 'High' priority | Filter is applied and dashboard refreshes to show only high priority tasks |
| 8 | Manager locates and clicks on the status filter dropdown and selects 'In Progress' status | Dashboard updates to show only tasks that are both high priority and in progress status |
| 9 | Manager verifies the filtered results display only tasks matching both filter criteria | Only tasks with high priority and in progress status are displayed |
| 10 | Manager clears all filters to view all tasks again | Dashboard resets and displays all assigned tasks |
| 11 | Manager clicks on a specific task from the list to view detailed information | Task detail view opens showing comprehensive task information |
| 12 | Manager verifies task details include task title, description, assigned employee, deadline, priority, and assignment history | All task details and assignment history are displayed accurately with timestamps and employee information |

**Postconditions:**
- Manager remains logged into the system
- Dashboard data remains accurate and unchanged
- All filters can be reapplied as needed
- Task detail view can be closed to return to dashboard

---

### Test Case: Ensure dashboard access is restricted to authorized managers
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user account is active and authenticated
- Non-manager user account (employee or other role) is active
- Unauthenticated user session is available
- Role-based access control is configured in the system
- Dashboard URL is known

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application without logging in and attempt to navigate directly to the dashboard URL | System redirects to login page or displays 'Unauthorized Access' error message |
| 2 | Verify that the error message clearly indicates authentication is required | Error message states 'Please log in to access this page' or similar authentication requirement message |
| 3 | Log into the system using employee credentials (non-manager role) | Employee is successfully authenticated and redirected to employee home page |
| 4 | Employee attempts to navigate to the task assignment dashboard URL directly | Access is denied with error message 'Access Denied: Insufficient Permissions' or similar authorization error |
| 5 | Verify that the dashboard menu option is not visible in the employee's navigation menu | Task assignment dashboard option is not displayed in employee's menu |
| 6 | Log out from employee account and log in using valid manager credentials | Manager is successfully authenticated and redirected to manager home page |
| 7 | Manager navigates to the task assignment dashboard | Dashboard loads successfully and displays all assigned tasks with full functionality |
| 8 | Verify manager has full access to all dashboard features including filters and task details | All dashboard features are accessible and functional for the authorized manager |

**Postconditions:**
- Unauthorized users cannot access the dashboard
- Access control logs record all unauthorized access attempts
- Authorized manager retains full dashboard access
- Security measures are confirmed to be working correctly

---

### Test Case: Verify dashboard load time under normal conditions
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager user account is active and authenticated
- Typical data volume is present (50-100 tasks assigned by the manager)
- System is under normal load conditions (not peak usage)
- Network connection is stable with normal latency
- Performance monitoring tools are available to measure load time
- Browser cache is cleared to ensure accurate measurement

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager logs into the system with valid credentials | Manager is successfully authenticated and home page loads |
| 2 | Clear browser cache and refresh the page to ensure clean test conditions | Browser cache is cleared and page is refreshed |
| 3 | Start performance timer or open browser developer tools to monitor network activity | Performance monitoring is active and ready to capture load time metrics |
| 4 | Manager clicks on the 'Task Assignment Dashboard' menu option | Dashboard page begins loading |
| 5 | Monitor the page load process and wait for dashboard to fully render with all task data | Dashboard completes loading with all tasks, filters, and UI elements fully rendered |
| 6 | Stop the performance timer when dashboard is fully interactive and all data is displayed | Load time is recorded from click to full page render |
| 7 | Verify the recorded load time is 3 seconds or less | Dashboard loads within 3 seconds under normal load conditions |
| 8 | Repeat the test 3 more times to ensure consistent performance | All subsequent load times are within 3 seconds, confirming consistent performance |

**Postconditions:**
- Dashboard load time meets performance requirement of 3 seconds or less
- Performance metrics are documented for baseline comparison
- Dashboard remains fully functional after load time test
- Manager can proceed with normal dashboard operations

---

## Story: As Employee, I want to acknowledge task assignments to achieve confirmation of responsibility acceptance
**Story ID:** story-17

### Test Case: Validate employee can acknowledge assigned task
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has at least one task assigned that has not been acknowledged
- Employee has appropriate permissions to view and acknowledge tasks
- System is operational and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to their task list or notifications section | Task list or notifications page is displayed showing assigned tasks |
| 2 | Employee selects and opens the assigned task details | Task details page is displayed with complete task information including title, description, deadline, priority, and an 'Acknowledge' button is visible and enabled |
| 3 | Employee clicks the 'Acknowledge' button | Acknowledgment status is updated, confirmation message is displayed (e.g., 'Task acknowledged successfully'), and the acknowledge button becomes disabled or changes to 'Acknowledged' state |
| 4 | Verify acknowledgment processing time | Acknowledgment is processed and confirmation is displayed within 2 seconds |
| 5 | Manager logs into the system and navigates to task management or team dashboard | Manager's dashboard or task management view is displayed |
| 6 | Manager views the acknowledgment status for the task acknowledged by the employee | Acknowledgment is reflected accurately showing employee name, acknowledgment timestamp, and status as 'Acknowledged' in the manager's view |

**Postconditions:**
- Task acknowledgment status is permanently stored in the database
- Task status is updated to 'Acknowledged' in the system
- Acknowledgment timestamp is recorded
- Manager can view the acknowledgment in their dashboard
- Employee cannot acknowledge the same task again

---

### Test Case: Verify system prevents multiple acknowledgments
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has at least one task assigned that has not been acknowledged
- System is operational and accessible
- Database is configured to prevent duplicate acknowledgments

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Employee navigates to their task list and opens an assigned task | Task details page is displayed with the 'Acknowledge' button visible and enabled |
| 2 | Employee clicks the 'Acknowledge' button for the first time | Acknowledgment is recorded successfully, confirmation message is displayed, and the acknowledge button becomes disabled or changes to 'Acknowledged' state |
| 3 | Verify acknowledgment is stored in the system | Task status shows as 'Acknowledged' with timestamp and employee information |
| 4 | Employee refreshes the task details page or navigates away and returns to the same task | Task details page is displayed showing the task is already acknowledged |
| 5 | Employee attempts to acknowledge the same task again by clicking the acknowledge button or attempting any workaround | System prevents duplicate acknowledgment and displays an appropriate message such as 'This task has already been acknowledged' or the acknowledge button remains disabled |
| 6 | Verify database records for the task acknowledgment | Only one acknowledgment record exists for the employee and task combination, confirming no duplicate entry was created |

**Postconditions:**
- Only one acknowledgment record exists in the database for the task
- Task acknowledgment status remains unchanged from the first acknowledgment
- System integrity is maintained with no duplicate records
- Employee receives clear feedback about the already acknowledged status

---

## Story: As Manager, I want to generate reports on task assignments to achieve data-driven decision making
**Story ID:** story-21

### Test Case: Validate report generation with filters
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager is logged into the system with valid credentials and manager role authorization
- Multiple tasks exist in the system with varying dates, employees, priorities, and statuses
- Manager has permissions to access the reports section
- System has sufficient data for meaningful report generation
- PDF and Excel export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the reports section from the main menu or dashboard | Reports page is displayed with report filter form showing available filter options (date range, employee, priority, status) |
| 2 | Manager selects filter criteria: date range (e.g., last 30 days), specific employee or team, priority level (e.g., High), and status (e.g., In Progress) | Selected filters are highlighted and applied to the filter form, all selections are visible and confirmed |
| 3 | Manager clicks the 'Generate Report' button | Report is generated accurately displaying task assignments matching the selected filters, showing columns for task name, assignee, deadline, priority, status, and other relevant fields |
| 4 | Verify the accuracy of the generated report data | All displayed data matches the applied filters, calculations and summaries are correct, and no irrelevant data is included |
| 5 | Manager clicks the 'Export to PDF' button | PDF file is downloaded successfully, file opens without errors, all report data is intact and properly formatted, headers and footers are present |
| 6 | Manager returns to the report view and clicks the 'Export to Excel' button | Excel file is downloaded successfully, file opens in spreadsheet application without errors, all data columns and rows are intact, data is editable and properly formatted |
| 7 | Compare data between the on-screen report, PDF export, and Excel export | All three formats contain identical data with no data loss, formatting is appropriate for each format type |

**Postconditions:**
- Report is successfully generated and displayed
- PDF and Excel files are saved to the download location
- No data loss occurred during export processes
- Report generation activity is logged in the system
- Manager can access the same report again if needed

---

### Test Case: Verify report scheduling functionality
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Manager is logged into the system with valid credentials and manager role authorization
- Manager has permissions to schedule automated reports
- System scheduling service is operational
- Email or notification system is configured for report delivery
- Reports section is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the reports section and selects the 'Schedule Report' option | Report scheduling interface is displayed with options for report type, filters, frequency, and delivery method |
| 2 | Manager configures the scheduled report: selects report type (task assignments), applies desired filters (e.g., all employees, all priorities), sets frequency (e.g., weekly, every Monday at 9 AM), and specifies delivery method (e.g., email) | All scheduling parameters are accepted and displayed in the configuration form |
| 3 | Manager clicks 'Save Schedule' or 'Create Schedule' button | Schedule is saved successfully, confirmation message is displayed (e.g., 'Report schedule created successfully'), and the schedule appears in the list of scheduled reports |
| 4 | Verify the scheduled report details in the scheduled reports list | Scheduled report is listed with correct parameters including report type, filters, frequency, next run date/time, and delivery method |
| 5 | Wait for the scheduled time or trigger the scheduled report manually if test environment allows | Report is generated automatically as per the schedule, report contains accurate data based on the configured filters |
| 6 | Verify report delivery through the specified method (check email or notification) | Report is delivered successfully to the manager via the specified delivery method, report file is attached or accessible, and data is complete and accurate |

**Postconditions:**
- Scheduled report configuration is saved in the database
- Scheduled report appears in the manager's list of scheduled reports
- System will continue to generate reports according to the schedule
- Report generation and delivery logs are created
- Manager can edit or delete the schedule if needed

---

### Test Case: Ensure report generation performance
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager is logged into the system with valid credentials
- System contains typical data volume representing normal operational load
- Database is populated with representative task data (minimum 100-500 tasks)
- System performance monitoring tools are available or timer is ready
- No other heavy processes are running that could affect performance

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the reports section | Reports page loads successfully and filter form is displayed |
| 2 | Manager selects filters representing typical report criteria (e.g., last 30 days, all employees, all priorities and statuses) | Filters are applied and ready for report generation |
| 3 | Start timer and click 'Generate Report' button | Report generation process begins immediately with loading indicator displayed |
| 4 | Monitor the report generation process and stop timer when report is fully displayed | Report is generated and displayed completely within 5 seconds, all data is loaded and visible, no timeout errors occur |
| 5 | Verify the completeness and accuracy of the generated report | Report contains all expected data matching the filter criteria, no data is missing or truncated due to performance optimization |
| 6 | Repeat the report generation process 2-3 times with similar data volumes | Each report generation completes within 5 seconds consistently, demonstrating reliable performance |

**Postconditions:**
- Report generation performance meets the 5-second requirement
- System remains responsive after report generation
- No performance degradation is observed
- Report data is complete and accurate despite performance constraints
- Performance metrics are logged for monitoring

---

