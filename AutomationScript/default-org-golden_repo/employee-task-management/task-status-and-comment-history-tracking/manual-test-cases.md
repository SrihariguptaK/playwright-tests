# Manual Test Cases

## Story: As Employee, I want to view a summary dashboard of my task statuses and comments to manage workload effectively
**Story ID:** story-18

### Test Case: Verify dashboard displays task status counts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has at least one task assigned in various statuses (e.g., To Do, In Progress, Completed)
- Database contains task records associated with the employee
- Dashboard API endpoint GET /api/dashboard/tasks-summary is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted and login button is enabled |
| 3 | Click the login button | System authenticates the user and redirects to the dashboard page |
| 4 | Observe the dashboard page load time | Dashboard loads completely within 3 seconds |
| 5 | Locate the task status summary section on the dashboard | Task status summary section is visible and clearly labeled |
| 6 | Review the task counts displayed for each status category (e.g., To Do, In Progress, Completed, Blocked) | Task counts are displayed correctly for each status, matching the actual number of tasks assigned to the employee in each status category |
| 7 | Verify that only tasks assigned to the logged-in employee are counted | Task counts reflect only the employee's assigned tasks, not tasks belonging to other employees |

**Postconditions:**
- Employee remains logged into the system
- Dashboard displays accurate task status counts
- No errors or warnings are displayed
- Session is active for further navigation

---

### Test Case: Verify recent comments are shown on dashboard
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee account exists and is authenticated in the system
- Employee has tasks with recent comments posted by self or other users
- Comments table contains at least 3-5 recent comments related to employee's tasks
- Dashboard is accessible and displays the comments section
- Comments are timestamped and sorted by most recent first

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee dashboard after successful login | Dashboard page loads and displays all sections including comments section |
| 2 | Locate the recent comments section on the dashboard | Recent comments section is visible with a clear heading (e.g., 'Recent Comments' or 'Latest Activity') |
| 3 | Review the comments displayed in the comments section | Recent comments related to the employee's tasks are displayed in chronological order (most recent first) |
| 4 | Verify each comment shows relevant information (commenter name, timestamp, task reference, comment text) | Each comment displays complete information including who posted it, when it was posted, which task it relates to, and the comment content |
| 5 | Confirm that only comments related to the employee's tasks are shown | All displayed comments are associated with tasks assigned to the logged-in employee, no comments from unrelated tasks appear |
| 6 | Check the number of comments displayed | A reasonable number of recent comments are shown (e.g., last 5-10 comments) without overwhelming the dashboard |

**Postconditions:**
- Employee can view recent activity on their tasks
- Comments section accurately reflects recent task-related communication
- Dashboard remains functional for further interaction
- No performance degradation observed

---

### Test Case: Test navigation from dashboard to task details
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the system
- Dashboard is loaded and displaying task information
- Employee has at least one task with a clickable link on the dashboard
- Task details page exists and is accessible for the linked task
- Browser supports navigation and back button functionality

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | View the dashboard and identify a task link in the task status summary or recent comments section | Task links are visible and clearly identifiable (e.g., underlined, different color, or with clickable icon) |
| 2 | Hover over a task link to verify it is interactive | Cursor changes to pointer/hand icon indicating the link is clickable |
| 3 | Click on the task link | System navigates away from the dashboard to the task details page |
| 4 | Verify the task details page loads completely | Task details page opens correctly showing comprehensive information about the selected task (title, description, status, assignee, comments, attachments, etc.) |
| 5 | Confirm that the task displayed matches the task link clicked on the dashboard | Task ID, title, and details correspond exactly to the task that was clicked from the dashboard |
| 6 | Use browser back button or navigation menu to return to the dashboard | Dashboard reloads successfully with all information intact |
| 7 | Click on a different task link from another section of the dashboard (e.g., from recent comments if first click was from status summary) | Navigation works consistently, opening the correct task details page for the newly selected task |

**Postconditions:**
- Employee successfully navigated to task details and back to dashboard
- Navigation links function correctly across all dashboard sections
- No broken links or navigation errors encountered
- Dashboard state is preserved when returning from task details
- User session remains active

---

