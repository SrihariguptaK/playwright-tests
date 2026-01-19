# Manual Test Cases

## Story: As Employee, I want to perform viewing task update history to achieve transparency
**Story ID:** story-5

### Test Case: Validate display of complete task update history
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged into the system with valid credentials
- User has access permissions to view task details
- At least one task exists with multiple status changes and comments
- Task has a minimum of 5 historical updates (status changes and comments)
- Browser is supported (Chrome, Firefox, Safari, or Edge)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the task detail page by clicking on a task from the task list | Task detail page loads successfully and displays task information |
| 2 | Click on the 'Update History' tab or section within the task detail page | Update history tab becomes active and displays the history section |
| 3 | Observe the complete list of status changes and comments displayed in the history section | Complete chronological list of all task status changes and comments is displayed in descending order (newest first) |
| 4 | Verify that each status change entry shows the timestamp in readable format (e.g., 'Jan 15, 2024 10:30 AM') | All status change entries display accurate timestamps in consistent format |
| 5 | Verify that each update entry shows the user name or identifier who made the change | All updates display the correct user details (name, username, or user ID) who performed the action |
| 6 | Verify that status changes show both 'from' and 'to' status values (e.g., 'Changed from In Progress to Completed') | Status change entries clearly indicate the previous status and new status |
| 7 | Verify that comment entries display the full comment text along with commenter details | All comments are displayed with complete text and associated user information |
| 8 | Scroll through the entire history list from top to bottom | List scrolls smoothly without lag, freezing, or errors. All entries remain properly formatted during scrolling |
| 9 | Check the page load time from when the history tab is clicked until all data is displayed | History data loads and displays within 3 seconds |
| 10 | Verify that no error messages or console errors appear during the display of history | No errors are displayed on the UI or in the browser console |

**Postconditions:**
- Task update history remains displayed on screen
- No data has been modified in the system
- User session remains active
- History data is ready for further filtering or export operations

---

### Test Case: Verify filtering of history by date and update type
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged into the system with valid credentials
- User has navigated to the task update history tab
- Task history contains updates spanning multiple dates (at least 30 days)
- Task history contains both status changes and comments
- History list is fully loaded and displayed
- Filter controls are visible and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the date range filter controls on the history page | Date range filter with 'From Date' and 'To Date' fields is visible and accessible |
| 2 | Click on the 'From Date' field and select a start date (e.g., 7 days ago) | Date picker opens and allows date selection. Selected date is populated in the 'From Date' field |
| 3 | Click on the 'To Date' field and select an end date (e.g., today's date) | Date picker opens and allows date selection. Selected date is populated in the 'To Date' field |
| 4 | Click the 'Apply Filter' or equivalent button to apply the date range filter | History list refreshes and displays only updates that fall within the selected date range. Update count reflects filtered results |
| 5 | Verify that all displayed entries have timestamps within the selected date range | All visible history entries have timestamps between the 'From Date' and 'To Date'. No entries outside this range are shown |
| 6 | Locate the update type filter dropdown or radio buttons (Status Changes / Comments / All) | Update type filter control is visible with options for filtering by type |
| 7 | Select 'Status Changes' from the update type filter | History list updates to show only status change entries. All comment entries are hidden from view |
| 8 | Verify that only status change entries are displayed in the filtered list | All visible entries are status changes. No comment entries are present in the list |
| 9 | Change the update type filter to 'Comments' | History list updates to show only comment entries. All status change entries are hidden from view |
| 10 | Verify that only comment entries are displayed in the filtered list | All visible entries are comments. No status change entries are present in the list |
| 11 | Apply both date range and update type filters simultaneously (e.g., Comments from last 7 days) | History list displays only entries that match both filter criteria (comments within the date range) |
| 12 | Click the 'Clear Filters' or 'Reset' button | All applied filters are removed. Date fields are cleared and update type is reset to 'All' |
| 13 | Verify that the full unfiltered history list is restored | Complete history list is displayed showing all status changes and comments across all dates. Entry count matches original unfiltered count |
| 14 | Check that filter operations complete within acceptable time | Each filter application completes within 2-3 seconds with smooth UI response |

**Postconditions:**
- Filters are cleared and full history is displayed
- No data has been modified in the database
- Filter controls remain functional for subsequent use
- User session remains active

---

### Test Case: Ensure export functionality works correctly
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged into the system with valid credentials
- User has navigated to the task update history tab
- Task history contains at least 10 update entries for meaningful export
- History list is fully loaded and displayed
- Export button or menu is visible on the history page
- User has appropriate permissions to export data
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the 'Export' button on the task update history page | Export button is visible and clickable in the history interface |
| 2 | Click on the 'Export' button | Export options menu or dialog appears showing available export formats (CSV and PDF) |
| 3 | Select 'CSV' format from the export options | CSV export process initiates. Loading indicator or progress message may appear |
| 4 | Wait for the CSV file download to complete | CSV file is automatically downloaded to the browser's default download location. File name follows naming convention (e.g., 'task_history_[taskId]_[date].csv') |
| 5 | Navigate to the download location and verify the CSV file exists | CSV file is present in the downloads folder with non-zero file size |
| 6 | Open the downloaded CSV file using a spreadsheet application (Excel, Google Sheets, etc.) | CSV file opens successfully without errors. Data is properly formatted in columns |
| 7 | Verify CSV file contains header row with column names (e.g., Date, Time, User, Update Type, Description, Status From, Status To) | First row contains appropriate column headers for all data fields |
| 8 | Verify that all history entries visible on the screen are present in the CSV file | CSV contains all update records with matching data (timestamps, users, status changes, comments). Row count matches the number of history entries |
| 9 | Verify data accuracy by comparing several CSV entries with corresponding on-screen history entries | Data in CSV exactly matches the displayed history information (dates, times, users, descriptions are identical) |
| 10 | Return to the task history page and click the 'Export' button again | Export options menu appears again |
| 11 | Select 'PDF' format from the export options | PDF export process initiates. Loading indicator or progress message may appear |
| 12 | Wait for the PDF file generation and download to complete | PDF file is automatically downloaded to the browser's default download location. File name follows naming convention (e.g., 'task_history_[taskId]_[date].pdf') |
| 13 | Navigate to the download location and verify the PDF file exists | PDF file is present in the downloads folder with non-zero file size |
| 14 | Open the downloaded PDF file using a PDF reader (Adobe Reader, browser, etc.) | PDF file opens successfully and displays formatted task history report |
| 15 | Verify PDF contains proper header with task information (task ID, task name, export date) | PDF header displays task identification details and report generation timestamp |
| 16 | Verify that all history entries are present in the PDF in a readable, formatted layout | PDF contains all update records in chronological order with clear formatting and readability |
| 17 | Verify data accuracy by comparing several PDF entries with corresponding on-screen history entries | Data in PDF exactly matches the displayed history information. All timestamps, users, and descriptions are accurate |
| 18 | Check that PDF formatting is professional with proper spacing, fonts, and page breaks if applicable | PDF is well-formatted, professional-looking, and suitable for reporting purposes |
| 19 | Verify that export operations complete within acceptable time (within 5 seconds for standard history size) | Both CSV and PDF exports complete and download within 5 seconds |

**Postconditions:**
- Two export files (CSV and PDF) are saved in the downloads folder
- Task history page remains open and functional
- No data has been modified in the system
- Exported files contain complete and accurate historical data
- User session remains active
- Export functionality remains available for subsequent use

---

