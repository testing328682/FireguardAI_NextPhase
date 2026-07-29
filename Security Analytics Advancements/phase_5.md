# Phase 5 - Interactive Dashboard & Cross Filtering

## Goal

Transform the Security Analytics dashboard from a collection of independent widgets into a fully interactive dashboard.

Every widget should work together.

Whenever the user interacts with any chart, card, or widget, the rest of the dashboard should immediately update to reflect that selection.

The user should never feel like they are viewing separate reports. Instead, the entire page should behave as one connected analytics workspace.

This phase should not introduce new charts.

Instead, it enhances everything built in Phases 1–4.

---

# Dashboard State

Introduce a shared dashboard state.

Instead of every widget managing its own filters independently, the dashboard should maintain one centralized filter state.

Every widget should subscribe to this shared state.

Whenever the state changes, every widget refreshes automatically.

This will prevent widgets from becoming inconsistent.

---

# Global Filters

The following filters should always remain synchronized across the entire dashboard.

Customer

Search

Configuration Status

Firmware

Grade

Severity

Time Range

Whenever any one of these changes, every widget should refresh automatically.

No page reload should occur.

---

# Cross Filtering

All interactive widgets should support cross-filtering.

Examples:

Click

Critical Findings

↓

Device Table

↓

Only devices with Critical findings remain.

Charts update.

Summary cards update.

Operational widgets update.

---

Example

Click

Firmware 7.3.2

↓

Everything refreshes using only devices running Firmware 7.3.2.

---

Example

Click

Grade F

↓

Dashboard now represents only Grade F devices.

---

Example

Click

Customer

↓

Entire dashboard switches to that customer.

---

# Active Filters Bar

Introduce an Active Filters bar directly below the dashboard toolbar.

Example

Customer: Acme Corp

Firmware: 7.3.2

Grade: F

Severity: Critical

Each filter should appear as a removable badge.

Example

Customer: Dell ✕

Firmware: 7.3.2 ✕

Grade: F ✕

The user should be able to remove filters individually.

---

# Clear All Filters

At the end of the Active Filters bar,

display

Clear All

Clicking it removes every dashboard filter except:

Search

Time Range

Customer (optional depending on organization type)

---

# Drill Down Behavior

Every widget should support drill-down.

---

Executive Cards

Click

Critical Findings

↓

Device Table

↓

Critical devices only.

---

Severity Doughnut

Click

Medium

↓

Only Medium findings remain.

---

Firmware Chart

Click

Firmware Version

↓

Dashboard refreshes.

---

Grade Chart

Click

Grade B

↓

Dashboard refreshes.

---

Most Common Findings

Click

SSH Enabled

↓

Only devices containing SSH Enabled finding remain.

---

Recently Changed Devices

Click

Branch Firewall

↓

Open Device Findings page.

---

Customer Overview

Click

Customer

↓

Dashboard refreshes.

---

# Hover Interactions

Every chart should display rich tooltips.

Example

Firmware

Version

7.3.2

Devices

91

Average Score

82

Critical Findings

16

---

Example

Grade

B

Devices

28

Average Score

84

---

# Breadcrumb

Display dashboard context.

Example

Security Analytics

>

Customer

>

Firmware 7.3.2

>

Grade B

This helps users understand why the dashboard currently looks the way it does.

---

# Dashboard Refresh

Add a Refresh button to the dashboard toolbar.

Refreshing should:

Reload

Cards

Charts

Widgets

Table

without reloading the page.

Display a small loading animation.

---

# Last Updated

Display

Last Updated

Example

5 seconds ago

2 minutes ago

Automatically update after every dashboard refresh.

---

# Auto Refresh

Add an Auto Refresh option.

Options

Off

30 seconds

1 minute

5 minutes

Default

Off

When enabled,

refresh the dashboard automatically.

Do not interrupt user interactions.

---

# Widget Synchronization

Every widget should always display consistent information.

Example

If the user filters to:

Grade F

Then

Executive Cards

↓

Grade F devices only

Charts

↓

Grade F devices only

Operational Widgets

↓

Grade F devices only

Device Table

↓

Grade F devices only

No widget should ever display stale information.

---

# Empty Dashboard

If filters produce no results,

display a friendly dashboard.

Example

"No devices match the selected filters."

Provide

Clear Filters

button.

---

# Smooth Animations

Animate

Card numbers

Chart transitions

Table refresh

Filter badges

Do not animate excessively.

Animations should feel professional.

---

# Performance

Dashboard interactions should feel instant.

Avoid unnecessary API calls.

Whenever possible,

reuse already-loaded data.

Use request caching where appropriate.

Avoid reloading the entire dashboard after every interaction.

---

# Future Compatibility

The dashboard architecture should support future widgets without requiring major redesign.

New widgets should automatically participate in:

Dashboard state

Cross filtering

Active Filters

Refresh

Search

Customer selection

---

# Acceptance Criteria

This phase is complete when:

* Every widget participates in dashboard filtering.
* Cross-filtering works across all dashboard components.
* Active Filters bar is implemented.
* Individual filter removal works.
* Clear All Filters works.
* Drill-down behavior works.
* Breadcrumb navigation reflects dashboard state.
* Refresh button works without page reload.
* Last Updated timestamp is displayed.
* Auto Refresh is implemented.
* Charts animate smoothly.
* Dashboard performance remains responsive.
* Existing functionality from Phases 1–4 remains intact.
* The original Findings page remains completely unchanged.
