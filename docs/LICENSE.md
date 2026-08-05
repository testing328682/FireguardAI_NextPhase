# FirewallGuard AI — License System

## Overview

Licenses control how many devices an organization can register and analyze.
Every device consumes one license slot from a purchase bundle.  Licenses are
per-organization and can stack — an org can hold multiple purchases with
different device counts, expiry dates, and plan tiers.

---

## Plan Types

| Type | Enum | Pricing |
|------|------|---------|
| **Free** | `PlanTier.free` | 1 device, 30-day trial |
| **Professional** | `PlanTier.professional` | Flat `price_per_device` per month or year |
| **MSP** | `PlanTier.msp` | Tier-based, e.g. 10 devices = $49/mo, 25 = $99/mo |

Plans are **dynamic** (`plans` table).  Server admins manage them via the
Platform Admin portal (Product Config → Plans).  Each plan defines:

- Name, description, plan type
- Features (JSON: `{ "findings_explorer": true, ... }`)
- `price_per_device` (Professional) or `pricing_tiers` (MSP)
- `yearly_discount_pct` (e.g. 20 = 20% off yearly)
- `is_testing` / `validity_minutes` (for short-lived test plans)
- `is_active` / `is_visible` / `sort_order`

---

## Customer License Lifecycle

### 1. Sign-up → Free Trial

On registration every org receives:

- A `LicensePurchase` row with **1 device, 30-day validity**
- Org fields: `subscription_status = "trialing"`, `plan = PlanTier.free`, `trial_ends_at = now + 30d`
- The free license shows as **"Active (Trial)"** on dashboards

### 2. Upgrade to Professional / MSP

- Customer picks a plan → a `LicensePurchase` is created
- `total_devices` = number of device slots purchased
- `subscription_term` = `"monthly"` or `"yearly"`
- Payment handled via Stripe (Phase 3)
- Org status: `subscription_status = "active"`

### 3. Multi-Purchase Support

An org can hold **multiple** `LicensePurchase` rows.  Each is an independent
bundle with its own device count, term, and expiry date.  This lets customers
add capacity without replacing existing licenses.

---

## Device Registration & License Consumption

When registering a device (`POST /api/v1/devices`), the user optionally selects
which `license_purchase_id` to consume:

```
POST /api/v1/devices
{
  "serial": "ABC123",
  "friendly_name": "HQ Firewall",
  "customer_id": "...",
  "license_purchase_id": "..."   // optional
}
```

### Validation rules

1. **Purchase exists** and belongs to the same org
2. **Not expired** — `expires_at > now` (402 "This license has expired")
3. **Slots available** — `consumed < total_devices` (402 "No licenses remaining")

If no `license_purchase_id` is provided, the system falls back to the org's
flat `device_count` limit (`billing.enforce_device_limit`).

### Cached license info

Every device stores a snapshot of its license at registration time:

```json
{
  "tier": "10",
  "total_devices": 10,
  "purchased_at": "2026-07-01T00:00:00Z",
  "expires_at": "2026-08-01T00:00:00Z",
  "is_trial": false
}
```

This survives `LicensePurchase` row deletion — the device still knows when
its license expired even if the purchase record is gone.

### Decommissioning

Devices are **decommissioned** rather than deleted.  The license slot remains
consumed (the purchase was already paid for).  Decommissioned devices are
hidden from the main device list unless explicitly requested.

---

## Per-Device License Fields

Every device returned by `GET /api/v1/devices` has these computed fields
(populated by `_build_device_license_info`):

| Field | Type | Example | Meaning |
|-------|------|---------|---------|
| `license_bundle` | string | `"Active"` | Human-readable status label |
| `license_days_remaining` | number | `14` | Days until expiry (hours if < 1d, minutes if < 1h) |
| `license_expiry` | datetime | `"2026-08-15T00:00:00Z"` | When this device's license expires |
| `license_info` | JSON | `{tier, total_devices, ...}` | Cached purchase snapshot |
| `decommissioned` | bool | `false` | Soft-delete flag |
| `configured` | bool | `true` | Has TSR been uploaded or API connected? |

### `license_bundle` values

| Value | Meaning |
|-------|---------|
| `"Active"` | Paid license, not expired |
| `"Active (Trial)"` | Free plan trial, not expired |
| `"Tier-10"` | MSP tier (10 devices), active |
| `"Expired"` | Paid license expired |
| `"Expired (Trial)"` | Trial expired |
| `""` | Legacy device or no license info |

### `license_days_remaining` values

| Value | Meaning |
|-------|---------|
| `≥ 86400` | Displayed as days |
| `≥ 3600` | Displayed as hours |
| `≥ 60` | Displayed as minutes |
| `0` | Expired |
| `null` | No expiry date set |

---

## Organization-Level License State

| Field | Type | Values | Meaning |
|-------|------|--------|---------|
| `subscription_status` | string | `trialing` / `active` / `past_due` / `canceled` / `none` | Current billing state |
| `trial_ends_at` | datetime | ISO timestamp or null | When free trial expires |
| `plan` | enum | `free` / `professional` / `msp` | Legacy plan enum |
| `plan_id` | FK | UUID or null | Current dynamic plan |
| `device_count` | int | e.g. 5 | Subscribed device capacity |
| `subscription_term` | string | `"monthly"` / `"yearly"` | Default billing term |
| `license_allocations` | JSON | `{"monthly": {"10": 3}}` | Per-term tier counts (MSP) |

---

## Database Tables

### `plans`

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID | PK |
| `name` | string, unique | Display name |
| `plan_type` | `"professional"` / `"msp"` | Pricing model |
| `is_active` / `is_visible` | bool | Controls availability |
| `features` | JSON | Feature flags |
| `price_per_device` | float | Professional only |
| `pricing_tiers` | JSON | MSP only: `{"10": 49, "25": 99}` |
| `yearly_discount_pct` | int | e.g. 20 = 20% off |
| `is_testing` | bool | Short-lived test plan |
| `validity_minutes` | int | 0 = standard; e.g. 5, 30, 1440 |

### `license_purchases`

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID | PK |
| `organization_id` | FK | Owning org |
| `subscription_term` | `"monthly"` / `"yearly"` | Billing period |
| `tier` | string, nullable | MSP tier key (e.g. `"10"`) |
| `tier_device_count` | int | Devices per tier unit |
| `count` | int | Units purchased |
| `total_devices` | int | `count × tier_device_count` (or `count` for Pro) |
| `purchased_at` | datetime | When purchased |
| `expires_at` | datetime | When it expires |

### `devices` (license columns)

| Column | Type | Purpose |
|--------|------|---------|
| `license_purchase_id` | FK, nullable | Which purchase consumed |
| `license_info` | JSON | Cached purchase snapshot |
| `decommissioned` | bool | Soft-delete |
| `decommissioned_at` | datetime, nullable | When decommissioned |

---

## How the Devices Widget Uses License Data

In `SecurityAnalytics.tsx`, the `DevicesWidget` calls `api.listDevices()`
and groups the returned devices:

```
Configured     ← configured === true
Not Configured ← configured === false

Active         ← license_bundle contains "Active" (anything not starting with "Expired")
Expired        ← license_bundle starts with "Expired"
```

---

## What a License Dashboard Widget Needs

To build a license overview widget, surface these aggregates from the existing
per-device data plus org-level state:

### From devices (already available via `listDevices()`)

- **Total licensed devices**: `SUM(total_devices)` across active purchases
- **In use**: `COUNT(devices WHERE decommissioned = false)`
- **Available slots**: licensed − in use
- **Active devices**: devices with non-expired license
- **Expiring soon (≤30 days)**: `license_days_remaining ≤ 30 AND > 0`
- **Expired**: `license_days_remaining === 0`

### From organization (available via `getOrganization()`)

- **Subscription status**: trial / active / past_due
- **Trial days remaining**: `trial_ends_at − now`
- **Plan name**: from `active_plan.name` or `plan` enum
- **Billing term**: monthly / yearly

### Recommended widget layout

```
┌─ License Summary ─────────────────────────┐
│                                            │
│  Professional Plan · Active                │
│  Renews Aug 15, 2026 (14 days)             │
│                                            │
│  ████████████████░░░░  8/10 devices used   │
│                                            │
│  Active      8                             │
│  Expiring    1 (≤30 days)                  │
│  Expired     0                             │
│  Available   2 slots                        │
└────────────────────────────────────────────┘
```

Or for trial orgs:

```
┌─ License Summary ─────────────────────────┐
│                                            │
│  Free Trial · 16 days remaining            │
│                                            │
│  ████████████████░░░░  1/1 devices used    │
│                                            │
│  Upgrade to Professional →                 │
└────────────────────────────────────────────┘
```
