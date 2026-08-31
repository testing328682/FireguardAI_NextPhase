I need you to make changes to the Server Admin → Rule Builder area.

This is a relatively complex change because the new Rule Builder type needs to resolve and correlate objects from the TSR rather than simply evaluating direct string conditions. Please do not start implementing immediately. First understand the existing architecture and propose a proper design.

## 1. Rule Builder navigation changes

Currently, the left navigation has:

- Rule Builder which has "CEL Rule Builder"

The existing CEL Rule Builder is already implemented and should remain fully functional.

I now want Rule Builder to become a parent navigation item with subpages:

- Rule Builder
  - CEL Rule Builder
  - Management Rules

This architecture should also make it easy to add additional Rule Builder subpages in the future.

Do not duplicate or break the existing CEL Rule Builder implementation. Ideally, refactor the navigation/routing structure cleanly so additional rule types can be added later.

---

# 2. Management Rules

Create a new:

`Management Rules`

subpage under Rule Builder.

The purpose of this page is to create detection rules specifically for firewall management-related access rules.

For example, I may want to detect firewall management access from the Internet.

A Management Rule should be able to define conditions against access rules, but some conditions require resolving references inside the TSR.

This is fundamentally different from the current CEL Rule Builder.

---

# 3. Difference from CEL Rule Builder

In the existing CEL Rule Builder, a condition might look like:

`x.src == "GMS Addresses"`

This performs a direct comparison against the value contained in the access rule.

For example:

`src = "GMS Addresses"`

matches:

`x.src == "GMS Addresses"`

The Management Rules system needs to support higher-level semantic conditions.

For example:

`Destination Address = All Interface IPs`

This does NOT mean:

`x.dst == "All Interface IPs"`

Instead, it means:

1. Find the destination address reference used by the access rule.
2. Resolve that reference against the address objects/address groups in the TSR.
3. Recursively resolve all nested groups.
4. Extract the actual IPs/hosts represented by those objects.
5. Retrieve all firewall interface IPs from the TSR.
6. Compare the resolved destination IPs against the firewall interface IPs.
7. If there is a match, the Management Rule is considered satisfied and should generate a finding.

This distinction is extremely important.

---

# 4. Example Management Rule

I want to be able to create a Management Rule with conditions such as:

### Access Rule conditions

Source Zone:

`WAN`

Destination Zone:

`WAN`

Destination Address:

`All Interface IPs`

Potentially later:

Source Address:

`GMS Addresses`

Service:

`HTTPS Management`

etc.

The first two conditions are straightforward.

For example:

`src_zone == WAN`

and

`dst_zone == WAN`

These can directly evaluate the access rule fields.

But:

`dst_address == All Interface IPs`

requires TSR object resolution.

---

# 5. Concrete TSR example

Suppose the TSR contains:

```text
▾ ACCESS_RULES [443]
  ▾ [0] {15}
      num = 1
      src_zone = "WAN"
      dst_zone = "WAN"
      action = "Allow"
      service = "HTTPS Management"
      enabled = true
      src = "GMS Addresses"
      dst = "All X0 Management IP"
      name = "Default Access Rule"
      comment = "Auto-added GMS rule"
      auto_rule = false
      management = true
      usage = 0
      last_hit = "00/00/0000 00:00:00.000"
      ipver = "IPv4"
```

The Management Rule could be:

```text
Source Zone       = WAN
Destination Zone  = WAN
Destination       = All Interface IPs
```

The evaluation should work like this.

### Step 1

Evaluate the simple access rule conditions:

```text
src_zone == WAN
dst_zone == WAN
```

The access rule satisfies both.

### Step 2

The Management Rule's destination condition is:

```text
Destination = All Interface IPs
```

This is NOT a literal comparison against:

```text
x.dst == "All Interface IPs"
```

Instead, retrieve:

```text
x.dst = "All X0 Management IP"
```

At this point, we only know the name of the referenced address object/group.

### Step 3

Resolve the referenced address object/group.

Search the TSR to find  address object or address group with "All X0 Management IP" name:

```text
"All X0 Management IP"
```

The resolver must support both:

- Address Objects
- Address Groups

This is important because an access rule can reference either one.

### Step 4

Resolve the complete object tree

Address Groups can contain:

- Address Objects
- Other Address Groups
- Nested Address Groups
- Multiple levels of nesting

For example:

```text
Group A
 ├── Object 1
 ├── Object 2
 └── Group B
      ├── Object 3
      └── Group C
           ├── Object 4
           └── Object 5
```

If an access rule references `Group A`, the resolver must recursively traverse the entire structure and ultimately retrieve all underlying address values.

Do not stop at the first level.

The final result should represent the complete set of addresses represented by the referenced object/group.

---

# 6. Address object types

Address Objects can represent different types of values, including:

- IP address
- Subnet
- Domain name / hostname

The resolver needs to understand these types appropriately.

For the specific `All Interface IPs` condition, the important comparison is against actual interface IP addresses.

Do not assume that every address object is simply a single IPv4 host.

Design this as a reusable address-resolution layer so other Management Rule conditions can use the same functionality later.

---

# 7. Interface IP resolution

For:

`Destination = All Interface IPs`

the system should first retrieve all relevant firewall interface IP addresses from the TSR.

For example, conceptually:

```text
X0 = 192.168.1.1
X1 = 10.10.10.1
X2 = 172.16.1.1
...
```

The actual interfaces available must come from the TSR.

Do not hardcode X0, X1, X2, etc.

The Management Rules UI could eventually provide options such as:

```text
All Interface IPs
X0 Interface IP
X1 Interface IP
X2 Interface IP
...
```

The available interface options should ideally be generated dynamically based on the interface information supported by the TSR/parser.

For now, architect the backend so that additional semantic targets such as individual interface IPs can be added without redesigning the entire rule engine.

---

# 8. Comparison

Once the access rule's destination reference has been recursively resolved, compare its resulting addresses against the interface IPs.

For example:

```text
Firewall Interfaces

X0 = 192.168.1.1
X1 = 10.0.0.1
```

Access rule:

```text
dst = "All X0 Management IP"
```

Resolved object:

```text
All X0 Management IP
    → 192.168.1.1
```

Comparison:

```text
192.168.1.1 == X0 interface IP
```

Match found.

Therefore:

```text
Management Rule = SATISFIED
```

and a finding should be generated for that device.

---

# 9. Important: Same name for Object and Group

The TSR can contain an Address Object and an Address Group with the same name.

For example:

```text
Address Object:
name = "Management Servers"

Address Group:
name = "Management Servers"
```

The resolver must not assume that a name uniquely identifies one type.

Design the data model/resolution logic so both can be discovered and evaluated.

If the access rule references a name that exists as both an object and a group, determine the correct behavior based on how SonicWall represents the reference in the TSR.

Do not simply overwrite one with the other in a dictionary such as:

```python
objects[name] = ...
```

because that could silently lose one of the entries.

Architect the resolver to handle name collisions safely and deterministically.

---

# 10. Recursive resolution and circular references

Because groups can contain other groups, also consider circular references.

For example:

```text
Group A
  → Group B
      → Group C
          → Group A
```

The resolver must never enter an infinite loop.

Use a visited-set/path tracking mechanism when recursively resolving groups.

The resolver should safely detect cycles and continue processing any other valid branches.

---

# 11. Apply the same architecture to other access rule fields

This semantic resolution architecture should NOT be limited to destination addresses.

I want the same concept to eventually work for:

- Source Address
- Destination Address
- Service
- Source Zone
- Destination Zone
- Other access-rule properties where references need to be resolved

For example, a future Management Rule could say:

```text
Source Address = <semantic condition>
Destination Address = <semantic condition>
Service = <semantic condition>
```

The important thing is that the architecture should separate:

1. Raw TSR parsing
2. TSR entity/object resolution
3. Semantic condition evaluation
4. Management Rule definition
5. Finding generation

Do not put all of this logic directly inside one large Management Rules evaluator.

---

# 12. Recommended architecture

Before implementing, inspect the existing codebase and determine the current architecture for:

- TSR parsing
- Access rule extraction
- Address object parsing
- Address group parsing
- Service parsing
- Interface parsing
- CEL Rule Builder
- Rule storage
- Rule execution/evaluation
- Finding generation
- Device analysis workflow

Then propose an architecture for Management Rules.

I would strongly prefer something conceptually similar to:

```text
TSR
 │
 ├── Access Rule Parser
 ├── Address Object Parser
 ├── Address Group Parser
 ├── Service Parser
 └── Interface Parser
          │
          ▼
   Normalized TSR Model
          │
          ▼
   Reference Resolver
          │
          ├── Address Resolver
          ├── Service Resolver
          ├── Interface Resolver
          └── Group/Reference Resolver
          │
          ▼
   Management Rule Evaluator
          │
          ▼
     Rule Result
          │
          ▼
      Finding Engine
```

This is only a conceptual direction. Inspect the existing code and adapt it to the current architecture rather than blindly implementing this exact structure.

---

# 13. Management Rule UI

Create a UI for creating Management Rules.

The UI should allow the administrator to define conditions in a structured way rather than requiring CEL syntax.

For example:

```text
Management Rule Name
[ Externally Accessible Firewall Management ]

Conditions

Field             Operator / Condition       Value
------------------------------------------------------
Source Zone       is                         WAN
Destination Zone  is                         WAN
Destination       matches                    All Interface IPs

                         [+ Add Condition]

[ Save Rule ]
```

The available fields and condition types should be designed so new semantic conditions can be added later.

For example:

```text
Destination
  ├── Any
  ├── All Interface IPs
  ├── Specific Interface IP
  └── ...
```

Do not overbuild the UI with every possible condition now.

Build a clean foundation that can be extended.

---

# 14. Rule evaluation behavior

When a device is analyzed:

1. Load the TSR.
2. Parse/normalize the relevant TSR sections.
3. Load active Management Rules.
4. Evaluate each Management Rule against the TSR.
5. Identify matching access rules.
6. Resolve references where required.
7. Evaluate semantic conditions.
8. Generate findings when a rule matches.
9. Ensure the finding contains enough context to explain why it matched.

For example, the finding should ideally be able to explain something like:

```text
Management access rule exposes a firewall interface IP.

Access Rule:
Default Access Rule

Source Zone:
WAN

Destination Zone:
WAN

Destination Address:
All X0 Management IP

Resolved Address:
192.168.1.1

Matched Interface:
X0

Service:
HTTPS Management
```

Use the existing finding architecture and UI conventions wherever possible.

---

# 15. Avoid duplicating TSR parsing logic

Before writing new parsers, inspect whether the existing CEL Rule Builder or TSR analyzer already has normalized representations of:

- Access Rules
- Address Objects
- Address Groups
- Services
- Interfaces

If they already exist, reuse them.

Do not create a second independent TSR parser unless there is a strong architectural reason.

If the existing representation is insufficient, refactor it into a reusable normalized model instead.

The goal is to have one reliable source of truth for TSR data.

---

# 16. Performance considerations

Be careful about repeatedly scanning the entire TSR for every access rule.

For example, do not do something equivalent to:

```text
For every access rule:
    Search entire TSR for address object
    Search entire TSR for address group
    Search entire TSR for nested groups
```

Instead, consider building indexed structures once:

```text
address_objects_by_name
address_groups_by_name
interfaces_by_name
services_by_name
```

Then resolve references efficiently.

Also consider caching resolved address groups during a single analysis.

The resolver should avoid repeatedly traversing the same nested group tree.

---

# 17. IPv4, IPv6, subnets and comparison semantics

Do not implement IP comparison as simple string comparison.

Use proper IP/network handling.

For example, these should be treated appropriately:

```text
192.168.1.1
192.168.1.0/24
```

If an address object represents a subnet, determine whether the interface IP falls within that subnet.

Also account for `ipver` where relevant.

Do not accidentally match:

```text
10.0.0.1
```

against:

```text
110.0.0.1
```

because of string-based comparison.

Use the appropriate IP address/network libraries already used by the project, or introduce a well-established standard library solution if necessary.

---

# 18. Important architectural requirement

Please do NOT start coding immediately.

First:

### Phase 1: Understand

Inspect the existing implementation and identify:

- Relevant frontend routes/components
- Backend APIs
- Database models
- TSR parser/data structures
- Existing CEL Rule Builder architecture
- Finding generation flow
- Existing address object/group representations

### Phase 2: Design

Provide me with:

1. Proposed frontend architecture
2. Proposed backend architecture
3. Data model changes, if required
4. API changes
5. Rule schema
6. TSR normalization/resolution strategy
7. Recursive group resolution strategy
8. Handling of object/group name collisions
9. Handling of circular groups
10. Finding generation flow
11. How the design can support future Management Rule conditions
12. Any migration or backward compatibility concerns

### Phase 3: Implementation

Only after the architecture is clear, implement the changes.

Keep the existing CEL Rule Builder working exactly as it does today.

Do not introduce unnecessary changes to unrelated parts of the application.

---

# 19. Testing requirements

Create or update tests for at least these scenarios:

### Basic matching

```text
src_zone = WAN
dst_zone = WAN
dst object resolves directly to interface IP
→ Finding
```

### No match

```text
dst object resolves to an unrelated IP
→ No finding
```

### Address Group

```text
Access rule
→ Address Group
→ Address Object
→ Interface IP
→ Finding
```

### Nested Address Groups

```text
Access rule
→ Group A
→ Group B
→ Group C
→ Address Object
→ Interface IP
→ Finding
```

### Same object/group name

```text
Address Object:
Management

Address Group:
Management
```

Verify that both are handled correctly according to TSR semantics.

### Circular groups

Verify that:

```text
A → B → C → A
```

does not cause infinite recursion.

### Subnet matching

Verify correct network membership behavior.

### Multiple interfaces

Verify that the resolver correctly compares against all available interface IPs.

### Multiple matching addresses

Verify that findings are deterministic and do not create unnecessary duplicate findings.

### Multiple matching access rules

Verify that the Management Rule can correctly identify all matching access rules.

---

# 20. Most important goal

I don't want this implemented as a collection of special-case checks such as:

```python
if condition == "All Interface IPs":
    ...
```

That may work for one rule but will become difficult to maintain.

Instead, build a reusable semantic rule evaluation framework where:

```text
Raw TSR value
      ↓
Reference resolution
      ↓
Normalized entity/value
      ↓
Semantic condition
      ↓
Rule evaluation
      ↓
Finding
```

The `All Interface IPs` condition should simply be the first semantic condition implemented using that framework.

Future conditions should be able to reuse the same resolver and evaluator.

Please inspect the existing codebase first, then give me the proposed architecture and implementation plan before making code changes.


# 21. Rule metadata

Each Management Rule should also support complete rule metadata.

When creating or editing a Management Rule, provide fields for:

* Title
* Description
* Severity
* Category
* Remediation

These fields are important because they should be carried through to the resulting finding when the Management Rule matches an access rule.

For example:

```text id="m4n8q2"
Title:
Firewall Management Exposed to WAN

Description:
The firewall management interface is accessible from the WAN through an enabled access rule.

Severity:
Critical

Category:
Firewall Management

Remediation:
Restrict firewall management access to trusted source addresses and avoid exposing management interfaces directly to the Internet.
```

The metadata should be stored as part of the Management Rule definition and should not need to be manually recreated when a finding is generated.

When the rule produces a finding, the finding should inherit the appropriate metadata from the rule:

```text id="q7x3pd"
Management Rule
      │
      ├── Title
      ├── Description
      ├── Severity
      ├── Category
      ├── Remediation
      │
      ▼
   Rule Evaluation
      │
      ▼
    Finding
```

Please inspect the existing rule/finding models and UI to determine whether these metadata fields already exist and can be reused.

If the existing CEL Rule Builder already has a similar metadata structure, reuse the existing implementation or common model wherever practical rather than creating duplicate metadata systems.

Also make sure these fields are available when creating and editing Management Rules, and that they are displayed correctly wherever findings are shown, including the existing Device Findings UI and any report/export functionality that already supports these fields.

Do not hardcode severity, category, or remediation values into the evaluator. These should be properties of the individual Management Rule so that different rules can define their own metadata.

The architecture should also make it easy to add additional metadata fields in the future without requiring changes to the core rule evaluation engine.
