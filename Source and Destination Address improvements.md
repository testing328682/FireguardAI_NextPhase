I want to extend the existing Management Rules functionality that we already implemented.

Do not redesign or rebuild the existing Management Rules architecture. First inspect the current implementation and understand how the existing semantic conditions, TSR resolution, rule schema, UI, and finding generation work. Then extend them cleanly.

## 1. Source and Destination Address improvements

Currently, Source Address and Destination Address can use semantic options such as:

- All Interface IPs
- Specific Interface IP

I now want to add another option:

- Specific IP Address

For example:

```text
Destination Address:
    Specific IP
    192.168.1.1
```

The behavior should be:

1. Retrieve the destination address reference from the access rule.
2. Resolve the referenced address object or address group.
3. Recursively resolve nested address groups and address objects as the existing implementation already does.
4. Extract the actual IP addresses, subnets, or relevant address values.
5. Compare the resolved addresses against the IP address defined in the Management Rule.
6. If there is a valid match, the condition is satisfied.

Do not perform this as a simple string comparison.

Use proper IP/network comparison so that subnet objects are handled correctly.

The same functionality must work for both:

```text
Source Address
Destination Address
```

For example:

```text
Management Rule:

Source Address:
    Specific IP
    10.10.10.50
```

should match an access rule if its source address object/group ultimately resolves to an address containing `10.10.10.50`.

The exact comparison semantics should follow the existing address resolution architecture.

---

## 2. Keep interface-based options

Do not remove or change the existing options.

Source Address and Destination Address should continue supporting:

```text
All Interface IPs
Specific Interface IP
Specific IP Address
```

The UI should make these options easy to select.

For example:

```text
Destination Address
[ Specific IP ▼ ]

IP Address
[ 192.168.1.1 ]
```

For:

```text
Destination Address
[ X0 Interface IP ▼ ]
```

the system should continue resolving the X0 IP from the TSR exactly as the existing implementation does.

Do not hardcode interface IPs.

---

# 3. Service semantic matching

I also want to extend the Service condition using the same semantic-resolution concept.

Add a semantic option:

```text
All Management Ports
```

The purpose is to detect access rules that expose any of the firewall's configured management ports.

The management ports should be retrieved dynamically from the TSR.

At minimum, identify:

- HTTP management port
- HTTPS management port
- SSH management port

Do not assume that the ports are always:

```text
80
443
22
```

Those are only defaults.

If the TSR shows that the firewall is configured with:

```text
HTTP  = 8080
HTTPS = 8443
SSH   = 2222
```

then:

```text
All Management Ports
```

must resolve to:

```text
8080
8443
2222
```

---

# 4. Service object/group resolution

Use the same principle already implemented for address objects and groups.

An access rule may contain:

```text
service = "HTTPS Management"
```

The evaluator should:

1. Retrieve the service reference.
2. Resolve the corresponding service object.
3. Resolve service groups where applicable.
4. Recursively resolve nested service groups.
5. Extract the actual protocol and port information.
6. Compare the resolved services against the configured management ports from the TSR.

Do not compare service names.

For example, an access rule could contain:

```text
service = "My Custom HTTPS Service"
```

and the TSR may show that this service is:

```text
TCP/443
```

If the firewall's configured HTTPS management port is `443`, then:

```text
Service = All Management Ports
```

must match.

The service name does not matter. The underlying protocol and port do.

---

# 5. Service groups and nested groups

Make sure the service resolver handles:

```text
Service Object
Service Group
Nested Service Groups
```

For example:

```text
Management Services
 ├── HTTPS Custom
 ├── HTTP Custom
 └── Remote Management
      ├── SSH Custom
      └── Other Service
```

If the access rule references `Management Services`, the evaluator must recursively resolve the entire tree and compare the underlying protocol/port combinations against the firewall's management ports.

Also make sure circular service group references cannot cause infinite recursion.

Reuse the same recursive resolution pattern already implemented for address groups wherever practical.

---

# 6. Zone wildcard

I also want a wildcard option for Source Zone and Destination Zone.

The value:

```text
*
```

should mean:

```text
Any Zone
```

It must NOT be treated as a literal zone name.

For example:

```text
Source Zone:
    *

Destination Zone:
    WAN
```

means:

```text
Match any source zone
AND
destination zone must be WAN
```

Similarly:

```text
Source Zone:
    WAN

Destination Zone:
    *
```

means:

```text
Source zone must be WAN
AND
any destination zone is acceptable
```

And:

```text
Source Zone:
    *

Destination Zone:
    *
```

means:

```text
Any source zone
AND
any destination zone
```

Please represent this internally as a proper wildcard/ANY condition rather than relying on string comparisons wherever possible.

---

# 7. Consistency between fields

The Management Rule engine should now be capable of combining these conditions.

For example:

```text
Source Zone:
    *

Destination Zone:
    WAN

Source Address:
    Specific IP
    10.10.10.50

Destination Address:
    X0 Interface IP

Service:
    All Management Ports
```

The evaluator should correctly process all of these conditions together.

Conceptually:

```text
Access Rule
    │
    ├── Source Zone
    │      └── Wildcard → Match anything
    │
    ├── Destination Zone
    │      └── Direct comparison → WAN
    │
    ├── Source Address
    │      └── Resolve → Compare with 10.10.10.50
    │
    ├── Destination Address
    │      └── Resolve → Compare with X0 IP
    │
    └── Service
           └── Resolve → Compare with management ports
```

All conditions should be evaluated using the existing Management Rules architecture.

---

# 8. UI requirements

Update the Management Rules UI so these new options can be configured naturally.

For Source Address and Destination Address, provide:

```text
All Interface IPs
Specific Interface IP
Specific IP Address
```

For Specific IP Address, show an appropriate IP input field.

For Source Zone and Destination Zone, include:

```text
*
```

as the first or most obvious wildcard option.

For Service, provide:

```text
All Management Ports
```

and preserve the existing service condition functionality.

The UI should not expose technical implementation details such as "semantic resolver" or "reference resolution".

---

# 9. Do not duplicate existing functionality

Before making changes, inspect the implementation from the previous Management Rules work.

Reuse:

- Existing TSR normalized models
- Existing address resolver
- Existing recursive group resolver
- Existing service parser/resolver if available
- Existing interface parser
- Existing rule condition schema
- Existing finding generation
- Existing UI components

Do not create parallel implementations of functionality that already exists.

If something needs to be generalized to support these new conditions, refactor the existing implementation rather than duplicating it.

---

# 10. Testing

Add or update tests for at least:

### Address

- Specific IP matches directly resolved address
- Specific IP matches an address inside an address group
- Specific IP matches through nested address groups
- Specific IP does not match unrelated addresses
- Specific IP correctly handles subnet objects
- Existing All Interface IPs behavior still works
- Existing Specific Interface behavior still works

### Services

- All Management Ports matches HTTP management port
- All Management Ports matches HTTPS management port
- All Management Ports matches SSH management port
- Custom service name resolving to a management port matches
- Service groups resolve correctly
- Nested service groups resolve correctly
- Non-management service does not match
- Custom management ports from the TSR are respected
- Circular service groups do not cause infinite recursion

### Zones

- `*` matches any source zone
- `*` matches any destination zone
- `*` combined with a specific zone works correctly
- `*` for both zones works correctly
- Existing direct zone matching remains unchanged

### Combined conditions

Test combinations such as:

```text
Source Zone = *
Destination Zone = WAN
Destination Address = X0 Interface IP
Service = All Management Ports
```

and:

```text
Source Address = Specific IP
Destination Address = Specific IP
Service = All Management Ports
```

Make sure the existing CEL Rule Builder and existing Management Rules continue to work exactly as before.

---

## 11. Important implementation principle

Do not implement these as isolated hardcoded special cases.

For example, avoid creating separate logic like:

```text
if value == "All Management Ports":
    do something
```

without integrating it into the existing semantic condition framework.

Instead, extend the current semantic target/resolver architecture so that:

```text
Address
    ├── All Interface IPs
    ├── Specific Interface IP
    └── Specific IP

Service
    └── All Management Ports

Zone
    └── Any / *
```

are simply additional supported condition types.

Before modifying code, inspect the current implementation and briefly explain which existing components you will extend or reuse. Then implement the changes and add the required tests.