# IDOR — Insecure Direct Object Reference Hunting Methodology

## Types to Hunt

| Type | Description |
|---|---|
| Horizontal IDOR | Access another user's data at same privilege level |
| Vertical IDOR | Access higher-privilege resources (user → admin) |
| Function-level IDOR | Call admin/restricted API functions as normal user |
| Indirect reference | Use predictable/guessable reference (sequential IDs, UUIDs) |

## Finding IDOR Entry Points

Look for any parameter that references a resource owned by a user:

- `?id=`, `?user_id=`, `?account_id=`, `?order_id=`, `?invoice_id=`
- Path parameters: `/api/users/123/profile`, `/orders/456/receipt`
- POST body: `{"target_user_id": 789}`
- GUIDs: even `?id=550e8400-e29b-41d4-a716-446655440000` may be IDOR if server doesn't verify ownership

**High-value targets to test:**
- User profile/settings endpoints (`/api/user/<id>`)
- Order/invoice/payment history (`/orders/<id>`)
- File download/export (`/export?report_id=<id>`)
- Message/notification retrieval (`/messages/<id>`)
- Admin APIs accessible from user JWT (check for unprotected `/api/admin/` endpoints)
- Password reset token usage (`/reset?token=<token>&user_id=<id>`)

## Confirmation Approach — Two Account Test

The gold standard for IDOR confirmation:

1. Create **Account A** and **Account B**
2. From Account A, note the resource ID (order, profile, message, etc.)
3. Log into **Account B** (different session/token)
4. From Account B, attempt to access Account A's resource using Account A's ID
5. If successful → IDOR confirmed

Provide both the request from Account B AND the response showing Account A's data.

## Authorization Check Locations (what to look for in code)

Vulnerable pattern — missing authorization check:
```
// VULNERABLE: only checks auth, not ownership
app.get('/orders/:id', authenticate, (req, res) => {
  const order = Order.findById(req.params.id)  // No ownership check!
  res.json(order)
})
```

Secure pattern — proper authorization:
```
// SAFE: checks both auth and ownership
app.get('/orders/:id', authenticate, (req, res) => {
  const order = Order.findOne({ id: req.params.id, user_id: req.user.id })
  if (!order) return res.status(403).json({ error: 'Forbidden' })
  res.json(order)
})
```

## UUID/GUID IDORs

Do NOT assume UUIDs are safe from IDOR. The reference value being hard to guess does NOT mean authorization is enforced. Test:
1. Note your UUID resource reference
2. Share/leak the UUID (e.g., in a URL) and test if another user can access it
3. If yes → IDOR exists, even if UUID is not guessable

UUIDs prevent enumeration but do NOT enforce access control.

## Mass Assignment IDOR

Sending additional fields in a PUT/PATCH that shouldn't be user-modifiable:
- `{"role": "admin"}` in profile update
- `{"user_id": 1}` in account settings
- `{"price": 0.01}` in checkout

Test by adding sensitive fields to update requests and checking if they take effect.

## Impact by Data Type

| Data Exposed | Severity |
|---|---|
| PII (name, email, address, phone) | High |
| Financial data (payment methods, transaction history) | High/Critical |
| Private messages | High |
| Account credentials or tokens | Critical |
| Public profile data (username, bio) | Low / Not reportable |
| Internal IDs without sensitive data | Low / Not reportable |

## Do Not Report
- Accessing public or non-sensitive data via known IDs
- IDOR that requires admin access to exploit (admin IDORing another admin)
- Enumerating sequential IDs without confirmed data leak (speculation)
