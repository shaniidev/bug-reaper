# Business Logic — Hunting Methodology

Business logic vulnerabilities abuse the application's intended functionality in ways developers didn't anticipate. They require understanding the business workflow, not just payloads.

## High-Value Business Logic Areas

| Area | What to Test |
|---|---|
| Pricing / Checkout | Price manipulation, negative quantities, coupon stacking |
| Workflow enforcement | Skipping required steps in multi-step flows |
| Race conditions | Double-spend, duplicate account creation, coupon reuse |
| Limit bypass | Rate limits, API quotas, subscription tier bypasses |
| Referral/reward abuse | Self-referral, circular referrals, credit multiplication |
| Account actions | Mass account creation, email enumeration, permission abuse |

## Price / Checkout Manipulation

**Test 1 — Negative Quantity:**
`{"quantity": -1, "item_id": "ABC"}` in cart API
If server calculates `price * quantity` and doesn't validate → negative total

**Test 2 — Price Parameter Tampering:**
Intercept cart update request, change `price` field directly
If server trusts client-provided price → price set to $0.01

**Test 3 — Integer Overflow:**
Very large quantities may overflow to negative numbers
`"quantity": 9999999999`

**Test 4 — Coupon Stacking:**
Apply same coupon code multiple times in one order
Apply multiple single-use coupons in parallel (race)

**Test 5 — Free Items:**
Remove specific items from order after discount applies
Add/remove items to make total < 0 or free

## Workflow / Step Bypass

Multi-step processes (checkout, KYC, email verification, quiz):
1. Start the flow, intercept state token at step 1
2. Jump directly to the final step endpoint with state token from step 1
3. Does the server enforce sequential completion?

**Also check:**
- Can you place an order without completing payment?
- Can you access premium content before subscription confirmed?
- Can you skip identity verification?
- Can you change email without confirming old email?

## Race Conditions

**Target:** Any operation that should only succeed once but might be exploitable via parallel requests.

*Common targets:*
- One-time coupon codes
- Free trial activation (one per account/email)
- Limited quantity items
- Currency transfers
- Referral bonus credit

**Exploitation method (suggest to user):**
Send 20-50 identical requests simultaneously using tools like `turbo intruder` or `ffuf` with `--rate 0` and parallel connections.

If server doesn't use database-level locking:
- Multiple successful redemptions of single-use coupon → free credits
- Double credit on transfer → duplication

**Confirm with two accounts:** Apply coupon in parallel from both → check if both receive discount.

## Tier / Subscription Bypass

- Sign up for free tier, explore what API endpoints are called for paid features
- Call paid-feature API endpoints directly with free-tier token
- Check if server enforces tier via JWT claim that can be modified (see auth-bypass.md)
- Downgrade account after accessing paid content — confirm content access is revoked

## Referral / Reward Abuse

- Self-referral: use your own referral link to sign up with secondary email
- Circular: A refers B, B refers A → infinite loop
- Apply referral after purchase (timing bypass)
- Referral credit without full signup completion by referred user

## Limit Bypass Techniques

If per-account limits exist, test:
- Same action with different user accounts (is limit per-user or per-session?)
- Same action with different IPs (`X-Forwarded-For` header rotation)
- Resetting count by deleting and re-creating items
- Parallel requests before server updates count

## Impact Classification

| Business Logic Bug | Severity |
|---|---|
| Price manipulation → free/negative price | High/Critical |
| Race condition on payment → double credit | High |
| Workflow bypass → access without payment | High |
| Coupon reuse / stacking | Medium/High |
| Tier bypass → premium content free | Medium/High |
| Self-referral Credit Abuse | Medium |
| Rate limit bypass (without exploitable action) | Low |

## Reportability Criteria

Business logic bugs MUST demonstrate:
1. Concrete financial or data loss beyond theoretical
2. Working reproduction (exact requests showing unexpected outcome)
3. The application's intended behavior (what SHOULD happen) vs what DOES happen
4. Not just a UX inconvenience — actual security/business impact
