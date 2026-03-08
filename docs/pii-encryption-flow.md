# PII Encryption Flow: Bidirectional Restoration

## Overview

AgentGate now implements **bidirectional PII restoration** - an encrypted conversation mode where:
- Users see their original sensitive data
- AI receives unique placeholders
- Responses are seamlessly rehydrated
- **PII never leaves your infrastructure**

This creates a natural conversation flow while maintaining complete data protection.

## Contract Update (Session-Scoped API)

The API contract is strict:

- `POST /api/pii/redact` requires `session_id`
- `POST /api/pii/restore` requires `session_id`
- Session must be created first via `POST /api/pii/sessions`

Canonical persistence uses two tables:

- `pii_human_mappings`: encrypted human-side values
- `pii_ai_tokens`: AI-facing token references (`<TYPE_N>`)

Token restoration is fail-closed for unknown or invalid mappings when policy is `fail_closed`.

---

## How It Works

### The Flow

```
┌─────────────┐
│  User Input │  "My SSN is 123-45-6789"
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Detect    │  Presidio NLP detects SSN
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Encrypt   │  Replace with <SSN_1>
│   (Redact)  │  Store mapping: <SSN_1> → 123-45-6789
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Send to AI │  "My SSN is <SSN_1>"
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ AI Response │  "I've recorded <SSN_1> for your account"
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Rehydrate  │  Replace <SSN_1> with 123-45-6789
│  (Restore)  │  "I've recorded 123-45-6789 for your account"
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ User Sees   │  Full response with real PII restored
└─────────────┘
```

---

## Real-World Example

### Conversation with PII

**User Types:**
```
My SSN is 123-45-6789 and email is john.doe@company.com.
Can you file my tax return?
```

**System Encrypts (invisible to user):**
```
Detected: SSN (123-45-6789), EMAIL (john.doe@company.com)
Created placeholders:
  <SSN_1> → 123-45-6789
  <EMAIL_1> → john.doe@company.com
```

**Sent to OpenAI:**
```
My SSN is <SSN_1> and email is <EMAIL_1>.
Can you file my tax return?
```

**AI Responds (with placeholders):**
```
I've recorded your SSN <SSN_1> and will send confirmation to <EMAIL_1>.
To proceed with filing, I'll need your W-2 forms. Please note that
<SSN_1> will be used for IRS verification.
```

**System Rehydrates:**
```
I've recorded your SSN 123-45-6789 and will send confirmation to john.doe@company.com.
To proceed with filing, I'll need your W-2 forms. Please note that
123-45-6789 will be used for IRS verification.
```

**User Sees:**
```
I've recorded your SSN 123-45-6789 and will send confirmation to john.doe@company.com.
To proceed with filing, I'll need your W-2 forms. Please note that
123-45-6789 will be used for IRS verification.
```

### Key Insight

The AI can **reference** the PII using placeholders! It can:
- Acknowledge receiving it
- Use it in context
- Reference it multiple times
- Build coherent responses

But the actual sensitive values **never leave your infrastructure**.

---

## Multiple PII Items

### Scenario: Healthcare Form

**User Types:**
```
Please update my records:
- SSN: 123-45-6789
- Phone: 555-123-4567
- Email: patient@email.com
- DOB: 01/15/1980
```

**Encrypted Placeholders:**
```
<SSN_1> → 123-45-6789
<PHONE_1> → 555-123-4567
<EMAIL_1> → patient@email.com
<DATE_1> → 01/15/1980
```

**Sent to AI:**
```
Please update my records:
- SSN: <SSN_1>
- Phone: <PHONE_1>
- Email: <EMAIL_1>
- DOB: <DATE_1>
```

**AI Response (with placeholders):**
```
I've updated your records:

✓ SSN <SSN_1> verified
✓ Phone <PHONE_1> confirmed
✓ Email <EMAIL_1> added to notifications
✓ DOB <DATE_1> matches existing records

Your profile is now complete. Confirmation sent to <EMAIL_1>.
```

**User Sees (fully rehydrated):**
```
I've updated your records:

✓ SSN 123-45-6789 verified
✓ Phone 555-123-4567 confirmed
✓ Email patient@email.com added to notifications
✓ DOB 01/15/1980 matches existing records

Your profile is now complete. Confirmation sent to patient@email.com.
```

---

## Persistent Mappings

Placeholders are **session-persistent** - the same PII value always gets the same placeholder:

### First Message

**User:**
```
My email is john@company.com
```

**Encrypted:**
```
<EMAIL_1> → john@company.com
```

### Second Message (5 minutes later)

**User:**
```
Send the report to john@company.com
```

**Encrypted:**
```
<EMAIL_1> → john@company.com (same placeholder reused!)
```

**AI Response:**
```
I'll send the report to <EMAIL_1> as discussed earlier.
```

**User Sees:**
```
I'll send the report to john@company.com as discussed earlier.
```

This maintains conversation coherence - the AI can reference previous PII mentions naturally.

---

## Security Benefits

### 1. Zero External Exposure

```
Traditional System:
User → Clear Text PII → OpenAI API → Response
❌ PII exposed to external service
❌ Stored in OpenAI logs
❌ Compliance violations

AgentGate:
User → Encrypted → OpenAI API → Rehydrated → User
✅ Only placeholders leave infrastructure
✅ OpenAI never sees real PII
✅ Full HIPAA/GDPR compliance
```

### 2. Audit Trail

Every PII item is logged:

```json
{
  "entity_type": "ssn",
  "masked_value": "<SSN_1>",
  "timestamp": "2025-01-10T14:30:00Z",
  "context": "playground_session_abc123",
  "stored_in_vault": true
}
```

Note: **Original value is encrypted in vault**, not in audit logs.

### 3. Compliance

| Regulation | Requirement | How AgentGate Complies |
|------------|-------------|------------------------|
| HIPAA | PHI must not leave infrastructure | ✅ Only placeholders sent externally |
| GDPR | Right to be forgotten | ✅ Delete from vault = gone forever |
| PCI DSS | No card data in external logs | ✅ OpenAI never sees card numbers |
| SOC 2 | Audit trail of data access | ✅ Full logging of PII detection |

---

## Testing

### Test 1: Basic Rehydration

```bash
curl -X POST http://localhost:3000/api/playground/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "My SSN is 123-45-6789",
    "sessionId": "test_rehydrate",
    "middleware": { "piiProtection": true }
  }'
```

**Expected Response:**
- `whatWasSentToAI`: Contains `<SSN_1>`
- `response`: Contains `123-45-6789` (rehydrated)

### Test 2: Multiple PII Types

```bash
curl -X POST http://localhost:3000/api/playground/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Contact me: 555-123-4567 or john@email.com",
    "sessionId": "test_multiple",
    "middleware": { "piiProtection": true }
  }'
```

**Expected:**
- AI receives: `<PHONE_1>` and `<EMAIL_1>`
- User sees: `555-123-4567` and `john@email.com`

### Test 3: Persistent Placeholders

```bash
# First message
curl -X POST http://localhost:3000/api/playground/chat \
  -d '{"message": "My email is john@test.com", "sessionId": "test_persist"}'

# Second message (same session)
curl -X POST http://localhost:3000/api/playground/chat \
  -d '{"message": "Send report to john@test.com", "sessionId": "test_persist"}'
```

**Expected:**
Both messages use `<EMAIL_1>` for the same email address.

---

## Implementation Details

### Placeholder Format

```
<TYPE_COUNTER>
```

Examples:
- `<SSN_1>`, `<SSN_2>`, `<SSN_3>`
- `<EMAIL_1>`, `<EMAIL_2>`
- `<CREDIT_CARD_1>`, `<CREDIT_CARD_2>`

### Session Storage

```typescript
interface SessionState {
  piiMappings: Record<string, string>;  // <SSN_1> → "123-45-6789"
  piiCounters: Record<string, number>;   // SSN → 3
}
```

### Rehydration Algorithm

```typescript
function rehydrate(text: string, mappings: Record<string, string>): string {
  // Sort by length descending to avoid partial replacements
  const sorted = Object.keys(mappings).sort((a, b) => b.length - a.length);

  let result = text;
  for (const placeholder of sorted) {
    result = result.split(placeholder).join(mappings[placeholder]);
  }

  return result;
}
```

### Why Sort by Length?

Prevents partial replacement issues:

```
Mappings:
  <EMAIL_1> → "john@email.com"
  <EMAIL_12> → "jane@email.com"

Text: "Send to <EMAIL_12>"

Wrong order:
  Replace <EMAIL_1> → "Send to john@email.com2" ❌

Correct order (longest first):
  Replace <EMAIL_12> → "Send to jane@email.com" ✅
```

---

## Comparison: Before vs After

### Before (Simple Masking)

**User:** `"My SSN is 123-45-6789"`
**AI Receives:** `"My SSN is [SSN REDACTED]"`
**AI Response:** `"I see your SSN has been redacted for security"`
**User Sees:** `"I see your SSN has been redacted for security"`

**Problem:** AI knows data was redacted, conversation feels unnatural.

### After (Bidirectional Restoration)

**User:** `"My SSN is 123-45-6789"`
**AI Receives:** `"My SSN is <SSN_1>"`
**AI Response:** `"I've recorded your SSN <SSN_1> for the account"`
**User Sees:** `"I've recorded your SSN 123-45-6789 for the account"`

**Solution:** Natural conversation flow, seamless experience.

---

## Dashboard Integration

### View Mappings

1. **Playground** - See what was sent to AI vs what user sees
2. **PII Vault** - View all encrypted mappings
3. **Audit Logs** - Track when PII was detected/restored

### Verification

```bash
# Check PII vault
curl http://localhost:8000/api/pii/vault/stats | jq

# Check audit logs
curl http://localhost:8000/api/audit | jq '.logs[] | select(.event_type == "playground_chat")'
```

---

## Production Considerations

### Memory Management

Session state is in-memory. For production:

```python
# Use Redis for distributed sessions
import redis
r = redis.Redis()

# Store mappings with TTL
r.setex(f"pii:{session_id}", 3600, json.dumps(mappings))
```

### Scaling

Each session maintains its own mappings. With 1M active sessions:
- Memory: ~10KB per session = ~10GB
- Solution: Time-based expiration, LRU cache

### Security

Mappings are sensitive! Protect with:
- Encryption at rest (vault)
- Encryption in transit (TLS)
- Access controls (RBAC)
- Audit logging (all access)

---

## FAQ

**Q: Does the AI "know" the PII is masked?**
A: No! The AI sees placeholders like `<SSN_1>` as regular text. It treats them as identifiers and can reference them naturally.

**Q: What if the AI generates new PII?**
A: AI-generated PII (like fake SSNs) is NOT rehydrated - only original user PII is restored.

**Q: Can I see the raw placeholders?**
A: Yes! In the playground, click "See what AgentGate protected" to view the comparison.

**Q: What happens when session expires?**
A: Mappings are lost. New session = new placeholders. This is by design for security.

**Q: Can I use this in production?**
A: Yes! This is production-ready. Just add persistent storage (Redis/DB) for mappings.

---

## Summary

| Feature | Traditional Masking | AgentGate Encryption |
|---------|---------------------|---------------------|
| **User Input** | `"SSN: 123-45-6789"` | `"SSN: 123-45-6789"` |
| **AI Receives** | `"SSN: [REDACTED]"` | `"SSN: <SSN_1>"` |
| **AI Can Reference** | ❌ No context | ✅ Uses `<SSN_1>` |
| **User Sees** | `"[REDACTED]"` | `"123-45-6789"` |
| **Experience** | Feels broken | Seamless |
| **Compliance** | ✅ Compliant | ✅ Compliant |
| **Security** | ✅ PII protected | ✅ PII protected |

**Encrypted conversation = Best of both worlds**
