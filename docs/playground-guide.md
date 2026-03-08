# Playground Guide: Understanding PII Masking vs Security Blocking

## Overview

The AgentGate Playground demonstrates two distinct protection mechanisms:

1. **PII Tokenization** - Replaces sensitive data with synthetic tokens, sends tokenized text to AI
2. **Security Blocking** - Completely prevents malicious requests from reaching AI

This guide clarifies the difference and shows you how to test each feature.

> Contract note: playground redaction/rehydration runs on a scoped backend PII session.
> The backend requires `session_id` for `/api/pii/redact` and `/api/pii/restore`.

---

## How PII Masking Works

### The Flow

```
User Input → PII Detection → Masking → Send to AI → Response → Display
```

### Example: PII Masking in Action

**What You Type:**
```
My SSN is 123-45-6789 and email is john@company.com
```

**What Gets Sent to OpenAI:**
```
My SSN is <SSN_1> and email is <EMAIL_1>
```

**What the AI Sees:**
The AI receives synthetic tokens and responds appropriately:
```
I can help you! I recorded <SSN_1> and <EMAIL_1>.
```

**What You See:**
The AI's response is shown to you. The PII values are **never** sent to the external API.

### Testing PII Masking

1. Go to http://localhost:3000/playground
2. Enable "PII Protection" toggle (should be ON by default)
3. Type one of these test messages:

   - `"My SSN is 123-45-6789"`
   - `"Email me at test@example.com"`
   - `"My card number is 4111-1111-1111-1111"`

4. Click "See what AgentGate protected" to view the comparison:
   - **Without AgentGate**: Raw data sent to AI
   - **With AgentGate**: Masked data sent to AI

5. Verify in dashboards:
   - http://localhost:3000/pii - See stored PII in vault
   - http://localhost:3000/audit - See masking events logged

### Key Points

- ✅ **Message is sent to AI** (just the masked version)
- ✅ **AI responds normally** (doesn't know PII was removed)
- ✅ **User gets helpful response** (conversation continues)
- ✅ **PII never leaves your infrastructure** (compliance achieved)

---

## How Security Blocking Works

### The Flow

```
User Input → Threat Detection → BLOCK → No AI Call → Show Block Message
```

### Example: Security Blocking in Action

**What You Type:**
```
DROP TABLE users; DELETE FROM passwords;
```

**What Happens:**
The request is **blocked before reaching the AI**. No API call is made.

**What You See:**
```
⛔ Request Blocked

This request was intercepted by AgentGate before reaching the model.

Classification: SQL Injection
Risk: Data loss, system compromise

In production, this event would be logged to the audit trail and
surfaced on the Security Threats dashboard.
```

### Testing Security Blocking

1. Go to http://localhost:3000/playground
2. Enable "Security Validator" toggle (should be ON by default)
3. Type one of these malicious prompts:

   - `"DROP TABLE users;"`
   - `"rm -rf / --no-preserve-root"`
   - `"<script>alert('XSS')</script>"`

4. The message will be **blocked** - no AI response
5. Verify in dashboard:
   - http://localhost:3000/security/threats - See blocked threats

### Key Points

- ❌ **Message is NOT sent to AI** (completely blocked)
- ❌ **No API call made** (cost $0.00)
- ✅ **Attack prevented** (system protected)
- ✅ **Event logged** (audit trail maintained)

---

## Side-by-Side Comparison

| Feature | PII Masking | Security Blocking |
|---------|-------------|-------------------|
| **Purpose** | Protect sensitive data | Prevent malicious attacks |
| **Mechanism** | Replace with tokens | Block entirely |
| **AI Call** | ✅ Yes (masked version) | ❌ No (blocked) |
| **User Experience** | Normal conversation | Block message shown |
| **Cost** | Normal API cost | $0.00 (no call) |
| **Example** | SSN, email, credit card | SQL injection, XSS |

---

## Testing Both Features Together

### Test Scenario 1: PII + Normal Request

**Input:**
```
My email is john@company.com - can you help me write a resume?
```

**Expected:**
- ✅ PII tokenized: `My email is <EMAIL_1> - can you help me write a resume?`
- ✅ Sent to AI
- ✅ AI responds with resume help
- ✅ Email stored in PII vault
- ✅ Cost tracked (~$0.003)

### Test Scenario 2: PII + Security Threat

**Input:**
```
My SSN is 123-45-6789; DROP TABLE users;
```

**Expected:**
- ✅ PII detected: `123-45-6789`
- ✅ Threat detected: `DROP TABLE users`
- ❌ **Request blocked** (threat takes precedence)
- ❌ No AI call made
- ✅ PII stored in vault (even though blocked)
- ✅ Threat logged in security dashboard
- ✅ Cost: $0.00

### Test Scenario 3: Multiple Protections

**Input:**
```
Process payment for card 4111-1111-1111-1111 and email receipt to admin@company.com
```

**Expected:**
- ✅ 2 PII items detected: Card, Email
- ✅ Tokenized: `Process payment for card <CREDIT_CARD_1> and email receipt to <EMAIL_1>`
- ✅ Sent to AI
- ✅ AI provides payment processing response
- ✅ Both PII items stored in vault
- ✅ Cost tracked

---

## Verifying Dashboard Population

### Using CLI

```bash
# Run comprehensive verification
python scripts/verify_dashboard_data.py

# Quick playground test
./scripts/test_playground.sh
```

### Manual Verification

1. **Playground** (http://localhost:3000/playground)
   - Send 3-5 test messages
   - Include PII (SSN, email, card)
   - Try a security threat (SQL injection)

2. **Audit Logs** (http://localhost:3000/audit)
   - Should see all playground activity
   - Filter by "playground" event type
   - Check timestamps match your tests

3. **PII Vault** (http://localhost:3000/pii)
   - Should see masked PII entries
   - Verify types: SSN, EMAIL, CREDIT_CARD
   - Check "playground_session" context

4. **Cost Tracking** (http://localhost:3000/costs)
   - Should see API call costs
   - Model: gpt-4o-mini
   - Provider: openai
   - Source: playground

5. **Security Threats** (http://localhost:3000/security/threats)
   - Should see blocked threats
   - Types: SQL Injection, XSS, Shell Injection
   - Status: blocked

---

## Common Confusion Points

### "Why doesn't it send the real PII to AI?"

**This is the FEATURE!** The whole point is to prevent sensitive data from leaving your infrastructure. The AI works fine with masked data and provides helpful responses without ever seeing the real PII values.

### "I want to have a conversation with PII"

You can! The AI doesn't need to see the actual PII values to help you. For example:

**You:**
```
My email is john@company.com - help me write a professional email
```

**AI sees:**
```
My email is <EMAIL_1> - help me write a professional email
```

**AI responds:**
```
I'd be happy to help! Here's a professional email template:
Dear [Recipient],
...
```

The AI understands you're asking for email help and provides it, even though it doesn't see your actual email address.

### "Security blocking seems different"

Yes! Security blocking is **intentionally different** from PII masking:

- **PII Masking**: For data protection (conversation continues)
- **Security Blocking**: For system protection (conversation stops)

When you type SQL injection, we don't "mask" it and send it to the AI - we block the entire request to prevent potential attacks on your system.

---

## Testing Checklist

Use this checklist to verify everything works:

### PII Masking Tests

- [ ] Enter SSN (123-45-6789)
- [ ] Enter email (test@example.com)
- [ ] Enter credit card (4111-1111-1111-1111)
- [ ] Enter phone number (555-123-4567)
- [ ] Verify masked data sent to AI
- [ ] Verify AI responds normally
- [ ] Verify PII stored in vault
- [ ] Verify cost tracked

### Security Blocking Tests

- [ ] Try SQL injection (DROP TABLE users)
- [ ] Try shell injection (rm -rf /)
- [ ] Try XSS (<script>alert('xss')</script>)
- [ ] Verify request blocked
- [ ] Verify no AI call made
- [ ] Verify $0.00 cost
- [ ] Verify threat logged

### Dashboard Population Tests

- [ ] Audit logs show all playground activity
- [ ] PII vault shows masked data
- [ ] Costs show API spending
- [ ] Security threats show blocked attacks
- [ ] All timestamps are recent
- [ ] Session IDs match

---

## Troubleshooting

### "PII not being detected"

1. Check pattern format:
   - SSN: `123-45-6789` (dashes required)
   - Email: `user@domain.com`
   - Card: `4111-1111-1111-1111`

2. Verify PII Protection toggle is ON

3. Check server logs for Presidio errors

### "Dashboard not populating"

1. Verify API server running (port 8000)
2. Verify dashboard running (port 3000)
3. Check browser console for errors
4. Run `python scripts/verify_dashboard_data.py`

### "Costs not tracking"

1. Verify OPENAI_API_KEY is set
2. Check that messages weren't blocked (blocked = $0.00)
3. Look for cost logging errors in server logs

---

## Advanced: Behind the Scenes

### PII Tokenization Architecture

```python
# 1. Detect PII
pii_items = presidio.analyze(text)  # spaCy NLP

# 2. Redact to deterministic tokens within the active session
tokenized_text = redact_with_scoped_session(text, pii_items, session_id)

# 3. Store two-table mappings
# - pii_human_mappings (encrypted original value)
# - pii_ai_tokens (token -> human mapping reference)
store_scoped_mapping(session_id, "<SSN_1>", "123-45-6789")

# 4. Send to AI
response = openai.chat(tokenized_text)

# 5. Restore from scoped backend mapping before returning to user
return restore_with_scoped_session(response, session_id)
```

### Security Blocking Architecture

```python
# 1. Check patterns
for pattern in DANGEROUS_PATTERNS:
    if pattern.match(text):
        # 2. Block immediately
        raise SecurityError("SQL Injection blocked")

# 3. No AI call made
# 4. Log to audit trail
# 5. Return block message
```

---

## References

- [PII Vault API](/api#/PII)
- [Security Threats API](/api#/Security)
- [Cost Tracking API](/api#/Costs)
- [Audit Logs API](/api#/Audit)
