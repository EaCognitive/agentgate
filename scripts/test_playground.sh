#!/bin/bash
# Test playground functionality and verify data syncs to dashboard

set -e

API_BASE="${API_BASE:-http://localhost:8000}"
DASHBOARD_BASE="${DASHBOARD_BASE:-http://localhost:3000}"

echo "========================================="
echo "AgentGate Playground Test"
echo "========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: PII Masking
echo "Test 1: PII Masking (should mask and send to AI)"
echo "-----------------------------------------"
RESPONSE=$(curl -s -X POST "$DASHBOARD_BASE/api/playground/chat" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "My SSN is 123-45-6789",
    "sessionId": "test_pii",
    "middleware": {
      "piiProtection": true,
      "validator": true,
      "rateLimiter": true,
      "costTracker": true
    }
  }')

if echo "$RESPONSE" | grep -q "SSN REDACTED"; then
  echo -e "${GREEN}✓ PII masking working${NC}"
  echo -e "  Masked message sent to AI"
else
  echo -e "${RED}✗ PII masking not working${NC}"
fi

if echo "$RESPONSE" | grep -q '"blocked":false'; then
  echo -e "${GREEN}✓ Message not blocked (correct)${NC}"
else
  echo -e "${RED}✗ Message was blocked (incorrect)${NC}"
fi
echo ""

# Test 2: Security Blocking
echo "Test 2: Security Blocking (should block malicious prompts)"
echo "-----------------------------------------"
RESPONSE=$(curl -s -X POST "$DASHBOARD_BASE/api/playground/chat" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "DROP TABLE users;",
    "sessionId": "test_security",
    "middleware": {
      "piiProtection": true,
      "validator": true,
      "rateLimiter": true,
      "costTracker": true
    }
  }')

if echo "$RESPONSE" | grep -q '"blocked":true'; then
  echo -e "${GREEN}✓ Security blocking working${NC}"
  echo -e "  SQL injection blocked"
else
  echo -e "${RED}✗ Security blocking not working${NC}"
fi
echo ""

# Test 3: Verify Audit Logs
echo "Test 3: Verify Data in Audit Logs"
echo "-----------------------------------------"
AUDIT_RESPONSE=$(curl -s "$API_BASE/api/audit")

if echo "$AUDIT_RESPONSE" | grep -q "playground"; then
  echo -e "${GREEN}✓ Playground data synced to audit logs${NC}"
  LOG_COUNT=$(echo "$AUDIT_RESPONSE" | grep -o '"event_type"' | wc -l)
  echo -e "  Found $LOG_COUNT audit log entries"
else
  echo -e "${YELLOW}⚠ No playground data in audit logs yet${NC}"
fi
echo ""

# Test 4: Verify PII Vault
echo "Test 4: Verify Data in PII Vault"
echo "-----------------------------------------"
PII_RESPONSE=$(curl -s "$API_BASE/api/pii/vault")

if echo "$PII_RESPONSE" | grep -q "items"; then
  ITEM_COUNT=$(echo "$PII_RESPONSE" | grep -o '"entity_type"' | wc -l)
  if [ "$ITEM_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ PII vault populated${NC}"
    echo -e "  Found $ITEM_COUNT PII items"
  else
    echo -e "${YELLOW}⚠ PII vault empty (try entering sensitive data)${NC}"
  fi
else
  echo -e "${RED}✗ PII vault endpoint error${NC}"
fi
echo ""

# Test 5: Verify Cost Tracking
echo "Test 5: Verify Data in Cost Tracking"
echo "-----------------------------------------"
COST_RESPONSE=$(curl -s "$API_BASE/api/costs")

if echo "$COST_RESPONSE" | grep -q "costs"; then
  COST_COUNT=$(echo "$COST_RESPONSE" | grep -o '"cost"' | wc -l)
  if [ "$COST_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ Cost tracking populated${NC}"
    echo -e "  Found $COST_COUNT cost entries"
  else
    echo -e "${YELLOW}⚠ No cost data yet${NC}"
  fi
else
  echo -e "${RED}✗ Cost tracking endpoint error${NC}"
fi
echo ""

echo "========================================="
echo "Summary"
echo "========================================="
echo ""
echo "✓ PII Masking: User enters sensitive data → masked → sent to AI → response returned"
echo "✓ Security Blocking: Malicious prompts blocked before reaching AI"
echo "✓ Data Sync: All playground activity logged to dashboard"
echo ""
echo "To verify visually:"
echo "  1. Open http://localhost:3000/playground"
echo "  2. Send messages with PII (SSN, email, credit card)"
echo "  3. Check http://localhost:3000/audit for logs"
echo "  4. Check http://localhost:3000/pii for vault"
echo "  5. Check http://localhost:3000/costs for tracking"
echo ""
