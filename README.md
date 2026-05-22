# 8 Step Close

Hosted starter for `8stepclose.com`.

This is a Node web service for approved mortgage/CRM/property data intake from ARIVE, BNTouch, LoanOfficer.ai, myhomeIQ, CINC, and Zillow.

Run locally:

```bash
npm start
```

Health check:

```text
/api/health
```

Dashboard login is controlled with Render environment variables:

```text
LOGIN_USERNAME
LOGIN_PASSWORD
SESSION_SECRET
ARIVE_WEBHOOK_TOKEN
MYHOMEIQ_WEBHOOK_TOKEN
ZILLOW_WEBHOOK_TOKEN
```

Production webhook endpoints:

```text
/api/webhooks/arive
/api/webhooks/bntouch
/api/webhooks/loanofficerai
/api/webhooks/myhomeiq
/api/webhooks/cinc
/api/webhooks/zillow
```

ARIVE Zapier loan-cycle updates should use:

```text
/api/webhooks/arive?token=YOUR_ARIVE_WEBHOOK_TOKEN
```

Zillow lender contacts should use:

```text
/api/webhooks/zillow?token=YOUR_ZILLOW_WEBHOOK_TOKEN
```

myhomeIQ Zapier flows should use:

```text
/api/webhooks/myhomeiq?token=YOUR_MYHOMEIQ_WEBHOOK_TOKEN
```

Before production borrower or lead data flows in, add a persistent database.
