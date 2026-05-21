# 8 Step Close

Hosted starter for `8stepclose.com`.

This is a Node web service for approved mortgage/CRM/property data intake from ARIVE, BNTouch, LoanOfficer.ai, myhomeIQ, CINC, and Zillow/Bridge.

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

Before production borrower or lead data flows in, add a persistent database.
