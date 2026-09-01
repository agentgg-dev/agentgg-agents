---
slug: fcm-api-key
name: Firebase Cloud Messaging API Key Exposure
description: 'Hardcoded Firebase Cloud Messaging (FCM) Server API keys committed to source. Allows sending push notifications to any device registered with the Firebase project — enables push notification spam, phishing, or social engineering at scale.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)(?:fcm|firebase.{0,10}messaging|FCM_SERVER_KEY|FCM_API_KEY).{0,30}[=:"''\s]+[A-Za-z0-9_\-]{100,}'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: FCM server key near FCM/firebase keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:FCM_SERVER_KEY|FCM_API_KEY|firebase.{0,10}server.{0,10}key|cloud.messaging.server.key).{0,30}[=:"''\s]+([A-Za-z0-9_\-]{100,})'
      label: FCM server key assignment (100+ char value)
    - regex: 'AAAA[A-Za-z0-9_\-]{100,}:[A-Za-z0-9_\-]{100,}'
      label: FCM legacy server key format (starts with AAAA)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Firebase Cloud Messaging (FCM) server keys.

## Key formats

- **FCM Legacy Server Key**: starts with `AAAA` followed by a long alphanumeric string (typically 140-200+ chars). Found in Firebase Console > Project Settings > Cloud Messaging.
- **FCM v1 Service Account**: a Google service account JSON file — covered separately by the gcp-service-account agent.

## What a leaked FCM server key enables

- Send push notifications to any device registered with the Firebase project
- Push notification phishing: send fake security alerts, fake OTPs, fake prize notifications to all users
- Notification spam to all devices (DDoS-like impact on user experience)
- If the app displays notification content in alerts, potential for UI redressing attacks

## True positive criteria

Flag at high:
1. Legacy FCM server key (100+ char key starting with `AAAA`) in a server-side file
2. Variable named `FCM_SERVER_KEY`, `FCM_API_KEY`, `FIREBASE_MESSAGING_SERVER_KEY` with a long string literal

Note at medium:
3. FCM server key in a mobile app binary or config file — client-embedded server keys should be migrated to server-side

## What to ignore

- Firebase client config keys (`apiKey` in `firebase-config.js`) — these are public-facing and intended to be embedded in clients
- `messagingSenderId` — a numeric ID, not a server key
- `process.env.FCM_SERVER_KEY` — safe env reference
- The new FCM v1 HTTP API uses service accounts, not API keys

Report: the key format (legacy vs. v1), where it appears (server config, mobile app, CI/CD), and whether the Firebase project ID is visible nearby.
