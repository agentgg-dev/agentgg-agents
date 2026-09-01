---
slug: adafruit-io-key
name: Adafruit IO API Key Exposure
description: 'Hardcoded Adafruit IO API keys (aio_ prefix, 28 alphanumeric chars) in source or config. Grants full read/write access to all IoT feeds, dashboards, and MQTT topics for the account.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\baio_[A-Za-z0-9]{28}\b'
      label: Adafruit IO API key (aio_)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Adafruit IO API keys. Adafruit IO is an IoT cloud platform — the API key controls all feeds, dashboards, and real-time MQTT data streams for the account.

## Token format

```
aio_<28 alphanumeric characters>
```

Keys are created in the Adafruit IO dashboard under "My Key."

## What a leaked key enables

- Read and write all IoT feed data (sensor readings, device state, historical data)
- Control any connected device that subscribes to a feed via MQTT
- Delete feeds and dashboards
- Access account profile information

## True positive criteria

Flag when ALL hold:
1. Value matches `aio_[A-Za-z0-9]{28}` exactly
2. It is a string literal, not an env var reference (`os.environ['AIO_KEY']`, `process.env.AIO_KEY`)
3. Not a placeholder (`aio_yourkeyhere`, all same characters)

## Examples

True positives:
```python
AIO_KEY = 'aio_<your_key_here>'
client = MQTTClient(AIO_USERNAME, AIO_KEY)
```

False positives to skip:
```python
AIO_KEY = os.environ['ADAFRUIT_IO_KEY']
```

Report whether the key appears in IoT firmware, a server-side script, or a frontend file.
