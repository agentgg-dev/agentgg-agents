---
slug: confluent-credentials
name: Confluent / Kafka Cloud Credentials Exposure
description: 'Hardcoded Confluent Cloud API keys (access token + secret) committed to source. Grants access to Kafka clusters, Schema Registry, and ksqlDB — enables reading message streams, producing malicious messages, or modifying cluster configuration.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)confluent.{0,30}[=:"''\s]+[a-z0-9]{16}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Confluent Cloud API key near confluent keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9]{16})(?:[''"\n\r\s`;]|$)'
      label: Confluent 16-char API key/token
    - regex: '(?i)(?:CONFLUENT_API_KEY|CONFLUENT_SECRET|KAFKA_API_KEY|KAFKA_API_SECRET|sasl\.username|sasl\.password)'
      label: Confluent/Kafka SASL credential variable name
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Confluent Cloud API credentials.

## Credential types

Confluent Cloud uses paired credentials: an API key (16-char uppercase alphanumeric) and API secret (64-char alphanumeric). In Kafka client config files:

```properties
sasl.username=<API_KEY>
sasl.password=<API_SECRET>
bootstrap.servers=pkc-XXXXX.region.provider.confluent.cloud:9092
```

## What leaked credentials enable

- Read all messages from Kafka topics the key has access to — may include PII, financial transactions, application events
- Produce messages to Kafka topics — inject malicious events into data pipelines
- Access Schema Registry to modify Avro/Protobuf schemas — can break consumers
- Access ksqlDB to run streaming queries on Kafka data

## True positive criteria

Flag at critical:
1. `sasl.username` and `sasl.password` both set to non-placeholder values in a Kafka properties file
2. `CONFLUENT_API_KEY` and `CONFLUENT_API_SECRET` both present as string literals

Flag at high:
3. `bootstrap.servers` pointing to `*.confluent.cloud` with SASL credentials nearby

## What to ignore

- `sasl.username=${CONFLUENT_API_KEY}` — environment variable substitution
- Placeholder values like `REPLACE_WITH_API_KEY`

Report: the Kafka bootstrap servers hostname (reveals which Confluent cluster), and whether both the key and secret are present (both needed for authentication).
