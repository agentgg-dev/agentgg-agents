---
slug: azure-connection-string
name: Azure Connection String Exposure
description: 'Hardcoded Azure Storage, Event Hub, Service Bus, or Cosmos DB connection strings containing AccountKey or SharedAccessKey in source or config. These keys grant full data-plane access to the Azure resource.'
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
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '(?i)AccountKey\s*=[^;]{10,}'
      label: Azure AccountKey in connection string
    - regex: '(?i)SharedAccessKey\s*=[^;]{10,}'
      label: Azure SharedAccessKey in connection string
    - regex: '(?i)SharedAccessSignature\s*=\s*sv='
      label: Azure SAS token
    - regex: '(?i)DefaultEndpointsProtocol=https?;AccountName='
      label: Azure Storage connection string prefix
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Azure connection strings. Azure connection strings embed account keys or shared access signatures that grant direct data-plane access to cloud resources.

## Connection string shapes

**Azure Storage (Blob, Queue, Table, File):**
```
DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=<base64-key>;EndpointSuffix=core.windows.net
```
The `AccountKey` is a 64-byte base64 value that gives full control of all containers and tables in the account.

**Azure Event Hub / Service Bus:**
```
Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=<base64-key>
```
`SharedAccessKey` grants send/listen/manage rights depending on the policy.

**Azure Cosmos DB:**
```
AccountEndpoint=https://myaccount.documents.azure.com:443/;AccountKey=<base64-key>
```

**Azure SAS tokens:**
```
https://mystorageaccount.blob.core.windows.net/container?sv=2021-06-08&ss=b&srt=co&sp=rwdlacuptfx&...&sig=<signature>
```
SAS tokens are time-limited but can grant broad permissions if misconfigured.

## Cross-file analysis

When a connection string is found:
1. Identify the resource type (Storage, Event Hub, Service Bus, Cosmos) and the account/namespace name
2. Look at how the code uses it — read-only, write, or manage — to assess blast radius
3. Check whether the key name is `RootManageSharedAccessKey` (maximum privileges) or a scoped policy

## True positive criteria

Flag when ALL hold:
1. A connection string with `AccountKey=`, `SharedAccessKey=`, or `AccountKey` containing a long base64 value (not a placeholder)
2. The value is a string literal in source or committed config — not read from `process.env`, `os.environ`, or a key vault reference like `@Microsoft.KeyVault(...)`
3. The key is not obviously fake: not `AAAA...AAAA==`, not `<your-account-key>`, not `base64encodedkey==`

## What to ignore

- Connection strings where the key portion is an environment variable reference: `AccountKey=${AZURE_STORAGE_KEY}`, `AccountKey=#{AzureStorageKey}#`
- Azure Key Vault references: `@Microsoft.KeyVault(SecretUri=...)`
- Managed identity configurations (no key in the string)
- Local development emulator strings: `UseDevelopmentStorage=true` or `AccountName=devstoreaccount1;AccountKey=Eby8vdM02...` (the well-known Azurite emulator key)

## The Azurite emulator key

The well-known local emulator key is:
`Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==`

This is public, not a real secret — skip it.

## Examples

True positives:
```
DefaultEndpointsProtocol=https;AccountName=prodfiles;AccountKey=abc123...base64==;EndpointSuffix=core.windows.net
```
```yaml
# In appsettings.json
"EventHubConnectionString": "Endpoint=sb://prod-events.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=xK7m...=="
```

False positives to skip:
```
DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=${AZURE_STORAGE_KEY};EndpointSuffix=core.windows.net
```
```
UseDevelopmentStorage=true
```

Report the resource type (Storage/Event Hub/Service Bus/Cosmos), the account name, the permission level implied by the key policy name, and whether the string appears in a production config vs a local dev setting.
