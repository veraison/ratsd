# CMW Example Files

This directory contains example Conceptual Message Wrapper (CMW) files for testing and development purposes with RATSD.

## File Overview

- **`basic-mock-tsm.json`** - Simple mock TSM attester example with minimal required fields
- **`mock-tsm-with-privilege.json`** - Mock TSM attester with privilege level specified
- **`tsm-report-basic.json`** - Basic TSM report attester example
- **`multi-attester.json`** - Example showing both mock-tsm and tsm-report attesters in one CMW
- **`tsm-cbor-format.json`** - TSM report using CBOR content type instead of JSON

## CMW Structure

All CMW files follow this basic structure:

```json
{
  "__cmwc_t": "tag:github.com,2025:veraison/ratsd/cmw",
  "<attester-name>": [
    "<content-type>",
    <evidence-data>
  ]
}
```

## Available Attesters

### mock-tsm
- **Content Type**: `application/vnd.veraison.configfs-tsm+json`
- **Required Fields**: `auxblob`, `outblob`
- **Optional Fields**: `provider`, `privilege_level` (0-3)

### tsm-report  
- **Content Types**: 
  - `application/vnd.veraison.configfs-tsm+json` (JSON format)
  - `application/vnd.veraison.configfs-tsm+cbor` (CBOR format)
- **Required Fields**: `auxblob`, `outblob`
- **Optional Fields**: `provider`, `privilege_level` (0-3)

## Usage with RATSD

These files can be used for testing RATSD in mock mode or as reference for understanding the expected CMW format.

### Testing with curl

```bash
# Basic query (returns all available attesters)
curl -X POST http://localhost:8895/ratsd/chares \
  -H "Content-type: application/vnd.veraison.chares+json" \
  -d '{"nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA"}'

# Query with specific attester selection
curl -X POST http://localhost:8895/ratsd/chares \
  -H "Content-type: application/vnd.veraison.chares+json" \
  -d '{
    "nonce": "TUlEQk5IMjhpaW9pc2pQeXh4eHh4eHh4eHh4eHh4eHhNSURCTkgyOGlpb2lzalB5eHh4eHh4eHh4eHh4eHh4eA",
    "attester-selection": {
      "mock-tsm": {
        "privilege_level": "3"
      }
    }
  }'
```

## Notes

- All `auxblob` and `outblob` values are base64-encoded
- The examples use fake/placeholder data for demonstration purposes
- For CBOR format, the evidence data itself is base64-encoded CBOR
- Privilege levels range from 0 (lowest) to 3 (highest)
