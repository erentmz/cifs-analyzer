# CIFS / NetBIOS Browser Analyzer (Zeek + Spicy)

A custom CIFS / NetBIOS Browser protocol analyzer developed using Zeek and Spicy DSL.

This project parses CIFS mailslot messages, decodes protocol-specific structures, converts legacy encodings (CP437), and generates structured Zeek logs for network analysis.

---

## Objectives

- Parse CIFS NetBIOS Browser mailslot packets
- Implement opcode-based message classification
- Decode ServerType bitmask flags (32-bit LE)
- Convert CP437 encoded NetBIOS names to UTF-8
- Sanitize NetBIOS suffix and padding
- Aggregate and log structured protocol metadata

---

## Architecture

1. **Spicy Layer**
   - Custom CIFS parser (`cifs.spicy`)
   - Opcode enum mapping
   - Structured message parsing
   - Event forwarding via `.evt`

2. **Zeek Layer**
   - Event handling (`cifs.zeek`)
   - ServerType bitmask decoding
   - CP437 → UTF-8 conversion
   - NetBIOS name sanitization
   - Aggregation logic
   - Structured logging

3. **Utility Modules**
   - `cp437.zeek` → Legacy encoding conversion
   - `svtype.zeek` → 32-bit ServerType flag decoder

---

## Implemented CIFS Message Types

- Host Announcement
- Local Master Announcement
- Domain/Workgroup Announcement
- Request Announcement
- Query For PDC

Each message is parsed, normalized, and logged with structured metadata.

---

## Technical Highlights

- Custom CP437 character mapping table
- NetBIOS suffix stripping and padding cleanup
- Little-endian 32-bit bitmask reconstruction
- Flag-to-role decoding (Workstation, Domain Controller, Master Browser, etc.)
- Event-driven Zeek integration
- Aggregated logging pipeline

---

## Project Structure
- spicy/ - CIFS protocol parser (.spicy, .evt)
- zeek/ - Zeek scripts (event handlers, logging)
- pcaps/ - Sample test traffic
- logs/ - Generated runtime logs
- tests/ - Run script

---

## Usage

Run with helper script:

```bash
./tests/run-zeek.sh

Or manually:

zeek -Cr pcaps/cifs.pcap zeek

Logs will be generated in the logs/ directory.
```
## Authors
- Ali Eren Temiz
- Melih Kemal Sel
