# EventRelay TLV Protocol Documentation

This document describes the Type-Length-Value (TLV) protocol used by the EventRelay system. The TLV protocol is a binary protocol that allows for efficient encoding and decoding of messages with variable-length fields.

## Table of Contents

1. [Protocol Overview](#protocol-overview)
2. [Message Structure](#message-structure)
3. [Binary Format Details](#binary-format-details)

## Protocol Overview

The EventRelay TLV protocol is designed for efficient message passing between clients and servers in a distributed event system. It uses a binary format where each message consists of:

- A header containing the message length and event type
- A variable number of fields, each with its own type, length, and value

This approach allows for:
- Compact message representation
- Efficient parsing and generation
- Extensibility through new field types
- Zero-copy operations where possible

## Message Structure

Each TLV message has the following structure:

```
+----------------+----------------+----------------+
| Message Length | Event Type     | Fields         |
| (4 bytes)      | (1 byte)       | (variable)     |
+----------------+----------------+----------------+
```

### Message Length (4 bytes)
- 32-bit unsigned integer in big-endian format
- Represents the total length of the message in bytes, including the length field itself

### Event Type (1 byte)
- 8-bit unsigned integer

### Fields (variable)
Each field has the following structure:

```
+----------------+----------------+----------------+
| Field Type     | Field Length   | Field Value    |
| (1 byte)       | (4 bytes)      | (variable)     |
+----------------+----------------+----------------+
```

- **Field Type (1 byte)**: 8-bit unsigned integer identifying the type of field
- **Field Length (4 bytes)**: 32-bit unsigned integer in big-endian format representing the length of the field value in bytes
- **Field Value (variable)**: The actual data of the field

## Binary Format Details

### Endianness
All multibyte integers in the protocol are encoded in big-endian format (network byte order).
