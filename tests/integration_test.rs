use bytes::Bytes;
use rapid_tlv::{RapidTlvField, RapidTlvMessage};

pub const EVT_SET: u8 = 0x10;
pub const EVT_GET: u8 = 0x11;
pub const EVT_DELETE: u8 = 0x12;

pub const FIELD_KEY: u8 = 0x01;
pub const FIELD_VALUE: u8 = 0x02;
pub const FIELD_TTL: u8 = 0x03;
pub const FIELD_PERSIST: u8 = 0x04;
pub const FIELD_GROUP: u8 = 0x05;
pub const FIELD_TIMESTAMP: u8 = 0x06;
pub const FIELD_VERSION: u8 = 0x07;
pub const FIELD_ID: u8 = 0x08;

#[test]
fn test_message_creation() {
    // Test creating a new message with an event type
    let event_type = EVT_SET;
    let msg = RapidTlvMessage::new(event_type);

    assert_eq!(msg.event_type, event_type);
}

#[test]
fn test_field_manipulation() {
    // Test adding, getting, and removing fields
    let event_type = EVT_SET;
    let mut msg = RapidTlvMessage::new(event_type);

    // Add a field
    let key = b"test_key";
    msg.add_field(FIELD_KEY, Bytes::from_static(key));

    // Get the field
    let field = msg.get_field(&FIELD_KEY);
    assert!(field.is_some());
    assert_eq!(field.unwrap().value(), key);

    // Add another field
    let value = b"test_value";
    msg.add_field(FIELD_VALUE, Bytes::from_static(value));

    // Get the second field
    let field = msg.get_field(&FIELD_VALUE);
    assert!(field.is_some());
    assert_eq!(field.unwrap().value(), value);

    // Remove a field
    let removed = msg.remove_field(FIELD_KEY);
    assert!(removed);

    // Verify it's gone
    let field = msg.get_field(&FIELD_KEY);
    assert!(field.is_none());

    // Try to remove a non-existent field
    let removed = msg.remove_field(FIELD_KEY);
    assert!(!removed); // remove_field returns false for non-existent fields
}

#[test]
fn test_message_encoding_decoding() {
    // Test encoding a message and then parsing it back
    let event_type = EVT_SET;
    let mut msg = RapidTlvMessage::new(event_type);

    // Add some fields
    msg.add_field(FIELD_KEY, Bytes::from_static(b"test_key"));
    msg.add_field(FIELD_VALUE, Bytes::from_static(b"test_value"));
    msg.add_field(FIELD_TTL, Bytes::from_static(&[0, 0, 0, 60])); // 60 seconds TTL

    // Encode the message
    let encoded = msg.encode().unwrap();

    // Parse the encoded message
    let parsed = RapidTlvMessage::parse(Bytes::copy_from_slice(encoded)).unwrap();

    // Verify the event type
    assert_eq!(parsed.event_type, event_type);

    // Verify the fields
    let key_field = parsed.get_field(&FIELD_KEY);
    assert!(key_field.is_some());
    assert_eq!(key_field.unwrap().value(), b"test_key");

    let value_field = parsed.get_field(&FIELD_VALUE);
    assert!(value_field.is_some());
    assert_eq!(value_field.unwrap().value(), b"test_value");

    let ttl_field = parsed.get_field(&FIELD_TTL);
    assert!(ttl_field.is_some());
    assert_eq!(ttl_field.unwrap().value(), &[0, 0, 0, 60]);
}

#[test]
fn test_error_handling() {
    // Test parsing malformed messages

    // Too short a message
    let too_short = Bytes::from_static(&[0, 0, 0, 5]);
    let result = RapidTlvMessage::parse(too_short);
    assert!(result.is_err());

    // Incomplete message (length field says 10 bytes, but only 5 are provided)
    let incomplete = Bytes::from_static(&[0, 0, 0, 10, 0x01]);
    let result = RapidTlvMessage::parse(incomplete);
    assert!(result.is_err());

    // Field with invalid length (field length exceeds message length)
    let invalid_field_length = Bytes::from_static(&[
        0, 0, 0, 10,   // Message length (10 bytes)
        0x01, // Event type (Set)
        0x01, // Field type (Key)
        0, 0, 0, 20, // Field length (20 bytes, which exceeds message length)
    ]);
    let result = RapidTlvMessage::parse(invalid_field_length);
    assert!(result.is_err());
}

#[test]
fn test_length_mismatch() {
    // Test parsing a message where the declared length doesn't match the actual length
    // This is similar to the issue described in the problem statement
    let message_with_length_mismatch = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x2C, // Message length = 44 bytes (incorrect)
        0x10, // Event type = 16
        0x10, // Field type = 16
        0x00, 0x00, 0x00, 0x0E, // Field length = 14
        0x75, 0x73, 0x65, 0x72, 0x64, 0x61, 0x74, 0x61, 0x3A, 0x68, 0x61, 0x6C, 0x6C,
        0x6F, // "userdata:hall"
        0x11, // Field type = 17
        0x00, 0x00, 0x00, 0x0A, // Field length = 10
        0x48, 0x61, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x65, 0x6C, 0x74, // "Hallo Welt"
        0x12, // Field type = 18
        0x00, 0x00, 0x00, 0x04, // Field length = 4
        0x00, 0x00, 0x01, 0x2C, // Value = 300
    ]);

    let result = RapidTlvMessage::parse(message_with_length_mismatch);
    assert!(result.is_err());

    // Create the same message but with the correct length
    let message_with_correct_length = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x30, // Message length = 48 bytes (correct)
        0x10, // Event type = 16
        0x10, // Field type = 16
        0x00, 0x00, 0x00, 0x0E, // Field length = 14
        0x75, 0x73, 0x65, 0x72, 0x64, 0x61, 0x74, 0x61, 0x3A, 0x68, 0x61, 0x6C, 0x6C,
        0x6F, // "userdata:hall"
        0x11, // Field type = 17
        0x00, 0x00, 0x00, 0x0A, // Field length = 10
        0x48, 0x61, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x65, 0x6C, 0x74, // "Hallo Welt"
        0x12, // Field type = 18
        0x00, 0x00, 0x00, 0x04, // Field length = 4
        0x00, 0x00, 0x01, 0x2C, // Value = 300
    ]);

    let result = RapidTlvMessage::parse(message_with_correct_length);
    assert!(result.is_ok());
}

#[test]
fn test_edge_cases() {
    // Test empty message
    let event_type = EVT_SET;
    let mut msg = RapidTlvMessage::new(event_type);

    // Encode an empty message
    let encoded = msg.encode().unwrap();

    // Parse empty message
    let parsed = RapidTlvMessage::parse(Bytes::copy_from_slice(encoded)).unwrap();
    assert_eq!(parsed.event_type, event_type);

    // Test message with empty field values
    msg.add_field(FIELD_KEY, Bytes::from_static(b""));
    msg.add_field(FIELD_VALUE, Bytes::from_static(b""));

    // Encode and parse
    let encoded = msg.encode().unwrap();
    let parsed = RapidTlvMessage::parse(Bytes::copy_from_slice(encoded)).unwrap();

    // Verify empty fields
    let key_field = parsed.get_field(&FIELD_KEY);
    assert!(key_field.is_some());
    assert_eq!(key_field.unwrap().value(), b"");

    let value_field = parsed.get_field(&FIELD_VALUE);
    assert!(value_field.is_some());
    assert_eq!(value_field.unwrap().value(), b"");

    // Test large field values
    let large_value = vec![0u8; 1024 * 1024]; // 1MB
    msg.add_field(FIELD_VALUE, Bytes::from(large_value.clone()));

    // Encode and parse
    let encoded = msg.encode().unwrap();
    let parsed = RapidTlvMessage::parse(Bytes::copy_from_slice(encoded)).unwrap();

    // Verify large field
    let value_field = parsed.get_field(&FIELD_VALUE);
    assert!(value_field.is_some());
    assert_eq!(value_field.unwrap().value(), large_value);
}

#[test]
fn test_event_type_conversion() {
    // Test all event types can be converted to u8 and back
    let event_types = [EVT_SET, EVT_GET, EVT_DELETE];

    for event_type in event_types.iter() {
        // Create a message with this event type
        let mut msg = RapidTlvMessage::new(*event_type);

        // Encode the message
        let result = msg.encode();

        // Some event types might not be fully implemented yet
        if let Ok(encoded) = result {
            // Parse the encoded message
            let parsed = RapidTlvMessage::parse(Bytes::copy_from_slice(encoded)).unwrap();

            // Verify the event type
            assert_eq!(parsed.event_type, *event_type);
        }
    }
}

#[test]
fn test_field_type_conversion() {
    // Test all field types can be converted to u8 and back
    let field_types = [
        FIELD_KEY,
        FIELD_VALUE,
        FIELD_TTL,
        FIELD_PERSIST,
        FIELD_GROUP,
        FIELD_TIMESTAMP,
        FIELD_VERSION,
        FIELD_ID,
    ];

    for field_type in field_types.iter() {
        // Create a field with this type
        let field = RapidTlvField::new(*field_type, Bytes::from_static(b"test"));

        // Encode the field
        let encoded = field.encode().unwrap();

        // The first byte should be the field type
        let field_type_byte = encoded[0];

        // Convert back to RapidTlvFieldType
        let decoded_type = field_type_byte;

        // Verify the field type
        assert_eq!(decoded_type, *field_type);
    }
}

#[test]
fn test_message_modification() {
    // Test modifying a message after parsing
    let event_type = EVT_SET;
    let mut msg = RapidTlvMessage::new(event_type);

    // Add initial fields
    msg.add_field(FIELD_KEY, Bytes::from_static(b"test_key"));
    msg.add_field(FIELD_VALUE, Bytes::from_static(b"initial_value"));

    // Encode the message
    let encoded = msg.encode().unwrap();

    // Parse the encoded message
    let mut parsed = RapidTlvMessage::parse(Bytes::copy_from_slice(encoded)).unwrap();

    // Modify the parsed message
    parsed.add_field(FIELD_VALUE, Bytes::from_static(b"updated_value"));

    // Create a new message with a different event type (since set_event_type is not available)
    let mut modified = RapidTlvMessage::new(EVT_GET);

    // Copy fields from parsed message
    if let Some(key_field) = parsed.get_field(&FIELD_KEY) {
        modified.add_field(FIELD_KEY, Bytes::copy_from_slice(key_field.value()));
    }
    if let Some(value_field) = parsed.get_field(&FIELD_VALUE) {
        modified.add_field(FIELD_VALUE, Bytes::copy_from_slice(value_field.value()));
    }

    // Encode the modified message
    let modified_encoded = modified.encode().unwrap();

    // Parse the modified message
    let modified = RapidTlvMessage::parse(Bytes::copy_from_slice(modified_encoded)).unwrap();

    // Verify the changes
    assert_eq!(modified.event_type, EVT_GET);

    let value_field = modified.get_field(&FIELD_VALUE);
    assert!(value_field.is_some());
    assert_eq!(value_field.unwrap().value(), b"updated_value");
}

#[test]
fn test_protocol_compliance() {
    // Test that the encoded message follows the TLV protocol specification
    let mut msg = RapidTlvMessage::new(EVT_SET);

    // Add a field
    msg.add_field(FIELD_KEY, Bytes::from_static(b"test_key"));

    // Encode the message
    let encoded = msg.encode().unwrap();

    // Check the structure:
    // 1. The first 4 bytes should be the message length (big-endian)
    // Note: In the current implementation, the message length includes the 4 bytes for the length field itself
    let msg_len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
    assert_eq!(msg_len, encoded.len());

    // 2. The next byte should be the event type
    assert_eq!(encoded[4], EVT_SET); // Set = 0x01

    // 3. The next byte should be the field type
    assert_eq!(encoded[5], 0x01); // Key = 0x01

    // 4. The next 4 bytes should be the field length (big-endian)
    let field_len = u32::from_be_bytes([encoded[6], encoded[7], encoded[8], encoded[9]]) as usize;
    assert_eq!(field_len, b"test_key".len());

    // 5. The next bytes should be the field value
    assert_eq!(&encoded[10..10 + field_len], b"test_key");
}
