use crate::error::{Error, ErrorCode};
use crate::field::{Field, FieldType};
use bytes::{BufMut, Bytes, BytesMut};

pub type EventType = u8;

#[derive(Debug, Clone)]
pub struct Message {
    raw_data: Bytes,

    pub event_type: EventType,
    fields: [Option<Field>; 256],
}

impl Message {
    pub fn new(event_type: EventType) -> Message {
        Message {
            raw_data: Bytes::new(),
            event_type,
            fields: [(); 256].map(|_| None),
        }
    }

    pub fn parse(raw: Bytes) -> Result<Message, Error> {
        if raw.len() < 5 {
            return Err(Error::new(
                ErrorCode::Malformed,
                "Not enough data for TLV header".into(),
            ));
        }

        let mut msg = Message {
            raw_data: Bytes::new(),
            event_type: raw[4],
            fields: std::array::from_fn(|_| None),
        };

        let mut offset = 5;

        while offset + 5 <= raw.len() {
            let field_typ = raw[offset];
            offset += 1;

            let length = u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + length > raw.len() {
                return Err(Error::new(
                    ErrorCode::Malformed,
                    "Not enough data for field value".into(),
                ));
            }

            let value = raw.slice(offset..offset + length);
            offset += length;

            msg.fields[field_typ as usize] = Some(Field::new(field_typ, value));
        }

        msg.raw_data = raw;

        Ok(msg)
    }

    pub fn get_field(&self, field_type: &FieldType) -> Option<&Field> {
        self.fields[*field_type as usize].as_ref()
    }

    pub fn add_field(&mut self, field_type: FieldType, value: Bytes) {
        self.fields[field_type as usize] = Option::from(Field::new(field_type, value));

        self.raw_data = Bytes::new();
    }

    pub fn with_field(mut self, field_type: FieldType, value: Bytes) -> Self {
        self.fields[field_type as usize] = Option::from(Field::new(field_type, value));

        self.raw_data = Bytes::new();
        self
    }

    pub fn remove_field(&mut self, field_type: FieldType) -> bool {
        self.fields[field_type as usize] = None;

        self.raw_data = Bytes::new();
        true
    }

    pub fn encode(&mut self) -> Result<&[u8], Error> {
        // Only rebuild raw_data if it has been modified or is empty
        if self.raw_data.is_empty() {
            let mut buffer_len = 5; //  length 4 bytes + event_type 1 byte

            // berechne Länge aller Felder
            for field in self.fields.iter().flatten() {
                buffer_len += field.len();
            }

            // erstelle Buffer mit der richtigen Länge
            let mut buffer = BytesMut::with_capacity(buffer_len);

            // 1. schreibe Gesamtlänge (ink. event_type + Felder)
            buffer.put_u32(buffer_len as u32);

            // 2. schreibe EventType
            buffer.put_u8(self.event_type);

            // 3. Schreibe alle Felder direkt in Buffer
            for field in self.fields.iter().flatten() {
                buffer.put(field.encode()?)
            }

            self.raw_data = buffer.freeze(); // Bytes ist nun immutable view
        }

        Ok(self.raw_data.as_ref())
    }
}
