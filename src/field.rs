use crate::error::{Error, ErrorCode};
use bytes::{BufMut, Bytes};

pub type FieldType = u8;

#[derive(Debug,Clone)]
pub struct Field {
    field_type: FieldType,
    value: Bytes,
}

impl Field {
    pub fn new(field_type: FieldType, value: Bytes) -> Field {
        Field { field_type, value }
    }

    pub fn field_type(&self) -> &FieldType {
        &self.field_type
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
    
    pub fn update_value(&mut self, value: Bytes) {
        self.value = value;
    }

    pub fn len(&self) -> usize {
        self.value.len() + 1 + 4 // 1 byte for a field type, 4 bytes for length
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        let mut buffer = bytes::BytesMut::with_capacity(1 + 4 + self.value.len());

        // write a field type
        buffer.put_u8(self.field_type);

        // write length (big endian)
        buffer.put_u32(self.value.len() as u32);

        // write value
        buffer.put_slice(&self.value);

        Ok(buffer.freeze())
    }
}
