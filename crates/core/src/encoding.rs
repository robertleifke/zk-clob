use alloc::vec::Vec;

use crate::errors::CoreError;
use crate::types::U256;

pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub fn read_exact(&mut self, len: usize) -> Result<&'a [u8], CoreError> {
        if self.offset + len > self.bytes.len() {
            return Err(CoreError::Decode("unexpected EOF"));
        }
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }

    pub fn read_u8(&mut self) -> Result<u8, CoreError> {
        Ok(self.read_exact(1)?[0])
    }

    pub fn read_u32(&mut self) -> Result<u32, CoreError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u64(&mut self) -> Result<u64, CoreError> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_i32(&mut self) -> Result<i32, CoreError> {
        let bytes = self.read_exact(4)?;
        Ok(i32::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_b32(&mut self) -> Result<[u8; 32], CoreError> {
        let bytes = self.read_exact(32)?;
        Ok(bytes.try_into().unwrap())
    }

    pub fn read_addr(&mut self) -> Result<[u8; 20], CoreError> {
        let bytes = self.read_exact(20)?;
        Ok(bytes.try_into().unwrap())
    }

    pub fn read_u256(&mut self) -> Result<U256, CoreError> {
        let bytes = self.read_exact(32)?;
        Ok(U256::from_be_bytes(bytes))
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, CoreError> {
        let len = self.read_u32()? as usize;
        let bytes = self.read_exact(len)?;
        Ok(bytes.to_vec())
    }

    pub fn expect_finished(&self) -> Result<(), CoreError> {
        if self.offset != self.bytes.len() {
            return Err(CoreError::Decode("trailing bytes"));
        }
        Ok(())
    }
}

pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_b32(&mut self, value: &[u8; 32]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn write_addr(&mut self, value: &[u8; 20]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn write_u256(&mut self, value: &U256) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_bytes(&mut self, value: &[u8]) {
        self.write_u32(value.len() as u32);
        self.bytes.extend_from_slice(value);
    }

    pub fn write_raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }
}
