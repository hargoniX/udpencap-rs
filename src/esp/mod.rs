mod encryption;
mod padding;

use crate::esp::encryption::Cipher;
use crate::esp::padding::{pad, pad_len};
use crate::util::{Error, Result};
use generic_array::GenericArray;
use typenum::Unsigned;

use byteorder::{ByteOrder, NetworkEndian};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repr {
    pub spi: u32,
    pub sequence_number: u32,
    pub next_header: u8,
}

mod field {
    #![allow(non_snake_case)]
    use crate::esp::encryption::Cipher;
    use typenum::Unsigned;

    pub type Field = core::ops::Range<usize>;

    pub const SPI: Field = 0..4;
    pub const SEQUENCE_NUMBER: Field = 4..8;
    pub const ASSOCIATED_DATA: Field = SPI.start..SEQUENCE_NUMBER.end;

    pub fn IV<C>() -> Field
    where
        C: Cipher,
    {
        SEQUENCE_NUMBER.end..(SEQUENCE_NUMBER.end + C::IvSize::to_usize())
    }

    pub fn NEXT_HEADER<C>(packet_len: usize) -> usize
    where
        C: Cipher,
    {
        packet_len - C::TagSize::to_usize() - 1
    }

    pub fn PAD_LENGTH<C>(packet_len: usize) -> usize
    where
        C: Cipher,
    {
        packet_len - C::TagSize::to_usize() - 2
    }

    pub fn PAYLOAD<C>(packet_len: usize, pad_len: usize) -> Field
    where
        C: Cipher,
    {
        IV::<C>().end..(PAD_LENGTH::<C>(packet_len) - pad_len)
    }

    pub fn CIPHER_TEXT<C>(packet_len: usize) -> Field
    where
        C: Cipher,
    {
        IV::<C>().end..(packet_len - C::TagSize::to_usize())
    }

    pub fn ICV<C>(packet_len: usize) -> Field
    where
        C: Cipher,
    {
        (NEXT_HEADER::<C>(packet_len) + 1)..packet_len
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> EncryptedPacket<T> {
    pub fn new_unchecked(buffer: T) -> EncryptedPacket<T> {
        EncryptedPacket { buffer }
    }

    pub fn new_checked<C>(buffer: T) -> Result<EncryptedPacket<T>>
    where
        C: Cipher,
    {
        let packet = EncryptedPacket::new_unchecked(buffer);
        // TODO: Checks
        Ok(packet)
    }

    pub fn spi(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::SPI])
    }

    pub fn sequence_number(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::SEQUENCE_NUMBER])
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EncryptedPacket<T> {
    /// Splits the packet into 4 slices/GenericArray's:
    /// 1. The associated data
    /// 2. The IV
    /// 3. The ciphertext
    /// 4. The ICV
    pub fn split_cipher_material_mut<C>(
        &mut self,
    ) -> (
        &[u8],
        &GenericArray<u8, C::IvSize>,
        &mut [u8],
        &GenericArray<u8, C::TagSize>,
    )
    where
        C: Cipher,
    {
        let data = self.buffer.as_mut();
        let len = data.len();
        let (data, icv) = data.split_at_mut(field::CIPHER_TEXT::<C>(len).end);
        let (head, payload) = data.split_at_mut(field::CIPHER_TEXT::<C>(len).start);
        let (associated, iv) = head.split_at(field::ASSOCIATED_DATA.end);
        let iv = GenericArray::from_slice(iv);
        let icv = GenericArray::from_slice(icv);

        (associated, iv, payload, icv)
    }
}

#[derive(Debug, Clone)]
pub struct DecryptedPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> DecryptedPacket<T> {
    pub fn new_unchecked(buffer: T) -> DecryptedPacket<T> {
        DecryptedPacket { buffer }
    }

    pub fn new_checked<C>(buffer: T) -> Result<DecryptedPacket<T>>
    where
        C: Cipher,
    {
        let packet = DecryptedPacket::new_unchecked(buffer);
        // TODO: Checks
        Ok(packet)
    }

    pub fn spi(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::SPI])
    }

    pub fn sequence_number(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::SEQUENCE_NUMBER])
    }

    pub fn payload<C>(&self, _c: &C) -> &[u8]
    where
        C: Cipher,
    {
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD::<C>(data.len(), self.pad_len::<C>() as usize)]
    }

    pub fn pad_len<C>(&self) -> u8
    where
        C: Cipher,
    {
        let data = self.buffer.as_ref();
        let len = data.len();
        data[field::PAD_LENGTH::<C>(len)]
    }

    pub fn next_header<C>(&self) -> u8
    where
        C: Cipher,
    {
        let data = self.buffer.as_ref();
        let len = data.len();
        data[field::NEXT_HEADER::<C>(len)]
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> DecryptedPacket<T> {
    pub fn set_spi(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::SPI], value);
    }

    pub fn set_sequence_number(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::SEQUENCE_NUMBER], value);
    }

    pub fn set_iv<C>(&mut self, value: &GenericArray<u8, C::IvSize>)
    where
        C: Cipher,
    {
        let data = self.buffer.as_mut();
        data[field::IV::<C>()].copy_from_slice(value);
    }

    pub fn ciphertext_mut<C>(&mut self) -> &mut [u8]
    where
        C: Cipher,
    {
        let data = self.buffer.as_mut();
        let len = data.len();
        &mut data[field::CIPHER_TEXT::<C>(len)]
    }

    pub fn payload_mut<C>(&mut self) -> &mut [u8]
    where
        C: Cipher,
    {
        let pad_len = self.pad_len::<C>() as usize;
        let data = self.buffer.as_mut();
        let len = data.len();
        &mut data[field::PAYLOAD::<C>(len, pad_len)]
    }

    /// Splits the packet into 4 slices/GenericArray's:
    /// 1. The associated data
    /// 2. The IV
    /// 3. The ciphertext
    /// 4. The ICV
    pub fn split_cipher_material_mut<C>(
        &mut self,
    ) -> (
        &[u8],
        &GenericArray<u8, C::IvSize>,
        &mut [u8],
        &GenericArray<u8, C::TagSize>,
    )
    where
        C: Cipher,
    {
        let data = self.buffer.as_mut();
        let len = data.len();
        let (data, icv) = data.split_at_mut(field::CIPHER_TEXT::<C>(len).end);
        let (head, payload) = data.split_at_mut(field::CIPHER_TEXT::<C>(len).start);
        let (associated, iv) = head.split_at(field::ASSOCIATED_DATA.end);
        let iv = GenericArray::from_slice(iv);
        let icv = GenericArray::from_slice(icv);

        (associated, iv, payload, icv)
    }

    pub fn set_pad_len<C>(&mut self, value: u8)
    where
        C: Cipher,
    {
        let data = self.buffer.as_mut();
        let len = data.len();
        data[field::PAD_LENGTH::<C>(len)] = value;
    }

    pub fn set_next_header<C>(&mut self, value: u8)
    where
        C: Cipher,
    {
        let data = self.buffer.as_mut();
        let len = data.len();
        data[field::NEXT_HEADER::<C>(len)] = value;
    }

    pub fn set_icv<C>(&mut self, value: &GenericArray<u8, C::TagSize>)
    where
        C: Cipher,
    {
        let data = self.buffer.as_mut();
        let len = data.len();
        data[field::ICV::<C>(len)].copy_from_slice(value);
    }
}

impl<T> EncryptedPacket<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    pub fn decrypt<C>(mut self, cipher: &C) -> Result<DecryptedPacket<T>>
    where
        C: Cipher,
    {
        let (associated, iv, ciphertext, icv) = self.split_cipher_material_mut::<C>();
        cipher.decrypt(&iv, associated, ciphertext, icv)?;
        // TODO: Validate padding
        DecryptedPacket::new_checked::<C>(self.into_inner())
    }
}

impl Repr {
    pub fn new(spi: u32, sequence_number: u32, next_header: u8) -> Self {
        Repr {
            spi,
            sequence_number,
            next_header,
        }
    }

    pub fn parse<T, C>(dec: &DecryptedPacket<T>) -> Repr
    where
        T: AsRef<[u8]>,
        C: Cipher,
    {
        Repr {
            spi: dec.spi(),
            sequence_number: dec.sequence_number(),
            next_header: dec.next_header::<C>(),
        }
    }

    pub fn emit<T, C>(
        &self,
        cipher: &C,
        mut packet: DecryptedPacket<T>,
        payload_len: usize,
        emit_payload: impl FnOnce(&mut [u8]),
        iv: &GenericArray<u8, C::IvSize>,
    ) -> Result<EncryptedPacket<T>>
    where
        C: Cipher,
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        packet.set_spi(self.spi);
        packet.set_sequence_number(self.sequence_number);
        packet.set_iv::<C>(iv);
        packet.set_pad_len::<C>(pad_len(payload_len, C::BlockSize::to_usize()));
        emit_payload(packet.payload_mut::<C>());
        pad(
            packet.ciphertext_mut::<C>(),
            payload_len,
            C::BlockSize::to_usize(),
        );
        packet.set_next_header::<C>(self.next_header);
        let (associated, _, ciphertext, _) = packet.split_cipher_material_mut::<C>();
        let tag = cipher.encrypt(iv, associated, ciphertext)?;
        packet.set_icv::<C>(&tag);
        let buffer = packet.into_inner();
        Ok(EncryptedPacket { buffer })
    }
}

pub fn packet_len<C>(payload_len: usize, _c: &C) -> usize
where
    C: Cipher,
{
    let len = 4 + // SPI
        4 + // sequence number
        C::IvSize::to_usize() + // IV
        payload_len + // payload length
        pad_len(payload_len, C::BlockSize::to_usize()) as usize + // paddiong
        1 + // pad length field
        1 + // next_header field
        C::TagSize::to_usize(); // ICV
    len
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::esp::encryption::AeadCipher;
    use aes_gcm::Aes256Gcm;
    use aes_gcm::NewAead;
    use generic_array::arr;
    use hmac::Hmac;
    use sha2::Sha256;
    use block_modes::Cbc;
    use block_padding::NoPadding;
    use crypto::mac::NewMac;
    use crypto::cipher::NewBlockCipher;
    use crate::esp::encryption::BlockMacCipher;
    use aes::Aes256;

    #[test]
    fn encrypt_decrypt_inverse() {
        let data = Vec::from("Hello World I am around".as_bytes());
        let repr = Repr::new(1, 1, 4);

        let key = aes_gcm::Key::from_slice(b"an example very very secret key.");
        let iv = arr![u8; 0,0,0,0,0,0,0,1];
        let salt = arr![u8; 0,0,0,1];
        let aes = Aes256Gcm::new(key);
        let cipher = AeadCipher::new(aes, salt);

        let len = packet_len(data.len(), &cipher);
        let mut packet_buffer = Vec::with_capacity(len);
        unsafe {
            packet_buffer.set_len(len);
        }
        let packet = DecryptedPacket::new_unchecked(packet_buffer);

        let encrypted = repr
            .emit(
                &cipher,
                packet,
                data.len(),
                |vec| vec.copy_from_slice(&data),
                &iv,
            )
            .unwrap();
        let decrypted = encrypted.decrypt(&cipher).unwrap();
        assert_eq!(data, decrypted.payload(&cipher));
    }

    #[test]
    fn encrypt_decrypt_inverse_2() {
        let data = Vec::from("Hello World I am around".as_bytes());
        let repr = Repr::new(1, 1, 4);

        let key = GenericArray::from_slice(b"an example very very secret key.");
        let iv = GenericArray::from_slice(b"abcdefghijklopqr");
        let aes = Aes256::new(key);
        let mac = Hmac::<Sha256>::new_from_slice(b"very good key and such").unwrap();
        let cipher = BlockMacCipher::<_, Cbc<Aes256, NoPadding>, _>::new(aes, mac);

        let len = packet_len(data.len(), &cipher);
        let mut packet_buffer = Vec::with_capacity(len);
        unsafe {
            packet_buffer.set_len(len);
        }
        let packet = DecryptedPacket::new_unchecked(packet_buffer);

        let encrypted = repr
            .emit(
                &cipher,
                packet,
                data.len(),
                |vec| vec.copy_from_slice(&data),
                &iv,
            )
            .unwrap();
        let decrypted = encrypted.decrypt(&cipher).unwrap();
        assert_eq!(data, decrypted.payload(&cipher));
    }
}
