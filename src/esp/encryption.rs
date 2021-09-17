use crate::util::{Error, Result};
use crate::esp;
use aes_gcm::AeadInPlace;
use block_modes::BlockMode;
use block_padding::NoPadding;
use core::marker::PhantomData;
use core::ops::Sub;
use crypto::aead::{AeadCore, NewAead};
use crypto::cipher::BlockCipher;
use crypto::mac::Mac;
use generic_array::{ArrayLength, GenericArray};
use typenum::Diff;
use typenum::U4;

pub trait Cipher {
    type TagSize: ArrayLength<u8>;
    type BlockSize: ArrayLength<u8>;
    type IvSize: ArrayLength<u8>;

    fn encrypt(
        &self,
        iv: &GenericArray<u8, Self::IvSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>>;
    fn decrypt(
        &self,
        iv: &GenericArray<u8, Self::IvSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<()>;
}

pub struct AeadCipher<C, SaltSize: ArrayLength<u8>> {
    cipher: C,
    salt: GenericArray<u8, SaltSize>,
}

pub struct BlockMacCipher<C, Mode, M> {
    cipher: C,
    mode: PhantomData<Mode>,
    mac: M,
}

impl<C, SaltSize: ArrayLength<u8>> AeadCipher<C, SaltSize> {
    pub fn new(cipher: C, salt: GenericArray<u8, SaltSize>) -> AeadCipher<C, SaltSize> {
        AeadCipher { cipher, salt }
    }
}

impl<C, Mode, M> BlockMacCipher<C, Mode, M> {
    pub fn new(cipher: C, mac: M) -> BlockMacCipher<C, Mode, M> {
        BlockMacCipher {
            cipher,
            mode: PhantomData,
            mac,
        }
    }
}

impl<C: NewAead + AeadInPlace, SaltSize: ArrayLength<u8>> Cipher for AeadCipher<C, SaltSize>
// The job of these trait bounds is to ensure that the type IvSize below works,
// I am at the moment not good enough with typenum to check whether this is actually
// how its supposed to be done but it works.
where
    <C as AeadCore>::NonceSize: Sub<SaltSize>,
    <<C as AeadCore>::NonceSize as Sub<SaltSize>>::Output: ArrayLength<u8>,
{
    type TagSize = <C as AeadCore>::TagSize;
    type BlockSize = U4;
    type IvSize = Diff<<C as AeadCore>::NonceSize, SaltSize>;

    fn encrypt(
        &self,
        iv: &GenericArray<u8, Self::IvSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>> {
        // TODO: use GenericArray concat instead
        let nonce_slice = [self.salt.as_ref(), iv].concat();
        let nonce = GenericArray::from_slice(&nonce_slice);
        self.cipher
            .encrypt_in_place_detached(&nonce, associated_data, buffer)
            .map_err(|_| esp::Error::Foo)
    }
    fn decrypt(
        &self,
        iv: &GenericArray<u8, Self::IvSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<()> {
        // TODO: use GenericArray concat instead
        let nonce_slice = [self.salt.as_ref(), iv].concat();
        let nonce = GenericArray::from_slice(&nonce_slice);
        self.cipher
            .decrypt_in_place_detached(&nonce, associated_data, buffer, tag)
            .map_err(|_| esp::Error::Foo)
    }
}

impl<C: BlockCipher + Clone, Mode: BlockMode<C, NoPadding>, M: Mac> Cipher
    for BlockMacCipher<C, Mode, M>
{
    type TagSize = <M as Mac>::OutputSize;
    type BlockSize = <C as BlockCipher>::BlockSize;
    type IvSize = <Mode as BlockMode<C, NoPadding>>::IvSize;

    fn encrypt(
        &self,
        iv: &GenericArray<u8, Self::IvSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>> {
        let mut mac = self.mac.clone();
        mac.update(associated_data);
        mac.update(iv);
        mac.update(buffer);
        let tag = mac.finalize();
        let block_cipher = Mode::new(self.cipher.clone(), iv);
        block_cipher
            .encrypt(buffer, buffer.len())
            .map_err(|_| esp::Error::Foo)?;
        Ok(tag.into_bytes())
    }

    fn decrypt(
        &self,
        iv: &GenericArray<u8, Self::IvSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<()> {
        let block_cipher = Mode::new(self.cipher.clone(), iv);
        block_cipher.decrypt(buffer).map_err(|_| esp::Error::Foo)?;
        let mut mac = self.mac.clone();
        mac.update(associated_data);
        mac.update(iv);
        mac.update(buffer);
        mac.verify(tag).map_err(|_| esp::Error::Foo)
    }
}

#[cfg(test)]
mod test {
    use super::{AeadCipher, BlockMacCipher, Cipher};
    use aes::Aes256;
    use aes_gcm::aead::NewAead;
    use aes_gcm::Aes256Gcm;
    use block_modes::Cbc;
    use block_padding::NoPadding;
    use core::marker::PhantomData;
    use crypto::cipher::NewBlockCipher;
    use crypto::mac::NewMac;
    use generic_array::arr;
    use generic_array::GenericArray;
    use hmac::Hmac;
    use sha2::Sha256;

    #[test]
    fn test() {
        let key = aes_gcm::Key::from_slice(b"an example very very secret key.");
        let aes = Aes256Gcm::new(key);
        let salt = arr![u8; 0,0,0,1];
        let iv = arr![u8; 0,0,0,0,0,0,0,1];
        let plaintext = b"plaintext message";
        let cipher = AeadCipher { cipher: aes, salt };
        let mut buffer = Vec::new();
        buffer.extend_from_slice(plaintext);

        let tag = cipher
            .encrypt(&iv, b"abc", &mut buffer)
            .expect("encryption failure!");

        assert_ne!(&buffer, plaintext);

        cipher
            .decrypt(&iv, b"abc", &mut buffer, &tag)
            .expect("decryption failure!");
        assert_eq!(&buffer, plaintext);
    }

    #[test]
    fn test2() {
        let key = GenericArray::from_slice(b"an example very very secret key.");
        let iv = GenericArray::from_slice(b"abcdefghijklopqr");
        let plaintext = b"plaintext messag";
        let aes = Aes256::new(key);
        let mac = Hmac::<Sha256>::new_from_slice(b"very good key and such").unwrap();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(plaintext);
        let cipher = BlockMacCipher {
            cipher: aes,
            mode: PhantomData::<Cbc<Aes256, NoPadding>>,
            mac,
        };
        let tag = cipher
            .encrypt(&iv, b"abc", &mut buffer)
            .expect("encryption failure!");

        assert_ne!(&buffer, plaintext);

        cipher
            .decrypt(&iv, b"abc", &mut buffer, &tag)
            .expect("decryption failure!");
        assert_eq!(&buffer, plaintext);
    }
}
