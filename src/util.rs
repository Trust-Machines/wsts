use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    curve::{point::Point, scalar::Scalar},
    errors::EncryptionError,
};

/// Size of the AES-GCM nonce
pub const AES_GCM_NONCE_SIZE: usize = 12;

#[allow(dead_code)]
/// Digest the hasher to a Scalar
pub fn hash_to_scalar(hasher: &mut Sha256) -> Scalar {
    let h = hasher.clone();
    let hash = h.finalize();
    let mut hash_bytes: [u8; 32] = [0; 32];
    hash_bytes.clone_from_slice(hash.as_slice());

    Scalar::from(hash_bytes)
}

/// Do a Diffie-Hellman key exchange to create a shared secret from the passed private/public keys
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> [u8; 32] {
    let shared_key = private_key * public_key;

    make_shared_secret_from_key(&shared_key)
}

/// Create a shared secret from the passed Diffie-Hellman shared key
pub fn make_shared_secret_from_key(shared_key: &Point) -> [u8; 32] {
    ansi_x963_derive_key(
        shared_key.compress().as_bytes(),
        "DH_SHARED_SECRET_KEY/".as_bytes(),
    )
}

/// Derive a shared key using the ANSI-x963 standard
/// https://www.secg.org/sec1-v2.pdf (section 3.6.1)
pub fn ansi_x963_derive_key(shared_key: &[u8], shared_info: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let counter = 1u32;

    hasher.update(shared_key);
    hasher.update(counter.to_be_bytes());
    hasher.update(shared_info);

    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];

    bytes.clone_from_slice(hash.as_slice());
    bytes
}

/// Encrypt the passed data using the key
pub fn encrypt<RNG: RngCore + CryptoRng>(
    key: &[u8; 32],
    data: &[u8],
    rng: &mut RNG,
) -> Result<Vec<u8>, EncryptionError> {
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];

    rng.fill_bytes(&mut nonce_bytes);

    let nonce_vec = nonce_bytes.to_vec();
    let nonce = Nonce::from_slice(&nonce_vec);
    let cipher = Aes256Gcm::new(key.into());
    let cipher_vec = cipher.encrypt(nonce, data.to_vec().as_ref())?;
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&nonce_vec);
    bytes.extend_from_slice(&cipher_vec);

    Ok(bytes)
}

/// Decrypt the passed data using the key
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if data.len() < AES_GCM_NONCE_SIZE {
        return Err(EncryptionError::MissingNonce);
    }
    let nonce_vec = data[..AES_GCM_NONCE_SIZE].to_vec();
    let cipher_vec = data[AES_GCM_NONCE_SIZE..].to_vec();
    let nonce = Nonce::from_slice(&nonce_vec);
    let cipher = Aes256Gcm::new(key.into());

    Ok(cipher.decrypt(nonce, cipher_vec.as_ref())?)
}

/// Creates a new random number generator.
pub fn create_rng() -> impl RngCore + CryptoRng {
    OsRng
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::{point::Point, scalar::Scalar};

    #[test]
    #[allow(non_snake_case)]
    fn test_shared_secret() {
        let mut rng = create_rng();

        let x = Scalar::random(&mut rng);
        let y = Scalar::random(&mut rng);

        let X = Point::from(x);
        let Y = Point::from(y);

        let xy = make_shared_secret(&x, &Y);
        let yx = make_shared_secret(&y, &X);

        assert_eq!(xy, yx);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_encrypt_decrypt() {
        let mut rng = create_rng();
        let msg = "It was many and many a year ago, in a kingdom by the sea...";

        let x = Scalar::random(&mut rng);
        let y = Scalar::random(&mut rng);

        let X = Point::from(x);
        let Y = Point::from(y);

        let xy = make_shared_secret(&x, &Y);
        let yx = make_shared_secret(&y, &X);

        let cipher = encrypt(&xy, msg.as_bytes(), &mut rng).unwrap();
        let plain = decrypt(&yx, &cipher).unwrap();

        assert_eq!(msg.as_bytes(), &plain);

        let missing_nonce = &cipher[..AES_GCM_NONCE_SIZE - 1];
        match decrypt(&yx, &missing_nonce) {
            Err(EncryptionError::MissingNonce) => {}
            Err(e) => panic!("expected MissingNonce got Err({e})"),
            Ok(_) => panic!("expected MissingNonce got Ok()"),
        }

        let missing_data = &cipher[..AES_GCM_NONCE_SIZE];
        match decrypt(&yx, &missing_data) {
            Err(EncryptionError::AesGcm(_)) => (),
            Err(e) => panic!("expected EncryptionError(AesGcm) got Err({e:?})"),
            Ok(_) => panic!("expected EncryptionError(AesGcm) got Ok()"),
        }

        let small_data = &cipher[..AES_GCM_NONCE_SIZE + 1];
        match decrypt(&yx, &small_data) {
            Err(EncryptionError::AesGcm(_)) => (),
            Err(e) => panic!("expected EncryptionError(AesGcm) got Err({e:?})"),
            Ok(_) => panic!("expected EncryptionError(AesGcm) got Ok()"),
        }
    }
}
