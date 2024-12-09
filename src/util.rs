use aes_gcm::{aead::Aead, Aes256Gcm, Error as AesGcmError, KeyInit, Nonce};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::curve::{point::Point, scalar::Scalar};

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
) -> Result<Vec<u8>, AesGcmError> {
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
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, AesGcmError> {
    let nonce_vec = data[..AES_GCM_NONCE_SIZE].to_vec();
    let cipher_vec = data[AES_GCM_NONCE_SIZE..].to_vec();
    let nonce = Nonce::from_slice(&nonce_vec);
    let cipher = Aes256Gcm::new(key.into());

    cipher.decrypt(nonce, cipher_vec.as_ref())
}

/// An El-Gamal encryption packet
struct ElGamal {
    c1: Scalar,
    c2: Scalar,
}

/// encrypt using a scalar based El-Gamal
pub fn encrypt_elgamal<RNG: RngCore + CryptoRng>(
    generator: Scalar,
    message: Scalar,
    public_key: Scalar,
    rng: &mut RNG,
) -> Result<ElGamal, String> {
    // ephemeral key
    let k = Scalar::random(rng);

    let c1 = generator ^ k;
    let c2 = (message.invert()) * (public_key ^ k);

    Ok(ElGamal { c1, c2 })
}

/// encrypt using a scalar based El-Gamal
pub fn decrypt_elgamal(elgamal: &ElGamal, private_key: Scalar) -> Result<Scalar, String> {
    let message = (elgamal.c1 ^ private_key) * (elgamal.c2.invert());
    Ok(message)
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
    fn shared_secret() {
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
    fn encrypt_decrypt() {
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
    }

    #[test]
    fn elgamal() {
        let mut rng = create_rng();
        let generator = Scalar::random(&mut rng);
        let private_key = Scalar::random(&mut rng);
        let public_key = generator ^ private_key;
        let message = Scalar::random(&mut rng);

        let elgamal = encrypt_elgamal(generator, message, public_key, &mut rng).unwrap();
        let decrypted_message = decrypt_elgamal(&elgamal, private_key).unwrap();

        assert_eq!(message, decrypted_message);
    }

    #[test]
    fn pvss() {}
}
