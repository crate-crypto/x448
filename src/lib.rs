use ed448::curve::MontgomeryPoint;
use ed448::Scalar;

pub struct PublicKey(MontgomeryPoint);

//XXX: Can probably use a trait for all of the shared functionality between different secret types
pub struct Secret([u8; 56]);

impl PublicKey {
    /// Converts a bytes slice into a Public key
    pub fn from_bytes(bytes: &[u8]) -> Option<PublicKey> {
        // First check if we have 56 bytes
        if bytes.len() != 56 {
            return None;
        }

        let point = MontgomeryPoint(bytes_to_array(bytes));
        Some(PublicKey(point))
    }
    /// Converts a public key into a byte array
    pub fn as_bytes(&self) -> [u8; 56] {
        (self.0).0
    }
}

fn bytes_to_array(bytes: &[u8]) -> [u8; 56] {
    let mut array: [u8; 56] = [0; 56];
    array.copy_from_slice(&bytes);
    array
}

impl Secret {
    /// Clamps the Secret
    fn clamp(&mut self) {
        self.0[0] &= 252;
        self.0[55] |= 128;
    }
    /// Performs a Diffie-hellman key exchange
    /// Between the secret key and an external public key
    pub fn as_diffie_hellman(&self, public_key: &PublicKey) -> PublicKey {
        let shared_key = public_key.0.mul(&self.as_scalar()); // FIXME: in Ed448 crate
        PublicKey(shared_key)
    }
    /// Performs a Diffie-hellman key exchange once
    /// Between the secret key and an external public key
    pub fn to_diffie_hellman(self, public_key: &PublicKey) -> PublicKey {
        self.as_diffie_hellman(public_key)
    }
    /// Converts a byte slice into a secret
    /// and clamp
    pub fn from_bytes(bytes: &[u8]) -> Option<Secret> {
        // First check if we have 56 bytes
        if bytes.len() != 56 {
            return None;
        }

        let mut secret = Secret(bytes_to_array(bytes));
        secret.clamp();

        Some(secret)
    }
    // XXX: Use RNG to produce a random secret
    pub fn new() -> Secret {
        todo!()
    }
    /// Converts a secret into a byte array
    pub fn as_bytes(&self) -> [u8; 56] {
        self.0
    }
    /// Converts a secret into a scalar
    /// so that it can be used in scalar mul
    fn as_scalar(&self) -> Scalar {
        Scalar::from_bytes(self.0)
    }
    pub fn as_public_key(&self) -> PublicKey {
        todo!()
    }
}

mod test {
    use super::*;

    // Swaps a secret and public key as mentioned in the RFC test vector iteration
    // This should only be completed for tests
    fn swap(secret: &Secret, public_key: PublicKey) -> (Secret, PublicKey) {
        todo!()
    }

    // Helper method
    fn hex_to_array(data: &str) -> [u8; 56] {
        let bytes = hex::decode(data).unwrap();
        bytes_to_array(&bytes)
    }

    #[test]
    fn test_rfc_vector1() {
        // Load basepoint
        let point_bytes = hex_to_array("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
        let public_key = PublicKey::from_bytes(&point_bytes).unwrap();

        let scalar_bytes = hex_to_array("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
        let secret = Secret::from_bytes(&scalar_bytes).unwrap();

        // Compute output
        let output = secret.as_diffie_hellman(&public_key);

        // Expected output
        let expected = hex_to_array("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
        assert_eq!(&output.as_bytes()[..], &expected[..]);
    }
}
