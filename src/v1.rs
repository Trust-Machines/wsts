use num_traits::Zero;
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use secp256k1_math::{
    point::{Point, G},
    scalar::Scalar,
};

use crate::common::{Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare};
use crate::compute::{binding, challenge, intermediate, lambda};
use crate::schnorr::ID;
use crate::vss::VSS;

use hashbrown::HashMap;

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct Party {
    pub id: usize,
    pub public_key: Point,
    n: usize,
    _t: usize,
    f: Polynomial<Scalar>,
    //shares: HashMap<usize, Scalar>, // received from other parties
    private_key: Scalar,
    group_key: Point,
    nonces: Vec<Nonce>,
    B: Vec<Vec<PublicNonce>>, // received from other parties
}

impl Party {
    #[allow(non_snake_case)]
    pub fn new<RNG: RngCore + CryptoRng>(id: usize, n: usize, t: usize, rng: &mut RNG) -> Self {
        Self {
            id: id,
            n: n,
            _t: t,
            f: VSS::random_poly(t - 1, rng),
            private_key: Scalar::zero(),
            public_key: Point::zero(),
            group_key: Point::zero(),
            nonces: Vec::new(),
            B: Vec::new(),
        }
    }

    pub fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        num_nonces: u32,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        self.nonces = (0..num_nonces)
            .map(|_| Nonce {
                d: Scalar::random(rng),
                e: Scalar::random(rng),
            })
            .collect();
        self.nonces.iter().map(|n| PublicNonce::from(n)).collect()
    }

    #[allow(non_snake_case)]
    pub fn set_group_nonces(&mut self, B: Vec<Vec<PublicNonce>>) {
        self.B = B;
    }

    // Warning: This function assumes that B already exists - it's just for resetting
    #[allow(non_snake_case)]
    pub fn set_party_nonces(&mut self, i: usize, B: Vec<PublicNonce>) {
        self.B[i] = B;
    }

    #[allow(non_snake_case)]
    pub fn get_poly_commitment<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> PolyCommitment {
        PolyCommitment {
            id: ID::new(&self.id(), &self.f.data()[0], rng),
            A: (0..self.f.data().len())
                .map(|i| &self.f.data()[i] * G)
                .collect(),
        }
    }

    pub fn get_shares(&self) -> HashMap<usize, Scalar> {
        let mut shares = HashMap::new();
        for i in 0..self.n as usize {
            shares.insert(i, self.f.eval(Scalar::from((i + 1) as u32)));
        }
        shares
    }

    // TODO: Maybe this should be private? If receive_share is keeping track
    // of which it receives, then this could be called when it has N shares from unique ids
    #[allow(non_snake_case)]
    pub fn compute_secret(&mut self, shares: HashMap<usize, Scalar>, A: &Vec<PolyCommitment>) {
        // TODO: return error with a list of missing shares
        assert!(shares.len() == self.n);
        self.private_key = Scalar::zero();
        for (i, s) in shares.iter() {
            let Ai = &A[*i];
            assert!(Ai.verify()); // checks a0 proof
            assert!(
                s * G
                    == (0..Ai.A.len()).fold(Point::zero(), |s, j| s
                        + (Scalar::from((self.id + 1) as u32) ^ j) * Ai.A[j])
            );
            self.private_key += s;
            self.group_key += Ai.A[0].clone();
        }
        self.public_key = self.private_key * G;
        println!("Party {} secret {}", self.id, self.private_key);
    }

    fn id(&self) -> Scalar {
        Scalar::from((self.id + 1) as u32)
    }

    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &String, signers: &Vec<usize>, nonce_index: usize) -> Scalar {
        let (B, _R_vec, R) = intermediate(&signers, &self.B, nonce_index, &msg);
        let nonce = &self.nonces[nonce_index]; // TODO: needs to check that index exists
        let mut z = &nonce.d + &nonce.e * binding(&self.id(), &B, &msg);
        z += challenge(&self.group_key, &R, &msg) * &self.private_key * lambda(&self.id, signers);
        z
    }
}

#[allow(non_snake_case)]
pub struct SignatureAggregator {
    pub N: usize,
    pub T: usize,
    pub A: Vec<PolyCommitment>, // outer vector is N-long, inner vector is T-long
    pub B: Vec<Vec<PublicNonce>>, // outer vector is N-long, inner vector is T-long
    pub key: Point,
    nonce_ctr: usize,
    num_nonces: usize,
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    pub fn new(N: usize, T: usize, A: Vec<PolyCommitment>, B: Vec<Vec<PublicNonce>>) -> Self {
        // TODO: How should we handle bad As?
        assert!(A.len() == N);
        for A_i in &A {
            assert!(A_i.verify());
        }

        let mut key = Point::new(); // TODO: Compute pub key from A
        for A_i in &A {
            key += &A_i.A[0];
        }
        println!("SA groupKey {}", key);

        assert!(B.len() == N);
        let num_nonces = B[0].len();
        for b in &B {
            assert!(num_nonces == b.len());
        }
        // TODO: Check that each B_i is len num_nonces?

        Self {
            N: N,
            T: T,
            A: A,
            B: B,
            key: key,
            nonce_ctr: 0,
            num_nonces: num_nonces,
        }
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &String,
        sig_shares: &Vec<SignatureShare>,
        signers: &Vec<usize>,
    ) -> Signature {
        let (_B, R_vec, R) = intermediate(&signers, &self.B, self.nonce_ctr, &msg);

        let mut z = Scalar::zero();
        let c = challenge(&self.key, &R, &msg); // only needed for checking z_i
        for i in 0..signers.len() {
            let z_i = sig_shares[i].z_i;
            assert!(
                z_i * G
                    == R_vec[i]
                        + (lambda(&sig_shares[i].id, signers) * c * sig_shares[i].public_key)
            ); // TODO: This should return a list of bad parties.
            z += z_i;
        }
        self.update_nonce();

        Signature { R: R, z: z }
    }

    pub fn get_nonce_ctr(&self) -> usize {
        self.nonce_ctr
    }

    fn update_nonce(&mut self) {
        self.nonce_ctr += 1;
        if self.nonce_ctr == self.num_nonces {
            // TODO: Should this kick off the re-generation process?
            println!("This is the last available nonce! Need to generate more!");
        }
    }

    #[allow(non_snake_case)]
    pub fn set_party_nonces(&mut self, i: usize, B: Vec<PublicNonce>) {
        self.B[i] = B;
    }

    #[allow(non_snake_case)]
    pub fn set_group_nonces(&mut self, B: Vec<Vec<PublicNonce>>) {
        self.B = B;
        self.nonce_ctr = 0;
        self.num_nonces = self.B.len();
    }
}
