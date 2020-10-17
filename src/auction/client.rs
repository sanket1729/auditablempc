use crate::mpc::interpolate::interpolate_shares;
use crate::mpc::preprocessing::Preprocess;
use crate::mpc::{MPCConfig, MPCError};
use crate::ped_commitments::pec_polycommit::PECCommiterKey;
use crate::ped_commitments::pec_polycommit::PECPolycommit;
use crate::ped_commitments::pederson::Commitment as PedCommitment;
use crate::ped_commitments::pederson::{CommiterKey, PedersonCommitment};
use algebra_core::PairingEngine;
/// File representing the client in MPC auction application
use algebra_core::PrimeField;
use poly_commit::marlin_kzg10::Commitment as KGZCommitment;
use poly_commit::LabeledCommitment;
use rand_core::RngCore;

use algebra::Bls12_381;
use algebra::bls12_381::Fr as BlsFr;
/// MPC client struct
#[derive(Clone, Debug)]
pub struct Client {
    /// The client id
    pub id: usize,
    /// The bid of the client, currently only
    /// supporting one input per client for simplicity.
    /// In the auction application, this would be the bid
    pub input: Vec<BlsFr>,
    /// Share of random number recieved from the server
    pub rand_shares: Vec<Vec<BlsFr>>,
    /// Random interpolated value
    pub random_v_from_servers: Vec<BlsFr>,
    /// Input shares
    pub masked_input: Vec<BlsFr>,
    /// Commiter Key
    pub ck: CommiterKey<Bls12_381>,
}

impl Client {
    /// Create a new client
    pub fn new(id: usize, input: BlsFr, ck: CommiterKey<Bls12_381>) -> Self {
        Self {
            id: id,
            input: vec![input],
            rand_shares: vec![],
            random_v_from_servers: vec![],
            masked_input: vec![],
            ck: ck,
        }
    }

    /// Set the random shares recived from the servers
    pub fn recieve_random_shares(
        &mut self,
        shares_vec: Vec<Vec<BlsFr>>,
        preproc: &Preprocess<BlsFr>,
        mpc_config: MPCConfig,
    ) -> Result<Vec<BlsFr>, MPCError> {
        self.rand_shares = shares_vec.clone();
        let mut i = 0;
        for shares in shares_vec {
            let r = interpolate_shares(preproc, shares, mpc_config)?;
            self.random_v_from_servers.push(r);
            let masked_inp = self.input[i] + &r;
            self.masked_input.push(masked_inp);
            i += 1;
        }
        Ok(self.masked_input.clone())
    }

    /// Pedersen Commit to the inputs
    pub fn commit_input(&self) -> PedCommitment<Bls12_381> {
        PedersonCommitment::commit(&self.ck, self.input[0], self.random_v_from_servers[0])
    }

    /// Commit to the inputs using PEC
    pub fn pec_commit_input<R: RngCore, D: digest::Digest>(
        &mut self,
        ck: &PECCommiterKey,
        zk_rng: &mut R,
    ) -> LabeledCommitment<KGZCommitment<Bls12_381>> {
        let (comm, comm_rands) = PECPolycommit::commit::<_, D>(&ck, self.input[0], self.id + 1, zk_rng);
        let rand_poly = comm_rands[0].rand.blinding_polynomial.clone();
        assert_eq!(rand_poly.degree(), 1);
        self.input.push(rand_poly.coeffs[0]);
        self.input.push(rand_poly.coeffs[1]);
        comm[0].clone()
    }
}
