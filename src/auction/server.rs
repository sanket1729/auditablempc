use crate::mpc::preprocessing::Preprocess;
use crate::mpc::{MPCConfig, MPCError};
/// The server for MPC applications
use algebra_core::PairingEngine;
use core::ops::Mul;
use ff_fft::DensePolynomial as Polynomial;

use crate::mpc::interpolate::batch_interpolate_shares_exponent;
use crate::mpc::interpolate::interpolate_shares;
use crate::mpc::interpolate::pec_batch_interpolate_shares_exponent;
use crate::ped_commitments::pec_polycommit::PECCommiterKey;
use crate::ped_commitments::pec_polycommit::PECPolycommit;
use crate::ped_commitments::pederson::Commitment as PedCommitment;
use crate::ped_commitments::pederson::{CommiterKey, PedersonCommitment};
use poly_commit::marlin_kzg10::Commitment as KGZCommitment;
use poly_commit::LabeledCommitment;
use rand_core::RngCore;

use algebra::Bls12_381;
use algebra::bls12_381::Fr as BlsFr;
/// MPC server implementation
#[derive(Clone)]
pub struct MPCserver {
    ///Server id
    pub id: usize,
    /// MPC server state
    pub server_state: Vec<BlsFr>,
    /// Client inputs
    pub client_inputs: Vec<BlsFr>,
    /// Client inputs
    pub client_rand_inputs: Vec<BlsFr>,
    /// Server outputs
    pub server_outputs: Vec<BlsFr>,
    /// Random shares
    pub random_shares: Vec<BlsFr>,
    /// Zero shares
    pub zero_shares: Vec<BlsFr>,
    /// Triple shares
    pub triple_shares: Vec<(BlsFr, BlsFr, BlsFr)>,
    /// Current counter for rand shares consumption
    pub rand_share_iter: usize,
    /// Current counter for triple shares consumption
    pub triple_share_iter: usize,
    ///iterator for zero shares
    pub zero_share_iter: usize,
    /// Commiter Key
    pub ck: CommiterKey<Bls12_381>,
    /// Commitment to the output of computations
    pub output_comms: Vec<PedCommitment<Bls12_381>>,
    /// Commitment to the output of computations
    pub pec_output_comms: Vec<LabeledCommitment<KGZCommitment<Bls12_381>>>,
}

impl MPCserver {
    ///Create a new server
    pub fn new(id: usize, preproc: &Preprocess<BlsFr>, ck: CommiterKey<Bls12_381>) -> Self {
        Self {
            id: id,
            server_outputs: vec![],
            client_inputs: vec![],
            client_rand_inputs: vec![],
            server_state: vec![],
            zero_shares: preproc.shares_zero[id].clone(),
            random_shares: preproc.rand_shares[id].clone(),
            triple_shares: preproc.triples[id].clone(),
            rand_share_iter: 0,
            triple_share_iter: 0,
            zero_share_iter: 0,
            ck: ck,
            output_comms: vec![],
            pec_output_comms: vec![],
        }
    }
    /// Get triple
    pub fn get_new_triple(&mut self) -> ((BlsFr, BlsFr, BlsFr), usize) {
        let triple_ind = self.triple_share_iter;
        self.triple_share_iter += 1;
        (self.triple_shares[triple_ind], triple_ind)
    }

    /// Get zero share
    pub fn get_new_zero_share(&mut self) -> BlsFr {
        let ret = self.zero_shares[self.zero_share_iter];
        self.zero_share_iter += 1;
        ret
    }

    /// Beaver multiplication
    pub fn beaver_mult(
        &self,
        preproc: &Preprocess<BlsFr>,
        mpc_cfg: MPCConfig,
        x_share: BlsFr,
        y_share: BlsFr,
        triple_ind: usize,
        d_shares: Vec<BlsFr>,
        e_shares: Vec<BlsFr>,
    ) -> Result<BlsFr, MPCError> {
        let (_a, _b, ab) = self.triple_shares[triple_ind];
        let d_open = interpolate_shares(preproc, d_shares, mpc_cfg)?;
        let e_open = interpolate_shares(preproc, e_shares, mpc_cfg)?;

        let xy_share = ab + &x_share.mul(&e_open) + &y_share.mul(&d_open) - &e_open.mul(&d_open);
        Ok(xy_share)
    }

    /// Process new client input. Consumes the share
    pub fn get_rand_share(&mut self) -> (BlsFr, usize) {
        let elem = self.random_shares[self.rand_share_iter];
        self.rand_share_iter += 1;
        (elem, self.rand_share_iter - 1)
    }

    /// Process masked input
    pub fn process_masked_input(&mut self, masked_input: Vec<BlsFr>, rand_index: Vec<usize>) {
        self.client_inputs
            .push(masked_input[0] - &self.random_shares[rand_index[0]]);
        for i in 1..3 {
            self.client_rand_inputs
                .push(masked_input[i] - &self.random_shares[rand_index[i]]);
        }
    }

    /// HACKY: set server output
    /// Set the servers output
    pub fn set_server_output(&mut self, outputs: Vec<BlsFr>) {
        for output in outputs {
            self.server_outputs.push(output);
        }
    }

    /// Get partial commitment to the outputs
    /// Note that we assign a new r value here
    pub fn get_server_output_comm_share(&mut self) -> Vec<PedCommitment<Bls12_381>> {
        let mut comms = vec![];
        for output in self.server_outputs.clone() {
            let comm = PedersonCommitment::commit(
                &self.ck,
                output,
                self.random_shares[self.rand_share_iter],
            );
            self.rand_share_iter += 1;
            comms.push(comm);
        }
        comms
    }

    /// Get a vector of partial commitment to the outputs
    pub fn get_server_input_comm_share(&self) -> Vec<PedCommitment<Bls12_381>> {
        let mut comms = vec![];
        for i in 0..self.client_inputs.len() {
            let comm =
                PedersonCommitment::commit(&self.ck, self.client_inputs[i], self.random_shares[i]);
            comms.push(comm);
        }
        comms
    }

    /// Get a vector of partial commitment to the outputs
    pub fn get_server_output_pec_comm_share<R: RngCore, D: digest::Digest>(
        &mut self,
        ck: &PECCommiterKey,
        zk_rng: &mut R,
    ) -> Vec<LabeledCommitment<KGZCommitment<Bls12_381>>> {
        let mut comms = vec![];
        for output in self.server_outputs.clone() {
            let lagrange_poly_id = self.client_inputs.len() + 1;
            // Reconstruct the random polynomial
            let (comm, comm_rands) = PECPolycommit::commit::<_, D>(&ck, output, lagrange_poly_id, zk_rng);
            let rand_poly = comm_rands[0].rand.blinding_polynomial.clone();
            assert_eq!(rand_poly.degree(), 1);
            self.client_rand_inputs.push(rand_poly.coeffs[0]);
            self.client_rand_inputs.push(rand_poly.coeffs[1]);
            comms.push(comm[0].clone());
        }
        comms
    }

    /// Get a vector of partial commitment to the outputs
    pub fn get_server_input_pec_comm_share<R: RngCore, D: digest::Digest>(
        &self,
        ck: &PECCommiterKey,
        zk_rng: &mut R,
    ) -> Vec<LabeledCommitment<KGZCommitment<Bls12_381>>> {
        let mut comms = vec![];
        for i in 0..self.client_inputs.len() {
            let lagrange_poly_id = i + 1;
            // Reconstruct the random polynomial
            let blind_poly = Polynomial::from_coefficients_vec(vec![
                self.client_rand_inputs[2 * i],
                self.client_rand_inputs[2 * i + 1],
            ]);
            let (comm, _comm_rand, _s) = PECPolycommit::commit_with_rand::<_, D>(
                &ck,
                self.client_inputs[i],
                lagrange_poly_id,
                blind_poly,
                zk_rng,
            );
            comms.push(comm[0].clone());
        }
        comms
    }

    /// Combine shares to a total commitment
    pub fn combine_comm_shares(
        &mut self,
        preproc: &Preprocess<BlsFr>,
        share_comms: &Vec<Vec<PedCommitment<Bls12_381>>>,
        mpc_cfg: MPCConfig,
    ) -> Result<Vec<PedCommitment<Bls12_381>>, MPCError> {
        let _comms = batch_interpolate_shares_exponent(preproc, share_comms, mpc_cfg)?;
        self.output_comms.extend(_comms.clone());
        Ok(_comms)
    }

    /// Combine shares to a total output PEC commitment
    pub fn combine_pec_output_comm(
        &mut self,
        preproc: &Preprocess<BlsFr>,
        share_comms: &Vec<Vec<LabeledCommitment<KGZCommitment<Bls12_381>>>>,
        mpc_cfg: MPCConfig,
    ) -> Result<Vec<LabeledCommitment<KGZCommitment<Bls12_381>>>, MPCError> {
        let _comms = pec_batch_interpolate_shares_exponent(preproc, share_comms, mpc_cfg)?;
        self.pec_output_comms.extend(_comms.clone());
        Ok(_comms)
    }
}
