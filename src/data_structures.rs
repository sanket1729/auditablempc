use crate::ahp::indexer::*;
use crate::ahp::mpc_prover::ProverMsg;
use crate::Vec;
use algebra_core::PairingEngine;
use algebra_core::PrimeField;
use algebra_core::Zero;
use core::marker::PhantomData;
use poly_commit::data_structures::PCCommitment;
use poly_commit::marlin_kzg10::Commitment as KGZCommitment;
use poly_commit::marlin_kzg10::MarlinKZG10;
use poly_commit::LabeledCommitment;
use poly_commit::PolynomialCommitment;
use r1cs_core::ConstraintSynthesizer;

use crate::mpc::MPCConfig;
use crate::ped_commitments::pederson::Commitment as PedCommitment;

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */
/// The universal public parameters for the argument system.
pub type UniversalSRS<E, F> = <MarlinKZG10<E> as PolynomialCommitment<F>>::UniversalParams;

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */

/// Verification key for a specific index (i.e., R1CS matrices).
pub struct IndexVerifierKey<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> {
    /// Stores information about the size of the index, as well as its field of
    /// definition.
    pub index_info: IndexInfo<E::Fr, C>,
    /// Commitments to the indexed polynomials.
    pub index_comms: Vec<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>,
    /// The verifier key for this index, trimmed from the universal SRS.
    pub verifier_key: <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::VerifierKey,
}

impl<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> algebra_core::ToBytes
    for IndexVerifierKey<E, C>
{
    fn write<W: algebra_core::io::Write>(&self, mut w: W) -> algebra_core::io::Result<()> {
        self.index_info.write(&mut w)?;
        self.index_comms.write(&mut w)
    }
}

impl<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> Clone for IndexVerifierKey<E, C> {
    fn clone(&self) -> Self {
        Self {
            index_comms: self.index_comms.clone(),
            index_info: self.index_info.clone(),
            verifier_key: self.verifier_key.clone(),
        }
    }
}

impl<E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> IndexVerifierKey<E, C> {
    /// Iterate over the commitments to indexed polynomials in `self`.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = &<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment> {
        self.index_comms.iter()
    }
}

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */

/// Proving key for a specific index (i.e., R1CS matrices).
pub struct IndexProverKey<'a, E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> {
    /// The index verifier key.
    pub index_vk: IndexVerifierKey<E, C>,
    /// The randomness for the index polynomial commitments.
    pub index_comm_rands: Vec<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Randomness>,
    /// The index itself.
    pub index: Index<'a, E::Fr, C>,
    /// The committer key for this index, trimmed from the universal SRS.
    pub committer_key: <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::CommitterKey,
}

impl<'a, E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> Clone for IndexProverKey<'a, E, C>
where
    <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment: Clone,
{
    fn clone(&self) -> Self {
        Self {
            index_vk: self.index_vk.clone(),
            index_comm_rands: self.index_comm_rands.clone(),
            index: self.index.clone(),
            committer_key: self.committer_key.clone(),
        }
    }
}

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */

/// A zkSNARK proof.
pub struct Proof<F: PrimeField, E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> {
    /// Commitments to the polynomials produced by the AHP prover.
    pub commitments: Vec<Vec<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>>,
    /// Hiding input
    pub stmt_commitments: KGZCommitment<E>,
    /// Evaluations of these commited polynomials.
    pub evaluations: Vec<F>,
    /// The field elements sent by the prover.
    pub prover_messages: Vec<ProverMsg<E::Fr>>,
    /// An evaluation proof from the polynomial commitment.
    pub pc_proof: <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::BatchProof,
    #[doc(hidden)]
    constraint_system: PhantomData<C>,
}

impl<F: PrimeField, E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> Proof<F, E, C> {
    /// Construct a new proof.
    pub fn new(
        commitments: Vec<Vec<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>>,
        stmt_commitments: KGZCommitment<E>,
        evaluations: Vec<F>,
        prover_messages: Vec<ProverMsg<E::Fr>>,
        pc_proof: <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::BatchProof,
    ) -> Self {
        Self {
            commitments,
            stmt_commitments,
            evaluations,
            prover_messages,
            pc_proof,
            constraint_system: PhantomData,
        }
    }

    /// Prints information about the size of the proof.
    pub fn print_size_info(&self) {
        let size_of_fe_in_bytes = F::zero().into_repr().as_ref().len() * 8;
        let mut num_comms_without_degree_bounds = 0;
        let mut num_comms_with_degree_bounds = 0;
        let mut size_bytes_comms_without_degree_bounds = 0;
        let mut size_bytes_comms_with_degree_bounds = 0;
        let mut num_pederson_comm = 0;
        let mut size_bytes_pederson_comm = 0;
        for c in self.commitments.iter().flat_map(|c| c) {
            if !c.has_degree_bound() {
                num_comms_without_degree_bounds += 1;
                size_bytes_comms_without_degree_bounds += c.size_in_bytes();
            } else {
                num_comms_with_degree_bounds += 1;
                size_bytes_comms_with_degree_bounds += c.size_in_bytes();
            }
        }

        // for comm in &self.stmt_commitments {
        num_pederson_comm += 1;
        size_bytes_pederson_comm += self.stmt_commitments.size_in_bytes();
        // }

        let num_evals = self.evaluations.len();
        let evals_size_in_bytes = num_evals * size_of_fe_in_bytes;
        let num_prover_messages: usize = self
            .prover_messages
            .iter()
            .map(|v| v.field_elements.len())
            .sum();
        let prover_msg_size_in_bytes = num_prover_messages * size_of_fe_in_bytes;
        let arg_size = size_bytes_comms_with_degree_bounds
            + size_bytes_comms_without_degree_bounds
            + prover_msg_size_in_bytes
            + evals_size_in_bytes
            + size_bytes_pederson_comm;
        let stats = format!(
            "Argument size in bytes: {}\n\n\
             Number of commitments without degree bounds: {}\n\
             Size (in bytes) of commitments without degree bounds: {}\n\
             Number of commitments with degree bounds: {}\n\
             Size (in bytes) of commitments with degree bounds: {}\n\n\
             Number of evaluations: {}\n\
             Size (in bytes) of evaluations: {}\n\n\
             Number of field elements in prover messages: {}\n\
             Size (in bytes) of prover message: {}\n\
             Number of Pederson Commitments: {}\n\
             Size (in bytes) of Pederson Commitments: {}\n",
            arg_size,
            num_comms_without_degree_bounds,
            size_bytes_comms_without_degree_bounds,
            num_comms_with_degree_bounds,
            size_bytes_comms_with_degree_bounds,
            num_evals,
            evals_size_in_bytes,
            num_prover_messages,
            prover_msg_size_in_bytes,
            num_pederson_comm,
            size_bytes_pederson_comm,
        );
        add_to_trace!(|| "Statistics about proof", || stats);
    }
}

/// Gets the size of communication in init round: Per party
pub fn pec_round_comm_size<E: PairingEngine>(
    share_comm_vec: &Vec<
        LabeledCommitment<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>,
    >,
) -> usize {
    // let size_of_fe_in_bytes = E::Fr::zero().into_repr().as_ref().len() * 8;
    let mut num_comms_without_degree_bounds = 0;
    let mut num_comms_with_degree_bounds = 0;
    let mut size_bytes_comms_without_degree_bounds = 0;
    let mut size_bytes_comms_with_degree_bounds = 0;
    // For simplicity assume that the first share is local; this should not
    // affect the calcualation for sizes
    for comm in share_comm_vec[1..].iter() {
        let c = comm.commitment();
        if !c.has_degree_bound() {
            num_comms_without_degree_bounds += 1;
            size_bytes_comms_without_degree_bounds += c.size_in_bytes();
        } else {
            num_comms_with_degree_bounds += 1;
            size_bytes_comms_with_degree_bounds += c.size_in_bytes();
        }
    }
    let total_size = size_bytes_comms_without_degree_bounds + size_bytes_comms_with_degree_bounds;
    let stats = format!(
        "Init Round Total Communication:{}\n\
        Init round Number of commitments without degree bound:{}\n\
        Init round Size of Commitments without degree bound:{}\n\
        Init round Number of Commitments with degree bound:{}\n\
        Init round Size of commitments with degree bound:{}\n",
        total_size,
        num_comms_without_degree_bounds,
        size_bytes_comms_without_degree_bounds,
        num_comms_with_degree_bounds,
        size_bytes_comms_with_degree_bounds,
    );
    add_to_trace!(|| "Stats for Init round communication per party", || stats);
    total_size
}

/// Get the communication cost the init round.
pub fn pederson_vec_size<E: PairingEngine>(ped_vec: &Vec<PedCommitment<E>>) -> usize {
    let mut num_pederson_comm = 0;
    let mut size_bytes_pederson_comm = 0;

    for comm in ped_vec {
        num_pederson_comm += 1;
        size_bytes_pederson_comm += comm.size_in_bytes();
    }
    let stats = format!(
        "Init Round Total Communication:{}\n\
        Init Round Number of pederson Commitments:{}\n\
        Init Round Size in bytes of pederson commitments:{}\n",
        size_bytes_pederson_comm, num_pederson_comm, size_bytes_pederson_comm,
    );
    add_to_trace!(|| "Statistics about Init Round", || stats);
    size_bytes_pederson_comm
}

/// Gets the size of communication in first round: Per party
pub fn first_round_comm_size<E: PairingEngine>(
    share_comm_vec: &Vec<
        Vec<LabeledCommitment<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>>,
    >,
) -> usize {
    // let size_of_fe_in_bytes = E::Fr::zero().into_repr().as_ref().len() * 8;
    let mut num_comms_without_degree_bounds = 0;
    let mut num_comms_with_degree_bounds = 0;
    let mut size_bytes_comms_without_degree_bounds = 0;
    let mut size_bytes_comms_with_degree_bounds = 0;
    // For simplicity assume that the first share is local; this should not
    // affect the calcualation for sizes
    for comms in share_comm_vec[1..].iter() {
        for comm in comms {
            let c = comm.commitment();
            if !c.has_degree_bound() {
                num_comms_without_degree_bounds += 1;
                size_bytes_comms_without_degree_bounds += c.size_in_bytes();
            } else {
                num_comms_with_degree_bounds += 1;
                size_bytes_comms_with_degree_bounds += c.size_in_bytes();
            }
        }
    }
    let total_size = size_bytes_comms_without_degree_bounds + size_bytes_comms_with_degree_bounds;
    let stats = format!(
        "First round  Total shares size in bytes:{}\n\
        First round Number of commitments without degree bound:{}\n\
        First round Size of Commitments without degree bound:{}\n\
        First round Number of Commitments with degree bound:{}\n\
        First round Size of commitments with degree bound:{}\n",
        total_size,
        num_comms_without_degree_bounds,
        size_bytes_comms_without_degree_bounds,
        num_comms_with_degree_bounds,
        size_bytes_comms_with_degree_bounds,
    );
    add_to_trace!(|| "Stats for first round communication per party", || stats);
    total_size
}

/// Gets the size of communication in second round
pub fn second_round_comm_size<E: PairingEngine>(
    share_comm_vec: &Vec<
        Vec<LabeledCommitment<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>>,
    >,
    num_evals: usize,
    mpc_config: MPCConfig,
) -> usize {
    // Second round communication is polynomials plus the evaluations
    // of the secret and statement polynomials at Beta1
    let size_of_fe_in_bytes = E::Fr::zero().into_repr().as_ref().len() * 8;
    let mut num_comms_without_degree_bounds = 0;
    let mut num_comms_with_degree_bounds = 0;
    let mut size_bytes_comms_without_degree_bounds = 0;
    let mut size_bytes_comms_with_degree_bounds = 0;
    // For simplicity assume that the first share is local; this should not
    // affect the calcualation for sizes

    // The proof is just a single polycommit G1Affline point and hiding poly eval
    let prf_size = share_comm_vec[0][0].commitment().size_in_bytes() + size_of_fe_in_bytes;
    let total_prf_size = prf_size * (mpc_config.num_parties - 1);
    for comms in share_comm_vec[1..].iter() {
        for comm in comms {
            let c = comm.commitment();
            if !c.has_degree_bound() {
                num_comms_without_degree_bounds += 1;
                size_bytes_comms_without_degree_bounds += c.size_in_bytes();
            } else {
                num_comms_with_degree_bounds += 1;
                size_bytes_comms_with_degree_bounds += c.size_in_bytes();
            }
        }
    }

    // Again, -1 because one share is local
    let total_eval_size = num_evals * (mpc_config.num_parties - 1) * size_of_fe_in_bytes;
    let total_comm_size = total_eval_size
        + size_bytes_comms_with_degree_bounds
        + size_bytes_comms_without_degree_bounds
        + total_prf_size;

    let stats = format!(
        "Second Round Total shares in bytes:{}\n\
        Second Round Number of commitments without degree bound:{}\n\
        Second Round Size of Commitments without degree bound:{}\n\
        Second Round Number of Commitments with degree bound:{}\n\
        Second Round Size of commitments with degree bound:{}\n\
        Second Round total number of evaluations:{}\n\
        Second Round Evaluations in bytes:{}\n\
        Total PC proof size:{}\n",
        total_comm_size,
        num_comms_without_degree_bounds,
        size_bytes_comms_without_degree_bounds,
        num_comms_with_degree_bounds,
        size_bytes_comms_with_degree_bounds,
        num_evals,
        total_eval_size,
        total_prf_size,
    );
    add_to_trace!(|| "Stats for second round communication per party", || {
        stats
    });
    total_comm_size
}
