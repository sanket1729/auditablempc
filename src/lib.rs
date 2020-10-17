#![cfg_attr(not(feature = "std"), no_std)]

//! A crate for the Marlin preprocessing zkSNARK for R1CS.
//!
//! # Note
//!
//! Currently, Marlin only supports R1CS instances where the number of inputs
//! is the same as the number of constraints (i.e., where the constraint
//! matrices are square). Furthermore, Marlin only supports instances where the
//! public inputs are of size one less than a power of 2 (i.e., 2^n - 1).
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, private_in_public)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_mut, missing_docs)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate bench_utils;

use algebra_core::to_bytes;
use algebra_core::PairingEngine;
use algebra_core::ToBytes;
use algebra_core::UniformRand;
use core::marker::PhantomData;
use digest::Digest;
use poly_commit::marlin_kzg10::Commitment as KGZCommitment;
use poly_commit::marlin_kzg10::MarlinKZG10;
use poly_commit::Evaluations;
use poly_commit::{LabeledCommitment, PCUniversalParams, QuerySet};
use poly_commit::{LabeledPolynomial, PolynomialCommitment};
use r1cs_core::ConstraintSynthesizer;
use rand_core::RngCore;
use std::clone::Clone;
use std::collections::BTreeSet;
use std::thread::sleep;
use std::time::Duration;


use algebra::Bls12_381;
use algebra::bls12_381::Fr as BlsFr;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "std")]
use std::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

#[cfg(not(feature = "std"))]
macro_rules! eprintln {
    () => {};
    ($($arg: tt)*) => {};
}

/// Implements a Fiat-Shamir based Rng that allows one to incrementally update
/// the seed based on new messages in the proof transcript.
pub mod rng;
use rng::FiatShamirRng;

mod error;
pub use error::*;

use crate::ped_commitments::pec_polycommit::PECPolycommit;

mod data_structures;
pub use data_structures::*;
/// Implements an Algebraic Holographic Proof (AHP) for the R1CS indexed relation.
pub mod ahp;
/// Auction application
pub mod auction;
/// MPC operations for combining polycommits.
pub mod mpc;
/// Pederson Commitments
pub mod ped_commitments;
use ahp::mpc_prover::{ProverMsg, ProverState};
pub use ahp::AHPForR1CS;
pub use mpc::mpc_polycommits;
use mpc::mpc_polycommits::HomomorphicPC;
use mpc::preprocessing::Preprocess;
use mpc::MPCConfig;

#[cfg(test)]
mod test;

//communication latency in ms
const COMM_LATENCY: f64 = 200.0;
//communication bandwidth in Mbps
const COMM_BANDWIDTH: f64 = 250.0;

/// The compiled argument system.
pub struct AuditableMarlin<E: PairingEngine, D: Digest>(
    #[doc(hidden)] PhantomData<E>,
    // MarlinKZG10<E>,
    #[doc(hidden)] PhantomData<D>,
);

impl<E: PairingEngine, D: Digest> AuditableMarlin<E, D> {
    /// The personalization string for this protocol. Used to personalize the
    /// Fiat-Shamir rng.
    pub const PROTOCOL_NAME: &'static [u8] = b"AUDITABLE-MARLIN-2020";

    /// Generate the universal prover and verifier keys for the
    /// argument system.
    pub fn universal_setup<R: RngCore>(
        num_constraints: usize,
        num_variables: usize,
        num_non_zero: usize,
        rng: &mut R,
    ) -> Result<UniversalSRS<E, E::Fr>, Error<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Error>>
    {
        let max_degree =
            AHPForR1CS::<E::Fr>::max_degree(num_constraints, num_variables, num_non_zero)?;
        let setup_time = start_timer!(|| {
            format!(
            "Marlin::UniversalSetup with max_degree {}, computed for a maximum of {} constraints, {} vars, {} non_zero",
            max_degree, num_constraints, num_variables, num_non_zero,
        )
        });

        let srs = MarlinKZG10::setup(max_degree, rng).map_err(Error::from_pc_err);
        end_timer!(setup_time);
        srs
    }

    /// Generate the index-specific (i.e., circuit-specific) prover and verifier
    /// keys. This is a deterministic algorithm that anyone can rerun.
    pub fn index<C: ConstraintSynthesizer<E::Fr>>(
        srs: &UniversalSRS<E, E::Fr>,
        c: C,
    ) -> Result<
        (IndexProverKey<E, C>, IndexVerifierKey<E, C>),
        Error<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Error>,
    > {
        let index_time = start_timer!(|| "Marlin::Index");

        // TODO: Add check that c is in the correct mode.
        let index = AHPForR1CS::index(c)?;
        if srs.max_degree() < index.max_degree() {
            Err(Error::IndexTooLarge)?;
        }

        let coeff_support = AHPForR1CS::get_degree_bounds::<C>(&index.index_info);
        let (committer_key, verifier_key) =
            MarlinKZG10::trim(srs, index.max_degree(), Some(&coeff_support))
                .map_err(Error::from_pc_err)?;
        let commit_time = start_timer!(|| "Commit to index polynomials");
        let (index_comms, index_comm_rands): (_, _) =
            MarlinKZG10::commit(&committer_key, index.iter(), None).map_err(Error::from_pc_err)?;
        end_timer!(commit_time);

        let index_comms = index_comms
            .into_iter()
            .map(|c| c.commitment().clone())
            .collect();
        let index_vk = IndexVerifierKey {
            index_info: index.index_info,
            index_comms,
            verifier_key,
        };

        let index_pk = IndexProverKey {
            index,
            index_comm_rands,
            index_vk: index_vk.clone(),
            committer_key,
        };

        end_timer!(index_time);

        Ok((index_pk, index_vk))
    }

    /// Create a zkSNARK asserting that the constraint system is satisfied.
    /// This will be combined proof generated by all the MPC servers
    pub fn prove<C: Clone + ConstraintSynthesizer<E::Fr>, R: RngCore>(
        index_pk: &IndexProverKey<E, C>,
        statement_comms: KGZCommitment<E>,
        rand_assigments: &Vec<Vec<E::Fr>>,
        preproc: &Preprocess<E::Fr>,
        mpc_config: MPCConfig,
        c: Vec<C>,
        zk_rng: &mut R,
    ) -> Result<Proof<E::Fr, E, C>, Error<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Error>>
    {
        let total_prover_time = start_timer!(|| "Marlin::Prover");
        // Add check that c is in the correct mode.

        let mut mpc_server_states: Vec<ProverState<E::Fr, C>> = vec![];
        for i in 0..mpc_config.num_parties {
            let prover_init_time = start_timer!(|| "Initize prover for all servers");
            let rand_vec = rand_assigments[i].clone();
            let prover_init_state =
                AHPForR1CS::prover_init(&index_pk.index, c[i].clone(), rand_vec)?;
            mpc_server_states.push(prover_init_state);
            end_timer!(prover_init_time);
        }
        //TODO: Add public input commitment to the randomness here
        let mut fs_rng = FiatShamirRng::<D>::from_seed(
            &to_bytes![&Self::PROTOCOL_NAME, &index_pk.index_vk, statement_comms].unwrap(),
        );
        // --------------------------------------------------------------------
        // First round

        let mut first_oracle_comm_shares = vec![];
        let mut first_oracle_comm_rands_shares = vec![];
        let mut first_oracles_shares = vec![];
        let mut first_stmt_oracles_shares = vec![];
        // let mut first_stmt_comm_shares = vec![];
        let mpc_first_round_msg = ProverMsg::new(); //There is no prover message in the first round.
        for i in 0..mpc_config.num_parties {
            let first_round_all_comm_time = start_timer!(|| "Committing to first round polys");
            let (
                _prover_msg_share,
                prover_first_oracles_share,
                stmt_oracles_share,
                mpc_prover_first_state,
            ) = AHPForR1CS::prover_first_round(mpc_server_states[i].clone(), zk_rng)?;
            mpc_server_states[i] = mpc_prover_first_state;
            let (mut first_comm_share, mut first_comm_rands_share) =
                <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::commit(
                    &index_pk.committer_key,
                    prover_first_oracles_share.iter(),
                    Some(zk_rng),
                )
                .map_err(Error::from_pc_err)?;
            let (stmt_comm_share, stmt_comm_rands_share) = <MarlinKZG10<E>>::commit_with_rand(
                &index_pk.committer_key,
                stmt_oracles_share.iter(),
                stmt_oracles_share.r.polynomial().clone(),
                Some(zk_rng),
            )
            .map_err(Error::from_pc_err)?;
            first_comm_share.extend(stmt_comm_share);
            first_comm_rands_share.extend(stmt_comm_rands_share);

            first_oracle_comm_shares.push(first_comm_share);
            first_oracle_comm_rands_shares.push(first_comm_rands_share);

            first_oracles_shares.push(prover_first_oracles_share);
            first_stmt_oracles_shares.push(stmt_oracles_share);

            // first_stmt_comm_shares.push(stmt_comm_share);
            end_timer!(first_round_all_comm_time);
        }

        // At this point we have all the partial commitments
        // We assume instant communication between the parties and
        // commit to the sent instantly.

        // For benchmark results, we report an additional 200ms delay.
        // This is commented for regular use
        // ----- ONLY for benching and simulating delays.
        let first_round_bytes_sent = first_round_comm_size(&first_oracle_comm_shares);
        let first_communication_time = start_timer!(|| "First Round communication");
        // In nanosec
        let total_delay = 10.0_f64.powi(6i32) * COMM_LATENCY
            + ((first_round_bytes_sent * 8) as f64) / (COMM_BANDWIDTH * 10.0_f64.powi(6i32))
                * 10.0_f64.powi(9i32);
        let sec_delay = (total_delay / (10u64.pow(9u32) as f64)) as u64;
        let nano_delay = ((total_delay as u64) - sec_delay * 10u64.pow(9u32)) as u32;
        sleep(Duration::new(sec_delay, nano_delay));
        // Sleep additionally for the Communication transfer delay
        end_timer!(first_communication_time);
        //-----

        let first_round_comm_combine_time = start_timer!(|| "Combining partial commitments");

        let first_mpc_comms = <MarlinKZG10<E> as HomomorphicPC<E::Fr, E>>::mpc_pc_commit(
            &preproc,
            first_oracle_comm_shares,
        )?;

        //Sanity check that the reconstruction works!
        // ---------------------------------------
        // let final_stmt_comms = <MarlinKZG10<E> as HomomorphicPC<E::Fr, E>>::mpc_pc_commit(
        //     &preproc,
        //     first_stmt_comm_shares,
        // )?;

        // assert_eq!(statement_comms.commitment(), &final_stmt_comms[0]);
        // ----------------------------------------
        // first_mpc_comms.push(statement_comms.commitment().clone());

        fs_rng.absorb(&to_bytes![first_mpc_comms, mpc_first_round_msg].unwrap());
        let (verifier_first_msg, verifier_state) =
            AHPForR1CS::verifier_first_round(index_pk.index_vk.index_info, &mut fs_rng)?;

        end_timer!(first_round_comm_combine_time);
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Second round

        let mut second_oracle_comm_shares = vec![];
        let mut second_oracle_comm_rands_shares = vec![];
        let mut second_oracles_shares = vec![];
        let mpc_second_round_msg = ProverMsg::new(); //There is no prover message in the first round.
        for i in 0..mpc_config.num_parties {
            let second_round_all_comm_time = start_timer!(|| "Committing to second round polys");
            let (_prover_msg_share, prover_second_oracles_share, mpc_prover_second_state) =
                AHPForR1CS::prover_second_round(
                    &verifier_first_msg,
                    mpc_server_states[i].clone(),
                    zk_rng,
                );
            mpc_server_states[i] = mpc_prover_second_state;
            let (second_comm_share, second_comm_rands_share) =
                <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::commit(
                    &index_pk.committer_key,
                    prover_second_oracles_share.iter(),
                    Some(zk_rng),
                )
                .map_err(Error::from_pc_err)?;
            second_oracle_comm_shares.push(second_comm_share);
            second_oracle_comm_rands_shares.push(second_comm_rands_share);
            second_oracles_shares.push(prover_second_oracles_share);
            end_timer!(second_round_all_comm_time);
        }

        // ------------- ONLY for benching and simulating delays.
        let num_secret_evals = AHPForR1CS::<E::Fr>::SECRET_SHARED_POLYNOMIALS.len();
        let second_round_bytes_sent =
            second_round_comm_size(&second_oracle_comm_shares, num_secret_evals, mpc_config);
        let second_communication_time = start_timer!(|| "Second Round communication");
        // In nanosec
        let total_delay = 10.0_f64.powi(6i32) * COMM_LATENCY
            + ((second_round_bytes_sent * 8) as f64) / (COMM_BANDWIDTH * 10.0_f64.powi(6i32))
                * 10.0_f64.powi(9i32);
        let sec_delay = (total_delay / (10u64.pow(9u32) as f64)) as u64;
        let nano_delay = (total_delay as u64) - sec_delay * 10u64.pow(9u32);
        sleep(Duration::new(sec_delay, nano_delay as u32));
        end_timer!(second_communication_time);
        //----------------------------------

        let second_round_combine_time = start_timer!(|| "Second Round Combine time");
        let second_mpc_comms = <MarlinKZG10<E> as HomomorphicPC<E::Fr, E>>::mpc_pc_commit(
            &preproc,
            second_oracle_comm_shares,
        )?;
        end_timer!(second_round_combine_time);

        fs_rng.absorb(&to_bytes![second_mpc_comms, mpc_second_round_msg].unwrap());

        let (verifier_second_msg, verifier_state) =
            AHPForR1CS::verifier_second_round(verifier_state, &mut fs_rng);
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Third round
        // The states from third round onwards don't depend on any secret inputs
        // So, we can simply set this to the states of any servers.
        let prover_state = mpc_server_states[0].clone();
        let (prover_third_msg, prover_third_oracles, prover_state) =
            AHPForR1CS::prover_third_round(&verifier_second_msg, prover_state, zk_rng);

        let third_round_comm_time = start_timer!(|| "Committing to third round polys");
        let (third_comms, third_comm_rands) =
            <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::commit(
                &index_pk.committer_key,
                prover_third_oracles.iter(),
                Some(zk_rng),
            )
            .map_err(Error::from_pc_err)?;
        end_timer!(third_round_comm_time);

        fs_rng.absorb(&to_bytes![third_comms, prover_third_msg].unwrap());

        let (verifier_third_msg, verifier_state) =
            AHPForR1CS::verifier_third_round(verifier_state, &mut fs_rng);
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Fourth round
        let (prover_fourth_msg, prover_fourth_oracles) =
            AHPForR1CS::prover_fourth_round(&verifier_third_msg, prover_state, zk_rng)?;

        let fourth_round_comm_time = start_timer!(|| "Committing to fourth round polys");
        let (fourth_comms, fourth_comm_rands) =
            <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::commit(
                &index_pk.committer_key,
                prover_fourth_oracles.iter(),
                Some(zk_rng),
            )
            .map_err(Error::from_pc_err)?;
        end_timer!(fourth_round_comm_time);

        fs_rng.absorb(&to_bytes![fourth_comms, prover_fourth_msg].unwrap());
        let verifier_state = AHPForR1CS::verifier_fourth_round(verifier_state, &mut fs_rng);
        // --------------------------------------------------------------------
        // Gather secret shared polynomials into a vector
        let pc_proof_init_time = start_timer!(|| "PC proof init time");
        let secret_shared_polys: Vec<Vec<&LabeledPolynomial<E::Fr>>> = first_oracles_shares
            .iter()
            .zip(first_stmt_oracles_shares.iter())
            .zip(second_oracles_shares.iter())
            .map(|((f, stmt), s)| {
                let mut res = f.iter().collect::<Vec<&LabeledPolynomial<E::Fr>>>();
                res.extend(stmt.iter().collect::<Vec<&LabeledPolynomial<E::Fr>>>());
                res.extend(s.iter().collect::<Vec<&LabeledPolynomial<E::Fr>>>());
                res
            })
            .collect();

        // Gather public prover polynomials in one vector.
        let public_polynomials: Vec<_> = index_pk
            .index
            .iter()
            .chain(prover_third_oracles.iter())
            .chain(prover_fourth_oracles.iter())
            .collect();

        // Gather public commitments in one vector.
        let commitments: Vec<_> = vec![
            first_mpc_comms,
            second_mpc_comms,
            third_comms
                .into_iter()
                .map(|p| p.commitment().clone())
                .collect(),
            fourth_comms
                .into_iter()
                .map(|p| p.commitment().clone())
                .collect(),
        ];

        // Gather the secret shared commitments randomness into a vector
        let mut comm_rands_shares = first_oracle_comm_rands_shares;
        for i in 0..mpc_config.num_parties {
            comm_rands_shares[i].extend(second_oracle_comm_rands_shares[i].clone());
        }

        // Gather commitment randomness together.
        let comm_rands: Vec<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Randomness> = index_pk
            .index_comm_rands
            .clone()
            .into_iter()
            .chain(third_comm_rands)
            .chain(fourth_comm_rands)
            .collect();

        // Compute the AHP verifier's query set.
        let (query_set, _) = AHPForR1CS::verifier_query_set(verifier_state, &mut fs_rng);

        end_timer!(pc_proof_init_time);
        let eval_time = start_timer!(|| "Evaluating polynomials over query set");
        let mut evaluations_frm_oracles = Vec::new();
        let mut eval_pub = Vec::new();
        let mut eval_priv = Vec::new();
        let mut query_set_secret = QuerySet::<E::Fr>::new();
        let mut query_set_public = QuerySet::<E::Fr>::new();
        for (label, point) in &query_set {
            if let Some(idx) = AHPForR1CS::<E::Fr>::SECRET_SHARED_POLYNOMIALS
                .iter()
                .position(|x| x == label)
            {
                let poly_shares: Vec<&LabeledPolynomial<E::Fr>> =
                    secret_shared_polys.iter().map(|v| v[idx]).collect();
                let val = <MarlinKZG10<E> as HomomorphicPC<E::Fr, E>>::evaluate(
                    &poly_shares,
                    &preproc,
                    *point,
                )?;
                evaluations_frm_oracles.push(val);
                query_set_secret.insert((label, *point));
                eval_priv.push(val)
            } else {
                let polynomial = public_polynomials
                    .iter()
                    .find(|p| &p.label() == label)
                    .unwrap();
                query_set_public.insert((label, *point));
                let v = polynomial.evaluate(*point);
                evaluations_frm_oracles.push(v);
                eval_pub.push(v);
            }
        }
        end_timer!(eval_time);

        fs_rng.absorb(&evaluations_frm_oracles);
        let opening_challenge: E::Fr = u128::rand(&mut fs_rng).into();

        let mpc_proof = <MarlinKZG10<E> as HomomorphicPC<E::Fr, E>>::mpc_batch_open(
            &index_pk.committer_key,
            &preproc,
            &secret_shared_polys,
            &query_set_secret,
            opening_challenge,
            comm_rands_shares,
        )
        .unwrap(); //FIXME: Make errors better

        // Proofs done at all servers
        let pc_proof_creation_time = start_timer!(|| "PC Proof creation time");

        let pc_proof = <MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::batch_open(
            &index_pk.committer_key,
            public_polynomials,
            &query_set_public,
            opening_challenge,
            &comm_rands,
        )
        .map_err(Error::from_pc_err)?;

        let mut query_to_labels_map = BTreeMap::new();
        for (label, point) in query_set.iter() {
            let labels = query_to_labels_map.entry(point).or_insert(BTreeSet::new());
            labels.insert(label);
        }
        let mut prf = vec![];
        let mut pc_prf_index: usize = 0;
        for (_query, labels) in query_to_labels_map.into_iter() {
            // assert!(labels.len() > 0);
            let label = labels
                .iter()
                .next()
                .expect("Labels corresponding to a point can't be empty");
            if AHPForR1CS::<E::Fr>::SECRET_SHARED_POLYNOMIALS.contains(label) {
                prf.push(mpc_proof[0]);
            } else if AHPForR1CS::<E::Fr>::BETA2_POLYS.contains(label) {
                prf.push(pc_proof[pc_prf_index]);
                pc_prf_index += 1
            } else if AHPForR1CS::<E::Fr>::BETA3_POLYS.contains(label) {
                prf.push(pc_proof[pc_prf_index]);
                pc_prf_index += 1
            } else {
                unreachable!();
            }
        }

        // Gather prover messages together.
        let prover_messages = vec![
            mpc_first_round_msg,
            mpc_second_round_msg,
            prover_third_msg,
            prover_fourth_msg,
        ];
        end_timer!(pc_proof_creation_time);
        end_timer!(total_prover_time);
        let prf = Proof::new(
            commitments,
            statement_comms,
            evaluations_frm_oracles,
            prover_messages,
            prf,
        );
        prf.print_size_info();
        Ok(prf)
    }

    /// Verify that a proof for the constrain system defined by `C` asserts that
    /// all constraints are satisfied.
    pub fn audit<C: ConstraintSynthesizer<BlsFr>, R: RngCore>(
        index_vk: &IndexVerifierKey<Bls12_381, C>,
        stmt_comms: Vec<LabeledCommitment<KGZCommitment<Bls12_381>>>,
        proof: &Proof<BlsFr, Bls12_381, C>,
        rng: &mut R,
    ) -> Result<bool, Error<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Error>> {
        let verifier_time = start_timer!(|| "Marlin::Verify");

        // Get the statement commitments
        let statement_comms = &proof.stmt_commitments;

        let mut fs_rng = FiatShamirRng::<D>::from_seed(
            &to_bytes![&Self::PROTOCOL_NAME, &index_vk, statement_comms].unwrap(),
        );
        // --------------------------------------------------------------------
        // First round

        let first_comms = &proof.commitments[0];
        fs_rng.absorb(&to_bytes![first_comms, proof.prover_messages[0]].unwrap());
        let (_, verifier_state) =
            AHPForR1CS::verifier_first_round(index_vk.index_info, &mut fs_rng)?;
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Second round
        let second_comms = &proof.commitments[1];
        fs_rng.absorb(&to_bytes![second_comms, proof.prover_messages[1]].unwrap());

        let (_, verifier_state) = AHPForR1CS::verifier_second_round(verifier_state, &mut fs_rng);
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Third round
        let third_comms = &proof.commitments[2];
        fs_rng.absorb(&to_bytes![third_comms, proof.prover_messages[2]].unwrap());

        let (_, verifier_state) = AHPForR1CS::verifier_third_round(verifier_state, &mut fs_rng);
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Fourth round
        let fourth_comms = &proof.commitments[3];
        fs_rng.absorb(&to_bytes![fourth_comms, proof.prover_messages[3]].unwrap());
        let verifier_state = AHPForR1CS::verifier_fourth_round(verifier_state, &mut fs_rng);
        // --------------------------------------------------------------------

        // Collect degree bounds for commitments. Indexed polynomials have *no*
        // degree bounds because we know the committed index polynomial has the
        // correct degree.
        let degree_bounds = vec![None; index_vk.index_comms.len()]
            .into_iter()
            .chain(AHPForR1CS::prover_first_round_degree_bounds(
                &index_vk.index_info,
            ))
            .chain(vec![None].into_iter())
            .chain(AHPForR1CS::prover_second_round_degree_bounds(
                &index_vk.index_info,
            ))
            .chain(AHPForR1CS::prover_third_round_degree_bounds(
                &index_vk.index_info,
            ))
            .chain(AHPForR1CS::prover_fourth_round_degree_bounds(
                &index_vk.index_info,
            ))
            .collect::<Vec<_>>();

        // Gather commitments in one vector.
        let commitments: Vec<_> = index_vk
            .iter()
            .chain(first_comms)
            .chain(second_comms)
            .chain(third_comms)
            .chain(fourth_comms)
            .cloned()
            .zip(&AHPForR1CS::<E::Fr>::ALL_COMMITED_POLYNOMIALS)
            .zip(degree_bounds)
            .map(|((comm, label), degree_bound)| {
                LabeledCommitment::new(label.to_string(), comm, degree_bound)
            })
            .collect();

        let (query_set, verifier_state) =
            AHPForR1CS::verifier_query_set(verifier_state, &mut fs_rng);

        fs_rng.absorb(&proof.evaluations);
        let opening_challenge: BlsFr = u128::rand(&mut fs_rng).into();

        let evaluations: Evaluations<_> = query_set
            .iter()
            .cloned()
            .zip(proof.evaluations.iter().cloned())
            .collect();

        let evaluations_are_correct = <MarlinKZG10<Bls12_381> as PolynomialCommitment<BlsFr>>::batch_check(
            &index_vk.verifier_key,
            &commitments,
            &query_set,
            &evaluations,
            &proof.pc_proof,
            opening_challenge,
            rng,
        )
        .map_err(Error::from_pc_err)?;

        // let beta1 = verifier_state.second_round_msg.unwrap().beta_1.clone();

        let ahp_verifier_accepted = AHPForR1CS::verifier_decision(
            stmt_comms.len(),
            evaluations,
            &proof.prover_messages,
            verifier_state,
        )?;
        if !ahp_verifier_accepted {
            eprintln!("AHP decision predicate not satisfied");
        }
        if !evaluations_are_correct {
            eprintln!("PC::Check failed");
        }
        //-----------------------------------------
        //Check whether the statement is correct
        let stmt_check_time = start_timer!(|| "Check the statement time");
        let actual_stmt_comm = PECPolycommit::pec_interpolate("x_poly".to_owned(), stmt_comms);

        let stmt_comms_are_correct = *actual_stmt_comm.commitment() == proof.stmt_commitments;
        if !stmt_comms_are_correct {
            eprintln!("Statement validation check failed!");
        }
        end_timer!(stmt_check_time);
        end_timer!(verifier_time, || format!(
            " AHP decision: {} and PC::Check: {} and Stmt Commitment Check: {}",
            ahp_verifier_accepted, evaluations_are_correct, stmt_comms_are_correct
        ));
        Ok(ahp_verifier_accepted && evaluations_are_correct && stmt_comms_are_correct)
    }
}
