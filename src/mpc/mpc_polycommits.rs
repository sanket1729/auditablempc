/// The additional operations required for polycommit operations in MPC
use algebra_core::{AffineCurve, Field, PairingEngine, Zero};
use poly_commit::kzg10::Commitment as katePC;
use poly_commit::marlin_kzg10::Commitment as marlinPC;
use poly_commit::marlin_kzg10::MarlinKZG10;
use poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment, QuerySet};

use super::preprocessing::Preprocess;
use super::MPCError;
pub use crate::error::*;
/// Homomorphic PC trait
pub trait HomomorphicPC<F: Field, E: PairingEngine>: PolynomialCommitment<F> {
    /// Helper combine commitments homomorphically
    fn combine_homomorphic<'a>(
        coeffs_and_comms: impl IntoIterator<Item = (E::Fr, &'a marlinPC<E>)>,
    ) -> marlinPC<E>;

    /// Create a mpc Poly commmit from the *same* commitment key
    fn mpc_pc_commit(
        preproc_vandermonde: &Preprocess<E::Fr>,
        oracle_comms_shares: Vec<
            Vec<LabeledCommitment<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>>,
        >,
    ) -> Result<
        Vec<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>,
        Error<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Error>,
    >;

    ///Open a secret shared polynomial at a point. The evaluted value is opened
    /// Uses preprocessed vandermonde values
    fn evaluate(
        secret_shared_polys: &Vec<&LabeledPolynomial<E::Fr>>,
        preproc_vandermonde: &Preprocess<E::Fr>,
        point: E::Fr,
    ) -> Result<E::Fr, MPCError>;

    /// Combine secret-shared proofs from multiple servers into a single proof.
    fn mpc_pc_create_proof(
        proofs: Vec<Self::Proof>,
        preproc_vandermonde: &Preprocess<E::Fr>,
    ) -> Result<Self::Proof, MPCError>;

    /// MPC batch open proofs
    fn mpc_batch_open(
        ck: &Self::CommitterKey,
        preproc_vandermonde: &Preprocess<E::Fr>,
        secret_shared_polys: &Vec<Vec<&LabeledPolynomial<E::Fr>>>,
        query_set: &QuerySet<E::Fr>,
        opening_challenge: E::Fr,
        rands: Vec<Vec<Self::Randomness>>,
    ) -> Result<Self::BatchProof, Error<E>>;
}

impl<E: PairingEngine> HomomorphicPC<E::Fr, E> for MarlinKZG10<E> {
    fn combine_homomorphic<'a>(
        coeffs_and_comms: impl IntoIterator<Item = (E::Fr, &'a marlinPC<E>)>,
    ) -> marlinPC<E> {
        let (comm, shifted_comm) = Self::combine_commitments(coeffs_and_comms);
        let shifted_comm = if shifted_comm != E::G1Projective::zero() {
            Some(katePC(shifted_comm.into()))
        } else {
            None
        };
        marlinPC {
            comm: katePC(comm.into()),
            shifted_comm: shifted_comm,
        }
    }

    fn mpc_pc_commit(
        preproc_vandermonde: &Preprocess<E::Fr>,
        oracle_comms_shares: Vec<
            Vec<LabeledCommitment<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>>,
        >,
    ) -> Result<
        Vec<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment>,
        Error<<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Error>,
    > {
        let mut opened_commimtments = Vec::new();
        for i in 0..oracle_comms_shares[0].len() {
            let coeffs_and_comms: Vec<(
                E::Fr,
                &<MarlinKZG10<E> as PolynomialCommitment<E::Fr>>::Commitment,
            )> = preproc_vandermonde
                .lagrange_evals_at_zero
                .iter()
                .cloned()
                .zip(oracle_comms_shares.iter().map(|v| v[i].commitment()))
                .collect();
            let _comm =
                <MarlinKZG10<E> as HomomorphicPC<E::Fr, E>>::combine_homomorphic(coeffs_and_comms);
            opened_commimtments.push(_comm);
        }
        Ok(opened_commimtments)
    }

    fn evaluate(
        secret_shared_polys: &Vec<&LabeledPolynomial<E::Fr>>,
        preproc_vandermonde: &Preprocess<E::Fr>,
        point: E::Fr,
    ) -> Result<E::Fr, MPCError> {
        let local_eval_time = start_timer!(|| "Local polynomial evaluation");
        let local_evals: Vec<E::Fr> = secret_shared_polys
            .iter()
            .map(|poly| poly.evaluate(point))
            .collect();
        end_timer!(local_eval_time);

        let eval_combine_time = start_timer!(|| "Combine evaluations");
        let eval = local_evals
            .iter()
            .zip(preproc_vandermonde.lagrange_evals_at_zero.iter().cloned())
            .map(|(y, lagrange_x)| *y * &lagrange_x)
            .fold(E::Fr::zero(), |acc, x| acc + &x);
        end_timer!(eval_combine_time);
        Ok(eval)
    }

    fn mpc_pc_create_proof(
        proofs: Vec<Self::Proof>,
        preproc_vandermonde: &Preprocess<E::Fr>,
    ) -> Result<Self::Proof, MPCError> {
        let mut combined_comm = E::G1Projective::zero();
        let mut combined_blind_eval = E::Fr::zero();
        for (prf, lagrange_v) in proofs
            .iter()
            .zip(preproc_vandermonde.lagrange_evals_at_zero.iter().cloned())
        {
            combined_blind_eval += &(lagrange_v * &prf.random_v);
            combined_comm += &prf.w.mul(lagrange_v);
        }
        Ok(Self::Proof {
            w: combined_comm.into(),
            random_v: combined_blind_eval,
        })
    }

    fn mpc_batch_open<'a>(
        ck: &Self::CommitterKey,
        preproc_vandermonde: &Preprocess<E::Fr>,
        secret_shared_polys: &Vec<Vec<&LabeledPolynomial<E::Fr>>>,
        query_set: &QuerySet<E::Fr>,
        opening_challenge: E::Fr,
        rands: Vec<Vec<Self::Randomness>>,
    ) -> Result<Self::BatchProof, Error<E>> {
        let mut proofs = vec![];
        for i in 0..secret_shared_polys.len() {
            let proof_share_gen_time = start_timer!(|| "Generating local Proof shares");
            let poly_vec = secret_shared_polys[i].clone();
            let rand_vec = &rands[i];
            //FIXME: Change Error type
            let proof =
                Self::batch_open(ck, poly_vec, query_set, opening_challenge, rand_vec).unwrap();
            proofs.push(proof);
            end_timer!(proof_share_gen_time);
        }

        let proof_recon_time = start_timer!(|| "Combining MPC proofs!");
        let mut batch_proofs = vec![];
        for i in 0..proofs[0].len() {
            let _mpc_proofs: Vec<Self::Proof> = proofs.iter().map(|v| v[i]).collect();
            let batch_proof = Self::mpc_pc_create_proof(_mpc_proofs, preproc_vandermonde)?;
            batch_proofs.push(batch_proof);
        }
        end_timer!(proof_recon_time);
        Ok(batch_proofs.into())
    }
}
