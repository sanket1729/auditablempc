use super::preprocessing::Preprocess;
use super::{MPCConfig, MPCError};
use crate::ped_commitments::pederson::CommiterKey;
use crate::ped_commitments::pederson::Commitment;
use crate::ped_commitments::pederson::PedersonCommitment;
/// Interpolation related operations.
///
use algebra_core::PrimeField;
use algebra_core::Zero;
use algebra_core::{AffineCurve, PairingEngine, ProjectiveCurve};
use ff_fft::Evaluations as EvaluationsOnDomain;
use poly_commit::kzg10::Commitment as KGZNativeCommitment;
use poly_commit::marlin_kzg10::Commitment as KGZCommitment;
use poly_commit::LabeledCommitment;
/// Given n shares interpolate to find the correct polynomial if one exists.
/// If the shares are not consistent
pub fn interpolate_shares<F: PrimeField>(
    preproc: &Preprocess<F>,
    shares: Vec<F>,
    mpc_config: MPCConfig,
) -> Result<F, MPCError> {
    let r_poly = EvaluationsOnDomain::from_vec_and_domain(shares, preproc.domain_n).interpolate();
    if r_poly.degree() > mpc_config.num_corruptions {
        Err(MPCError::OptimisiticReconstructionFailure)
    } else {
        Ok(r_poly.evaluate(preproc.secret_eval_point))
    }
}

/// Evaluate in the exponent and get a commitment to the
/// evaluation of the polynomial
/// Use Domain_x here
/// TODO: Verify
pub fn evaluate_in_exponent<E: PairingEngine>(
    preproc: &Preprocess<E::Fr>,
    shares: &Vec<Commitment<E>>,
    point: E::Fr,
) -> Result<Commitment<E>, MPCError> {
    let mut combined_comm = E::G1Projective::zero();
    let point_evals = preproc.domain_x.evaluate_all_lagrange_coefficients(point);
    for (comm, lagrange_v) in shares.iter().zip(point_evals.iter().cloned()) {
        combined_comm += &comm.comm.mul(lagrange_v);
    }
    Ok(Commitment {
        comm: combined_comm.into_affine(),
    })
}

/// Interpolate in the exponent
pub fn batch_interpolate_shares_exponent<E: PairingEngine>(
    preproc: &Preprocess<E::Fr>,
    shares_comms: &Vec<Vec<Commitment<E>>>,
    mpc_config: MPCConfig,
) -> Result<Vec<Commitment<E>>, MPCError> {
    let mut combined_comms = vec![];
    for j in 0..shares_comms[0].len() {
        let mut combined_comm = E::G1Projective::zero();
        // TODO: change to robust later
        for (i, lagrange_v) in
            (0..mpc_config.num_parties).zip(preproc.lagrange_evals_at_zero.iter().cloned())
        {
            combined_comm += &shares_comms[i][j].comm.mul(lagrange_v);
        }
        combined_comms.push(Commitment {
            comm: combined_comm.into_affine(),
        });
    }
    Ok(combined_comms)
}

/// PEC batch interpolate in the exponent
pub fn pec_batch_interpolate_shares_exponent<E: PairingEngine>(
    preproc: &Preprocess<E::Fr>,
    shares_comms: &Vec<Vec<LabeledCommitment<KGZCommitment<E>>>>,
    mpc_config: MPCConfig,
) -> Result<Vec<LabeledCommitment<KGZCommitment<E>>>, MPCError> {
    let mut combined_comms = vec![];
    for j in 0..shares_comms[0].len() {
        let mut combined_comm = E::G1Projective::zero();
        // TODO: change to robust later
        for (i, lagrange_v) in
            (0..mpc_config.num_parties).zip(preproc.lagrange_evals_at_zero.iter().cloned())
        {
            combined_comm += &shares_comms[i][j].commitment().comm.0.mul(lagrange_v);
        }
        combined_comms.push(LabeledCommitment::new(
            "interpolate".to_string(),
            KGZCommitment {
                comm: KGZNativeCommitment(combined_comm.into_affine()),
                shifted_comm: None,
            },
            None,
        ));
    }
    Ok(combined_comms)
}

/// Validate evaluation in the exponent
/// Only for use in context. This function adds a dummy value at
/// the start to match the r1cs formatting.
pub fn check_eval_in_exponent<E: PairingEngine>(
    ck: &CommiterKey<E>,
    preproc: &Preprocess<E::Fr>,
    eval_point: E::Fr,
    x: E::Fr,
    r: E::Fr,
    comms: &Vec<Commitment<E>>,
) -> Result<bool, MPCError> {
    let eval_comm = evaluate_in_exponent(preproc, comms, eval_point)?;
    let expected_comm = PedersonCommitment::commit(ck, x, r);
    Ok(expected_comm.comm == eval_comm.comm)
}
