/// Preprocess all the lagrange polynoamial evaluations at 0.
use super::MPCError;
use crate::MPCConfig;
use algebra_core::PrimeField;
pub use ff_fft::DensePolynomial as Polynomial;
use ff_fft::EvaluationDomain;
use rand_core::RngCore;
///Maximum preproc shares, triples and rands
const MAX_PREPOC_SHARES: usize = 50000;
/// Preprocess all lagrange evaluations
#[derive(Clone, Debug)]
pub struct Preprocess<F: PrimeField> {
    /// Lagrange polyevals of domain_n
    pub lagrange_evals_at_zero: Vec<F>,
    /// Domain for MPC interpolation
    pub domain_n: EvaluationDomain<F>,
    /// Domain for stmt intepoolation
    /// We don't need the evaluations of zero of domain_x
    pub domain_x: EvaluationDomain<F>,
    /// The secret share evaluation point
    pub secret_eval_point: F,
    /// Random shares
    /// v[i][j] denotes the jth share of ith server
    pub rand_shares: Vec<Vec<F>>,
    /// Beaver multiplication triples
    pub triples: Vec<Vec<(F, F, F)>>,
    /// Sharings of zero
    pub shares_zero: Vec<Vec<F>>,
}

impl<F: PrimeField> Preprocess<F> {
    /// Create a new instance of lagrange polynomial
    pub fn new<R: RngCore>(cfg: MPCConfig, stmt_len: usize, rng: &mut R) -> Result<Self, MPCError> {
        let n = cfg.num_parties;
        let t = cfg.num_corruptions;
        // Must be powre of 2
        assert_eq!(n.count_ones(), 1);
        //Sample an omega from domain
        let domain_n: EvaluationDomain<F> =
            EvaluationDomain::new(n).ok_or(MPCError::FFTInstantiatingError)?;
        let eval_point = F::one() + F::one();

        let mut rand_polys = vec![];
        let mut triple_polys = vec![];
        let mut zero_polys = vec![];
        for _ in 0..MAX_PREPOC_SHARES {
            rand_polys.push(Polynomial::rand(t, rng));
            let mut zero_poly = Polynomial::rand(t, rng);
            let zero_eval = zero_poly.evaluate(eval_point);
            zero_poly.coeffs[0] = zero_poly.coeffs[0] - &zero_eval;
            zero_polys.push(zero_poly);

            let (a_poly, b_poly) = (Polynomial::rand(t, rng), Polynomial::rand(t, rng));
            let mut c_poly = Polynomial::rand(t, rng);
            let c_eval = c_poly.evaluate(eval_point);
            c_poly.coeffs[0] += a_poly
                .evaluate(eval_point)
                .mul(&b_poly.evaluate(eval_point))
                - &c_eval;
            triple_polys.push((a_poly, b_poly, c_poly));
        }

        let elems: Vec<_> = domain_n.elements().collect();
        let mut rand_shares = vec![];
        let mut all_zero_shares = vec![];
        for i in 0..n {
            let mut server_shares = vec![];
            let mut server_zero_shares = vec![];
            for j in 0..MAX_PREPOC_SHARES {
                server_shares.push(rand_polys[j].evaluate(elems[i]));
                server_zero_shares.push(zero_polys[j].evaluate(elems[i]));
            }
            rand_shares.push(server_shares);
            all_zero_shares.push(server_zero_shares);
        }

        let mut all_triple_shares = vec![];
        for i in 0..n {
            let mut server_tripleshares = vec![];
            let mut server_randshares = vec![];
            for j in 0..MAX_PREPOC_SHARES {
                server_randshares.push(rand_polys[j].evaluate(elems[i]));
                server_tripleshares.push((
                    triple_polys[j].0.evaluate(elems[i]),
                    triple_polys[j].1.evaluate(elems[i]),
                    triple_polys[j].2.evaluate(elems[i]),
                ));
            }
            rand_shares.push(server_randshares);
            all_triple_shares.push(server_tripleshares);
        }
        let domain_x: EvaluationDomain<F> =
            EvaluationDomain::new(stmt_len).ok_or(MPCError::FFTInstantiatingError)?;

        Ok(Self {
            lagrange_evals_at_zero: domain_n.evaluate_all_lagrange_coefficients(eval_point),
            domain_n: domain_n,
            domain_x: domain_x,
            secret_eval_point: eval_point,
            rand_shares: rand_shares,
            triples: all_triple_shares,
            shares_zero: all_zero_shares,
        })
    }
}

// mod marlin2{
//     // extern crate num_traits;
//     // use super::*;
//     use crate::AuditableMarlin;
//     use crate::mpc::preprocessing::Preprocess;
//     use algebra::bls12_381::Fr;
//     use algebra_core::fields::PrimeField;
//     use std::ops::Mul;
//     // use num_traits::identities::Zero;
//     // use algebra_core::biginteger::BigInteger256;
//     use algebra_core::FpParameters;
//     // use algebra_core::fields::fp_256::Fp256;
//     // use algebra_core::fields::models::fp_256::Fp256;

//     #[test]
//     fn sample(){
//         let x : Preprocess<Fr> = Preprocess::new(4).unwrap();

//         let mut _sum = x.lagrange_evals_at_zero[0] - x.lagrange_evals_at_zero[0];
//         for i in x.lagrange_evals_at_zero{
//             dbg!(i.into_repr());
//             _sum += i;
//         }
//         dbg!(_sum.into_repr());

//         for i in x.domain.elements(){
//             dbg!(i.into_repr());
//             dbg!(i.mul(i).mul(i).mul(i).into_repr());
//         }
//         dbg!(<<Fr as PrimeField>::Params as FpParameters>::MODULUS);
//     }
// }
