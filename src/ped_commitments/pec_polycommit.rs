use algebra_core;
use algebra_core::curves::AffineCurve;
use algebra_core::curves::ProjectiveCurve;
use algebra_core::One;
/// A Hacky implementation for Lagrange polycommits
use algebra_core::PairingEngine;
use algebra_core::Zero;
use core::marker::PhantomData;
pub use ff_fft::DensePolynomial as Polynomial;
use ff_fft::EvaluationDomain;
use poly_commit::kzg10::Commitment as KGZNativeCommitment;
use poly_commit::marlin_kzg10::Commitment as KGZCommitment;
use poly_commit::marlin_kzg10::CommitterKey;
use poly_commit::marlin_kzg10::MarlinKZG10;
use poly_commit::LabeledCommitment;
use poly_commit::LabeledPolynomial;
use poly_commit::PolynomialCommitment;
use rand_core::RngCore;
use algebra_core::ToBytes;
use algebra_core::to_bytes;

use crate::rng::FiatShamirRng;
use digest::Digest;

extern crate rand;
use algebra::UniformRand;
use algebra::bls12_381::Fr as blsFr;
use algebra::Bls12_381;
/// Implementation of Pederson Commitment
/// Only supports basic and required operations
pub struct PECPolycommit<E: PairingEngine> {
    _engine: PhantomData<E>,
}

/// CommiterKey for Lagrange Polynomial commitment
/// TODO: Preprocessing can improve speedup here
#[derive(Clone, Debug)]
pub struct PECCommiterKey<'srs, 'poly> {
    /// The KGZ committer key
    pub ck: &'srs CommitterKey<Bls12_381>,
    /// The lagrange polynomials
    pub lagrange_polys: Vec<LabeledPolynomial<'poly, blsFr>>,
}

impl PECPolycommit<Bls12_381> {
    /// Constructs the commiterKey for the pedersonCommitment
    pub fn setup<'srs, 'poly>(
        ck: &'srs CommitterKey<Bls12_381>,
        stmt_len: usize,
    ) -> PECCommiterKey<'srs, 'poly> {
        let domain_x: EvaluationDomain<blsFr> = EvaluationDomain::new(stmt_len).unwrap();
        let vanish_x: Polynomial<blsFr> = domain_x.vanishing_polynomial().into();

        let mut lagrange_polys = vec![];
        for (i, elem) in domain_x.elements().enumerate() {
            let root_poly = Polynomial::from_coefficients_vec(vec![-elem, blsFr::one()]);
            let lagrange_poly = &vanish_x / &root_poly;
            let eval_at_elem = lagrange_poly.evaluate(elem);
            let lagrange_poly = Polynomial::from_coefficients_vec(
                lagrange_poly
                    .coeffs
                    .iter()
                    .map(|c| *c / &eval_at_elem)
                    .collect(),
            );
            assert_eq!(blsFr::one(), lagrange_poly.evaluate(elem));
            let labeled_poly =
                LabeledPolynomial::new_owned(i.to_string(), lagrange_poly, None, None);
            lagrange_polys.push(labeled_poly);
        }
        PECCommiterKey {
            ck: ck,
            lagrange_polys: lagrange_polys,
        }
    }

    /// Commit to x with randomness r using ck.
    pub fn commit<R: RngCore, D: Digest>(
        ck: &PECCommiterKey,
        x: blsFr,
        i: usize,
        zk_rng: &mut R,
    ) -> (
        Vec<LabeledCommitment<KGZCommitment<Bls12_381>>>,
        Vec<<MarlinKZG10<Bls12_381> as PolynomialCommitment<blsFr>>::Randomness>,
    ) {
        let new_poly = Polynomial::from_coefficients_vec(
            ck.lagrange_polys[i]
                .polynomial()
                .coeffs
                .iter()
                .map(|c| x * c)
                .collect(),
        );
        let labeled_poly = LabeledPolynomial::new(x.to_string(), &new_poly, None, Some(1));
        let (comm, comm_rands) = <MarlinKZG10<Bls12_381> as PolynomialCommitment::<blsFr>>::commit(
            &ck.ck,
            vec![&labeled_poly],
            Some(zk_rng),
        )
        .unwrap();
        (comm, comm_rands)
    }

    /// Commit to x with randomness r using ck.
    pub fn commit_with_rand<R: RngCore, D: Digest>(
        ck: &PECCommiterKey,
        x: blsFr,
        i: usize,
        rand: Polynomial<blsFr>,
        zk_rng: &mut R,
    ) -> (
        Vec<LabeledCommitment<KGZCommitment<Bls12_381>>>,
        Vec<<MarlinKZG10<Bls12_381> as PolynomialCommitment<blsFr>>::Randomness>,
        blsFr,
    ) {
        let new_poly = Polynomial::from_coefficients_vec(
            ck.lagrange_polys[i]
                .polynomial()
                .coeffs
                .iter()
                .map(|c| x * c)
                .collect(),
        );
        let labeled_poly = LabeledPolynomial::new(x.to_string(), &new_poly, None, Some(1));
        let (comm, comm_rands) =
            <MarlinKZG10<Bls12_381>>::commit_with_rand(&ck.ck, vec![&labeled_poly], rand.clone(), Some(zk_rng))
                .unwrap();
        // Create a ZKP proof of multiplication
        // Step 1: Sample random k
        // TODO: Change this value to a random poly
        let k = blsFr::rand(zk_rng);
        let new_poly3 = Polynomial::from_coefficients_vec(
            ck.lagrange_polys[i]
                .polynomial()
                .coeffs
                .iter()
                .map(|c| k * c)
                .collect(),
        );
        let labeled_poly2 = LabeledPolynomial::new(x.to_string(), &new_poly3, None, None);
        let (comm_k, comm_k_rands) =
            <MarlinKZG10<Bls12_381>>::commit(&ck.ck, vec![&labeled_poly2], Some(zk_rng))
                .unwrap();
        
        //Challenge e. Change to Fiat Shamir
        let mut fs_rng = FiatShamirRng::<D>::from_seed(
            &to_bytes![comm_k].unwrap(),
        );

        let e = blsFr::rand(&mut fs_rng);
        use std::ops::Mul;
        let s = k + &x.mul(&e);
        // Add a mul for r too, this is not completely zk
        let new_poly3 = Polynomial::from_coefficients_vec(
            ck.lagrange_polys[i]
                .polynomial()
                .coeffs
                .iter()
                .map(|c| s * c)
                .collect(),
        );
        let rand_poly3 = Polynomial::from_coefficients_vec(
            rand.clone()
                .coeffs
                .iter()
                .map(|c| e * c)
                .collect(),
        );
        let labeled_poly3 = LabeledPolynomial::new(s.to_string(), &new_poly3, None, Some(1));
        // let k_blinding_poly = ;
        let (comm_s, comm_s_rands) =
            <MarlinKZG10<Bls12_381>>::commit_with_rand(&ck.ck, vec![&labeled_poly3], rand_poly3,Some(zk_rng))
                .unwrap();
        let mut combined_comm = <Bls12_381 as PairingEngine>::G1Projective::zero();
        combined_comm += &comm[0].commitment().comm.0.into_projective().mul(e);
        combined_comm += &comm_k[0].commitment().comm.0.into_projective();
        assert_eq!(comm_s[0].commitment().comm.0.into_projective(), combined_comm);
        // let r_s = comm_rands[0].clone() + &comm_k_rands[0];

        (comm, comm_rands, s)
    }

    /// PEC interpolate method
    pub fn pec_interpolate(
        label: String,
        eval_comms: Vec<LabeledCommitment<KGZCommitment<Bls12_381>>>,
    ) -> LabeledCommitment<KGZCommitment<Bls12_381>> {
        let mut combined_comm = <Bls12_381 as PairingEngine>::G1Projective::zero();
        for comm in eval_comms {
            combined_comm += &comm.commitment().comm.0.into_projective();
        }
        LabeledCommitment::new(
            label,
            KGZCommitment {
                comm: KGZNativeCommitment(combined_comm.into_affine()),
                shifted_comm: None,
            },
            None,
        )
    }

    /// Commit to 1 with randomness 0. required for internal operations.
    pub fn commit_to_one(ck: &PECCommiterKey) -> LabeledCommitment<KGZCommitment<Bls12_381>> {
        let new_poly = ck.lagrange_polys[0].clone();
        let labeled_poly = LabeledPolynomial::new("1".to_owned(), &new_poly, None, None);
        let (comm, _comm_rands) = <MarlinKZG10<Bls12_381> as PolynomialCommitment<blsFr>>::commit(
            &ck.ck,
            vec![&labeled_poly],
            None,
        )
        .unwrap();
        comm[0].clone()
    }
}
