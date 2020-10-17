use algebra_core;
/// A Hacky implementation for Pederson Commitments
/// Only meant for the use of this project.
use algebra_core::PairingEngine;
use algebra_core::ToBytes;
use algebra_core::Zero;
use algebra_core::{AffineCurve, ProjectiveCurve, UniformRand};
use core::marker::PhantomData;
use rand_core::RngCore;
/// Implementation of Pederson Commitment
/// Only supports basic and required operations
pub struct PedersonCommitment<E: PairingEngine> {
    _engine: PhantomData<E>,
}

///Pederson Commitment structure, ideally should not
/// Depend on pairing groups.
/// This implementation implements it on top of G1Affine
/// for demo purposes. Ideally, we should implement a Group
/// operation and sample generators for the group.
#[derive(Clone, Debug)]
pub struct Commitment<E: PairingEngine> {
    /// Pederson Commitment is just a point
    pub comm: E::G1Affine,
}

impl<E: PairingEngine> Commitment<E> {
    /// Get the size in bytes
    pub fn size_in_bytes(&self) -> usize {
        algebra_core::to_bytes![E::G1Affine::zero()].unwrap().len() / 2
    }
}

impl<E: PairingEngine> ToBytes for Commitment<E> {
    #[inline]
    fn write<W: algebra_core::io::Write>(&self, writer: W) -> algebra_core::io::Result<()> {
        self.comm.write(writer)
    }
}

/// CommiterKey for PedersonCommiterKey
#[derive(Clone, Debug, Copy)]
pub struct CommiterKey<E: PairingEngine> {
    ///g of pederson commitment
    pub g_point: E::G1Affine,
    ///h of pederson commitment
    pub h_point: E::G1Affine,
}

impl<E: PairingEngine> PedersonCommitment<E> {
    /// Constructs the commiterKey for the pedersonCommitment
    pub fn setup<R: RngCore>(rng: &mut R) -> CommiterKey<E> {
        CommiterKey {
            g_point: E::G1Projective::rand(rng).into_affine(),
            h_point: E::G1Projective::rand(rng).into_affine(),
        }
    }

    ///Commit to x with randomness r using ck.
    pub fn commit(ck: &CommiterKey<E>, x: E::Fr, r: E::Fr) -> Commitment<E> {
        Commitment {
            comm: (ck.g_point.mul(x) + &ck.h_point.mul(r)).into_affine(),
        }
    }
}
