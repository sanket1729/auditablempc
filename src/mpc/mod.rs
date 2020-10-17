/// Interpolation operations
pub mod interpolate;
/// The additional MPC operations required for Auditable MPC
/// These are built directly on top of rust
pub mod mpc_polycommits;
/// Preprocessing values
pub mod preprocessing;

///OptimisticMPC for interpolation
#[derive(Clone, Copy, Debug)]
pub struct MPCConfig {
    ///Total number of MPC parties
    pub num_parties: usize,
    ///Total corruptions
    pub num_corruptions: usize,
}

///MPC errors
#[derive(Debug)]
pub enum MPCError {
    /// Polynomail degree too large
    FFTInstantiatingError,
    /// Share corruption
    OptimisiticReconstructionFailure,
}
