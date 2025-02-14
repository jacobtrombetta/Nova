//! This module defines a collection of traits that define the behavior of a commitment engine
//! We require the commitment engine to provide a commitment to vectors with a single group element
use crate::traits::{AbsorbInROTrait, Engine, TranscriptReprTrait};
use core::{
  fmt::Debug,
  ops::{Add, Mul, MulAssign},
};
use serde::{Deserialize, Serialize};

/// A helper trait for types implementing scalar multiplication.
pub trait ScalarMul<Rhs, Output = Self>: Mul<Rhs, Output = Output> + MulAssign<Rhs> {}

impl<T, Rhs, Output> ScalarMul<Rhs, Output> for T where T: Mul<Rhs, Output = Output> + MulAssign<Rhs>
{}

/// This trait defines the behavior of the commitment
pub trait CommitmentTrait<E: Engine>:
  Clone
  + Copy
  + Debug
  + Default
  + PartialEq
  + Eq
  + Send
  + Sync
  + TranscriptReprTrait<E::GE>
  + Serialize
  + for<'de> Deserialize<'de>
  + AbsorbInROTrait<E>
  + Add<Self, Output = Self>
  + ScalarMul<E::Scalar>
{
  /// Returns the coordinate representation of the commitment
  fn to_coordinates(&self) -> (E::Base, E::Base, bool);
}

/// A trait that helps determine the length of a structure.
/// Note this does not impose any memory representation constraints on the structure.
pub trait Len {
  /// Returns the length of the structure.
  fn length(&self) -> usize;
}

/// A trait that ties different pieces of the commitment generation together
pub trait CommitmentEngineTrait<E: Engine>: Clone + Send + Sync {
  /// Holds the type of the commitment key
  /// The key should quantify its length in terms of group generators.
  type CommitmentKey: Len + Clone + Debug + Send + Sync + Serialize + for<'de> Deserialize<'de>;

  /// Holds the type of the derandomization key
  type DerandKey: Clone + Debug + Send + Sync + Serialize + for<'de> Deserialize<'de>;

  /// Holds the type of the commitment
  type Commitment: CommitmentTrait<E>;

  /// Samples a new commitment key of a specified size
  fn setup(label: &'static [u8], n: usize) -> Self::CommitmentKey;

  /// Extracts the blinding generator
  fn derand_key(ck: &Self::CommitmentKey) -> Self::DerandKey;

  /// Commits to the provided vector using the provided generators and random blind
  fn commit(ck: &Self::CommitmentKey, v: &[E::Scalar], r: &E::Scalar) -> Self::Commitment;

  /// Multi commits to the provided vectors using the provided generators and random blind
  fn multi_commit(
    ck: &Self::CommitmentKey,
    v: &[Vec<E::Scalar>],
    r: &E::Scalar,
  ) -> Vec<Self::Commitment> {
    v.iter().map(|v_i| Self::commit(ck, &v_i, &r)).collect()
  }

  /// Remove given blind from commitment
  fn derandomize(
    dk: &Self::DerandKey,
    commit: &Self::Commitment,
    r: &E::Scalar,
  ) -> Self::Commitment;
}
