//! This module implements the Nova traits for `bn256::Point`, `bn256::Scalar`, `grumpkin::Point`, `grumpkin::Scalar`.
use crate::{
  provider::traits::{DlogGroup, PairingGroup},
  traits::{Group, PrimeFieldExt, TranscriptReprTrait},
};
use digest::{ExtendableOutput, Update};
use ff::FromUniformBytes;
use halo2curves::{
  bn256::{Bn256, G1Affine as Bn256Affine, G2Affine, G2Compressed, Gt, G1 as Bn256Point, G2},
  group::{cofactor::CofactorCurveAffine, Curve, Group as AnotherGroup},
  grumpkin::{G1Affine as GrumpkinAffine, G1 as GrumpkinPoint},
  msm::msm_best,
  pairing::Engine as H2CEngine,
  CurveAffine, CurveExt,
};
use num_bigint::BigInt;
use num_traits::Num;
use rayon::prelude::*;
use sha3::Shake256;
use std::io::Read;

/// Re-exports that give access to the standard aliases used in the code base, for bn256
pub mod bn256 {
  pub use halo2curves::bn256::{Fq as Base, Fr as Scalar, G1Affine as Affine, G1 as Point};
}

/// Re-exports that give access to the standard aliases used in the code base, for grumpkin
pub mod grumpkin {
  pub use halo2curves::grumpkin::{Fq as Base, Fr as Scalar, G1Affine as Affine, G1 as Point};
}

impl Group for bn256::Point {
  type Base = bn256::Base;
  type Scalar = bn256::Scalar;
  fn group_params() -> (Self::Base, Self::Base, BigInt, BigInt) {
    let A = bn256::Point::a();
    let B = bn256::Point::b();
    let order = BigInt::from_str_radix(
      "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
      16,
    )
    .unwrap();
    let base = BigInt::from_str_radix(
      "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
      16,
    )
    .unwrap();
    (A, B, order, base)
  }
}
impl DlogGroup for bn256::Point {
  type AffineGroupElement = bn256::Affine;
  #[cfg(not(feature = "blitzar"))]
  #[tracing::instrument(
    name = "bn256::vartime_multiscalar_mul (cpu)",
    level = "debug",
    skip_all
  )]
  fn vartime_multiscalar_mul(scalars: &[Self::Scalar], bases: &[Self::AffineGroupElement]) -> Self {
    msm_best(scalars, bases)
  }

  #[tracing::instrument(
    name = "bn256::vartime_multiscalar_mul_cpu (cpu)",
    level = "debug",
    skip_all
  )]
  fn vartime_multiscalar_mul_cpu(
    scalars: &[Self::Scalar],
    bases: &[Self::AffineGroupElement],
  ) -> Self {
    msm_best(scalars, bases)
  }
  #[cfg(feature = "blitzar")]
  #[tracing::instrument(
    name = "bn256::vartime_multiscalar_mul (gpu)",
    level = "debug",
    skip_all
  )]
  fn vartime_multiscalar_mul(scalars: &[Self::Scalar], bases: &[Self::AffineGroupElement]) -> Self {
    super::blitzar::vartime_multiscalar_mul(scalars, bases)
  }
  fn affine(&self) -> Self::AffineGroupElement {
    self.to_affine()
  }
  fn group(p: &Self::AffineGroupElement) -> Self {
    bn256::Point::from(*p)
  }
  fn from_label(label: &'static [u8], n: usize) -> Vec<Self::AffineGroupElement> {
    let mut shake = Shake256::default();
    shake.update(label);
    let mut reader = shake.finalize_xof();
    let mut uniform_bytes_vec = Vec::new();
    for _ in 0..n {
      let mut uniform_bytes = [0u8; 32];
      reader.read_exact(&mut uniform_bytes).unwrap();
      uniform_bytes_vec.push(uniform_bytes);
    }
    let gens_proj: Vec<Bn256Point> = (0..n)
      .into_par_iter()
      .map(|i| {
        let hash = Bn256Point::hash_to_curve("from_uniform_bytes");
        hash(&uniform_bytes_vec[i])
      })
      .collect();
    let num_threads = rayon::current_num_threads();
    if gens_proj.len() > num_threads {
      let chunk = (gens_proj.len() as f64 / num_threads as f64).ceil() as usize;
      (0..num_threads)
        .into_par_iter()
        .flat_map(|i| {
          let start = i * chunk;
          let end = if i == num_threads - 1 {
            gens_proj.len()
          } else {
            core::cmp::min((i + 1) * chunk, gens_proj.len())
          };
          if end > start {
            let mut gens = vec![Bn256Affine::identity(); end - start];
            <Self as Curve>::batch_normalize(&gens_proj[start..end], &mut gens);
            gens
          } else {
            vec![]
          }
        })
        .collect()
    } else {
      let mut gens = vec![Bn256Affine::identity(); n];
      <Self as Curve>::batch_normalize(&gens_proj, &mut gens);
      gens
    }
  }
  fn zero() -> Self {
    bn256::Point::identity()
  }
  fn gen() -> Self {
    bn256::Point::generator()
  }
  fn to_coordinates(&self) -> (Self::Base, Self::Base, bool) {
    let coordinates = self.affine().coordinates();
    if coordinates.is_some().unwrap_u8() == 1 && (Bn256Affine::identity() != self.affine()) {
      (*coordinates.unwrap().x(), *coordinates.unwrap().y(), false)
    } else {
      (Self::Base::zero(), Self::Base::zero(), true)
    }
  }
}
impl PrimeFieldExt for bn256::Scalar {
  fn from_uniform(bytes: &[u8]) -> Self {
    let bytes_arr: [u8; 64] = bytes.try_into().unwrap();
    bn256::Scalar::from_uniform_bytes(&bytes_arr)
  }
}
impl<G: Group> TranscriptReprTrait<G> for bn256::Scalar {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    self.to_bytes().to_vec()
  }
}
impl<G: DlogGroup> TranscriptReprTrait<G> for bn256::Affine {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    let coords = self.coordinates().unwrap();
    [coords.x().to_bytes(), coords.y().to_bytes()].concat()
  }
}

impl Group for grumpkin::Point {
  type Base = grumpkin::Base;
  type Scalar = grumpkin::Scalar;
  fn group_params() -> (Self::Base, Self::Base, BigInt, BigInt) {
    let A = grumpkin::Point::a();
    let B = grumpkin::Point::b();
    let order = BigInt::from_str_radix(
      "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
      16,
    )
    .unwrap();
    let base = BigInt::from_str_radix(
      "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
      16,
    )
    .unwrap();
    (A, B, order, base)
  }
}
impl DlogGroup for grumpkin::Point {
  type AffineGroupElement = grumpkin::Affine;
  #[tracing::instrument(
    name = "grumpkin::vartime_multiscalar_mul (cpu)",
    level = "debug",
    skip_all
  )]
  fn vartime_multiscalar_mul(scalars: &[Self::Scalar], bases: &[Self::AffineGroupElement]) -> Self {
    msm_best(scalars, bases)
  }
  fn affine(&self) -> Self::AffineGroupElement {
    self.to_affine()
  }
  fn group(p: &Self::AffineGroupElement) -> Self {
    grumpkin::Point::from(*p)
  }
  fn from_label(label: &'static [u8], n: usize) -> Vec<Self::AffineGroupElement> {
    let mut shake = Shake256::default();
    shake.update(label);
    let mut reader = shake.finalize_xof();
    let mut uniform_bytes_vec = Vec::new();
    for _ in 0..n {
      let mut uniform_bytes = [0u8; 32];
      reader.read_exact(&mut uniform_bytes).unwrap();
      uniform_bytes_vec.push(uniform_bytes);
    }
    let gens_proj: Vec<GrumpkinPoint> = (0..n)
      .into_par_iter()
      .map(|i| {
        let hash = GrumpkinPoint::hash_to_curve("from_uniform_bytes");
        hash(&uniform_bytes_vec[i])
      })
      .collect();
    let num_threads = rayon::current_num_threads();
    if gens_proj.len() > num_threads {
      let chunk = (gens_proj.len() as f64 / num_threads as f64).ceil() as usize;
      (0..num_threads)
        .into_par_iter()
        .flat_map(|i| {
          let start = i * chunk;
          let end = if i == num_threads - 1 {
            gens_proj.len()
          } else {
            core::cmp::min((i + 1) * chunk, gens_proj.len())
          };
          if end > start {
            let mut gens = vec![GrumpkinAffine::identity(); end - start];
            <Self as Curve>::batch_normalize(&gens_proj[start..end], &mut gens);
            gens
          } else {
            vec![]
          }
        })
        .collect()
    } else {
      let mut gens = vec![GrumpkinAffine::identity(); n];
      <Self as Curve>::batch_normalize(&gens_proj, &mut gens);
      gens
    }
  }
  fn zero() -> Self {
    grumpkin::Point::identity()
  }
  fn gen() -> Self {
    grumpkin::Point::generator()
  }
  fn to_coordinates(&self) -> (Self::Base, Self::Base, bool) {
    let coordinates = self.affine().coordinates();
    if coordinates.is_some().unwrap_u8() == 1 && (GrumpkinAffine::identity() != self.affine()) {
      (*coordinates.unwrap().x(), *coordinates.unwrap().y(), false)
    } else {
      (Self::Base::zero(), Self::Base::zero(), true)
    }
  }
}
impl PrimeFieldExt for grumpkin::Scalar {
  fn from_uniform(bytes: &[u8]) -> Self {
    let bytes_arr: [u8; 64] = bytes.try_into().unwrap();
    grumpkin::Scalar::from_uniform_bytes(&bytes_arr)
  }
}
impl<G: Group> TranscriptReprTrait<G> for grumpkin::Scalar {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    self.to_bytes().into_iter().rev().collect()
  }
}
impl<G: DlogGroup> TranscriptReprTrait<G> for grumpkin::Affine {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    let coords = self.coordinates().unwrap();
    let x_bytes = coords.x().to_bytes().into_iter();
    let y_bytes = coords.y().to_bytes().into_iter();
    x_bytes.rev().chain(y_bytes.rev()).collect()
  }
}

impl PairingGroup for Bn256Point {
  type G2 = G2;
  type GT = Gt;

  fn pairing(p: &Self, q: &Self::G2) -> Self::GT {
    <Bn256 as H2CEngine>::pairing(&p.affine(), &q.affine())
  }
}

impl Group for G2 {
  type Base = bn256::Base;
  type Scalar = bn256::Scalar;

  fn group_params() -> (Self::Base, Self::Base, BigInt, BigInt) {
    let A = bn256::Point::a();
    let B = bn256::Point::b();
    let order = BigInt::from_str_radix(
      "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
      16,
    )
    .unwrap();
    let base = BigInt::from_str_radix(
      "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
      16,
    )
    .unwrap();

    (A, B, order, base)
  }
}

impl DlogGroup for G2 {
  type AffineGroupElement = G2Affine;

  fn vartime_multiscalar_mul(scalars: &[Self::Scalar], bases: &[Self::AffineGroupElement]) -> Self {
    msm_best(scalars, bases)
  }

  fn affine(&self) -> Self::AffineGroupElement {
    self.to_affine()
  }

  fn group(p: &Self::AffineGroupElement) -> Self {
    G2::from(*p)
  }

  fn from_label(_label: &'static [u8], _n: usize) -> Vec<Self::AffineGroupElement> {
    unimplemented!()
  }

  fn zero() -> Self {
    G2::identity()
  }

  fn gen() -> Self {
    G2::generator()
  }

  fn to_coordinates(&self) -> (Self::Base, Self::Base, bool) {
    unimplemented!()
  }
}

impl<G: DlogGroup> TranscriptReprTrait<G> for G2Compressed {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    self.as_ref().to_vec()
  }
}

impl<G: DlogGroup> TranscriptReprTrait<G> for G2Affine {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    unimplemented!()
  }
}
