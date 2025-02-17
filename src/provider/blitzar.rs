use blitzar;
use halo2curves::bn256::{Fr as Scalar, G1Affine as Affine, G1 as Point};

/// A trait that provides the ability to perform multi-scalar multiplication in variable time
pub fn vartime_multiscalar_mul(scalars: &[Scalar], bases: &[Affine]) -> Point {
  let mut blitzar_commitments = vec![Point::default(); 1];

  blitzar::compute::compute_bn254_g1_uncompressed_commitments_with_halo2_generators(
    &mut blitzar_commitments,
    &[scalars.into()],
    bases,
  );

  blitzar_commitments[0]
}

/// A trait that provides the ability to perform multi multi-scalar multiplication in variable time
pub fn multi_vartime_multiscalar_mul(scalars: &[Vec<Scalar>], bases: &[Affine]) -> Vec<Point> {
  let mut blitzar_commitments = vec![Point::default(); scalars.len()];

  blitzar::compute::compute_bn254_g1_uncompressed_commitments_with_halo2_generators(
    &mut blitzar_commitments,
    &scalars.iter().map(|v| v[..].into()).collect::<Vec<_>>(),
    bases,
  );

  blitzar_commitments
}

#[cfg(test)]
mod tests {
  use super::*;
  use ff::Field;
  use halo2curves::msm::msm_best;

  #[test]
  fn test_empty_vartime_multiscalar_mul() {
    let scalars = vec![];
    let bases = vec![];

    let result = vartime_multiscalar_mul(&scalars, &bases);

    assert_eq!(result, Point::default());
  }

  #[test]
  fn test_simple_vartime_multiscalar_mul() {
    let mut rng = rand::thread_rng();

    let scalars = vec![Scalar::random(&mut rng), Scalar::random(&mut rng)];
    let g = Affine::random(&mut rng);
    let bases = vec![g, g];

    let result = vartime_multiscalar_mul(&scalars, &bases);

    let expected = g * scalars[0] + g * scalars[1];

    assert_eq!(result, expected);
  }

  #[test]
  fn test_vartime_multiscalar_mul() {
    let mut rng = rand::thread_rng();
    let sample_len = 100;

    let (scalars, bases): (Vec<_>, Vec<_>) = (0..sample_len)
      .map(|_| (Scalar::random(&mut rng), Affine::random(&mut rng)))
      .unzip();

    let result = vartime_multiscalar_mul(&scalars, &bases);

    let mut expected = Point::default();
    for i in 0..sample_len {
      expected += bases[i] * scalars[i];
    }

    assert_eq!(result, expected);
  }

  #[test]
  fn test_vartime_multiscalar_mul_with_msm_best() {
    let mut rng = rand::thread_rng();
    let sample_len = 100;

    let (scalars, bases): (Vec<_>, Vec<_>) = (0..sample_len)
      .map(|_| (Scalar::random(&mut rng), Affine::random(&mut rng)))
      .unzip();

    let result = vartime_multiscalar_mul(&scalars, &bases);
    let expected = msm_best(&scalars, &bases);

    assert_eq!(result, expected);
  }
}
