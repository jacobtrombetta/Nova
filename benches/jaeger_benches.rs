//! Derived from test_hyperkzg_large in the hyperkzg module
//! ```bash
//! docker run --rm -d --name jaeger -p 6831:6831/udp -p 16686:16686 jaegertracing/all-in-one:1.62.0
//! cargo bench --bench jaeger_benches
//! ```
//! Then, navigate to <http://localhost:16686> to view the traces.
#[cfg(feature = "blitzar")]
use blitzar::compute::init_backend;
use core::marker::PhantomData;
use ff::PrimeField;
use nova_snark::{
  frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
  nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::RelaxedR1CSSNARKTrait,
    Engine,
  },
};
use chrono::Local;
use std::thread;

#[derive(Clone, Debug, Default)]
struct NonTrivialCircuit<F: PrimeField> {
  num_cons: usize,
  _p: PhantomData<F>,
}

impl<F: PrimeField> NonTrivialCircuit<F> {
  pub fn new(num_cons: usize) -> Self {
    Self {
      num_cons,
      _p: PhantomData,
    }
  }
}
impl<F: PrimeField> StepCircuit<F> for NonTrivialCircuit<F> {
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    // Consider an equation: `x^2 = y`, where `x` and `y` are respectively the input and output.
    let mut x = z[0].clone();
    let mut y = x.clone();
    for i in 0..self.num_cons {
      y = x.square(cs.namespace(|| format!("x_sq_{i}")))?;
      x = y.clone();
    }
    Ok(vec![y])
  }
}

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type C1 = NonTrivialCircuit<<E1 as Engine>::Scalar>;
type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

fn bench_compressed_snark_internal<S1: RelaxedR1CSSNARKTrait<E1>, S2: RelaxedR1CSSNARKTrait<E2>>(
  num_cons: usize,
) {
  println!("bench_compressed_snark_internal num_cons: {}", num_cons);
  let c_primary = NonTrivialCircuit::new(num_cons);
  println!("TrivialCircuit::default");
  let c_secondary = TrivialCircuit::default();

  // Produce public parameters
  println!("PublicParams::<E1, E2, C1, C2>::setup");
  let pp = PublicParams::<E1, E2, C1, C2>::setup(
    &c_primary,
    &c_secondary,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )
  .unwrap();

  // Produce prover and verifier keys for CompressedSNARK
  println!("CompressedSNARK::<_, _, _, _, S1, S2>::setup");
  let (_, _) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();

  // produce a recursive SNARK
  for _ in 0..1 {
    let num_steps = 3;
    println!("RecursiveSNARK::new");
    let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> = RecursiveSNARK::new(
      &pp,
      &c_primary,
      &c_secondary,
      &[<E1 as Engine>::Scalar::from(2u64)],
      &[<E2 as Engine>::Scalar::from(2u64)],
    )
    .unwrap();

    for i in 0..num_steps {
      println!("RecursiveSNARK::prove_step step {}", i);
      let thread_id = thread::current().id();
      let timestamp = Local::now();
      println!("Start RecursiveSNARK::prove_step Thread ID: {:?}, Timestamp: {}", thread_id, timestamp);
      let res = recursive_snark.prove_step(&pp, &c_primary, &c_secondary);
      let timestamp = Local::now();
      println!("End RecursiveSNARK::prove_step Thread ID: {:?}, Timestamp: {}", thread_id, timestamp);
      assert!(res.is_ok());

      // verify the recursive snark at each step of recursion
      println!("RecursiveSNARK::verify");
      let timestamp = Local::now();
      println!("Start RecursiveSNARK::verify Thread ID: {:?}, Timestamp: {}", thread_id, timestamp);
      let res = recursive_snark.verify(
        &pp,
        i + 1,
        &[<E1 as Engine>::Scalar::from(2u64)],
        &[<E2 as Engine>::Scalar::from(2u64)],
      );
      let timestamp = Local::now();
      println!("End RecursiveSNARK::verify Thread ID: {:?}, Timestamp: {}", thread_id, timestamp);
      assert!(res.is_ok());
    }
  }

  // // Bench time to produce a compressed SNARK
  // for _ in 0..1 {
  //   println!("CompressedSNARK::<_, _, _, _, S1, S2>::prove");
  //   let _ = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark).is_ok();
  // }
}

fn main() {
  #[cfg(feature = "blitzar")]
  init_backend();

  use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

  let tracer = opentelemetry_jaeger::new_agent_pipeline()
    .with_service_name("benches")
    .install_simple()
    .unwrap();

  let opentelemetry = tracing_opentelemetry::layer().with_tracer(tracer);

  let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("DEBUG"));

  tracing_subscriber::registry()
    .with(opentelemetry)
    .with(filter)
    .try_init()
    .unwrap();

  bench_compressed_snark_internal::<S1, S2>(1 << 20);
}
