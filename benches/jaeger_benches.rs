// Derived from test_hyperkzg_large in the hyperkzg module
#[cfg(feature = "blitzar")]
use blitzar::compute::init_backend;
use nova_snark::{
  provider::{hyperkzg::EvaluationArgument, keccak::Keccak256Transcript, Bn256EngineKZG},
  spartan::polys::multilinear::MultilinearPolynomial, traits::{evaluation::EvaluationEngineTrait, TranscriptEngineTrait},
};
use ff::Field;
use halo2curves::bn256::Fr;
use nova_snark::{provider::hyperkzg::{CommitmentEngine, CommitmentKey, EvaluationEngine}, traits::commitment::CommitmentEngineTrait};
use rand::SeedableRng;

type E = Bn256EngineKZG;

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

  // test the hyperkzg prover and verifier with random instances (derived from a seed)
  for _ in 0..3 {
    let ell = 20;

    let mut rng = rand::rngs::StdRng::seed_from_u64(ell as u64);

    let n = 1 << ell; // n = 2^ell

    let poly = (0..n).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();
    let point = (0..ell).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();
    let eval = MultilinearPolynomial::evaluate_with(&poly, &point);

    let ck: CommitmentKey<E> = CommitmentEngine::setup(b"test", n);
    let (pk, vk) = EvaluationEngine::setup(&ck);

    // make a commitment
    let c = CommitmentEngine::commit(&ck, &poly, &Fr::ZERO);

    // prove an evaluation
    let mut prover_transcript = Keccak256Transcript::new(b"TestEval");
    let proof: EvaluationArgument<E> =
        EvaluationEngine::prove(&ck, &pk, &mut prover_transcript, &c, &poly, &point, &eval)
            .unwrap();

    // verify the evaluation
    let mut verifier_tr = Keccak256Transcript::new(b"TestEval");
    assert!(EvaluationEngine::verify(&vk, &mut verifier_tr, &c, &point, &eval, &proof).is_ok());
}
}
