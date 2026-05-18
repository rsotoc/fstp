use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fstp_core::blocklace::{AggregateAttrs, BlockPayload, BlocklaceStore, InMemoryBlocklace};
use fstp_core::message::EventClass;
use fstp_core::types::{Ed25519Sig, Sha256Hash};

fn mock_signature() -> Ed25519Sig {
    Ed25519Sig(ed25519_dalek::Signature::from_bytes(&[0u8; 64]))
}

fn mock_payload(seed: u64) -> BlockPayload {
    BlockPayload {
        event_hash: Sha256Hash::digest(&seed.to_be_bytes()),
        event_class: EventClass::Decision,
        aggregate_attrs: AggregateAttrs {
            participant_count: Some(5),
            quorum_reached: Some(true),
            rounds_completed: Some(1),
        },
    }
}

/// Construye un blocklace con `n` bloques y devuelve la instancia.
/// El `offset` en el seed garantiza que dos blocklaces con el mismo
/// `n` pero diferente `offset` produzcan hashes distintos — necesario
/// para simular divergencia real en lugar de bloques duplicados.
fn build_blocklace(n: u64, seed_offset: u64) -> InMemoryBlocklace {
    let mut bl = InMemoryBlocklace::new();
    for i in 0..n {
        bl.append(mock_payload(seed_offset + i), mock_signature()).unwrap();
    }
    bl
}

/// Construye el par (A, B) donde:
///   - ambos comparten una base de `shared` bloques idénticos
///   - A tiene `delta` bloques adicionales que B no conoce
///   - B tiene su propio frontier (sin bloques extra) desde el que A calcula el delta
///
/// Nota: `merge_blocks` actualiza el frontier de B con los bloques compartidos,
/// lo que hace que `sync_delta` calcule correctamente solo los `delta` bloques de A.
fn build_pair(shared: u64, delta: u64) -> (InMemoryBlocklace, InMemoryBlocklace) {
    // Fase 1: construir la historia compartida
    let mut bl_a = InMemoryBlocklace::new();
    let mut shared_blocks = Vec::with_capacity(shared as usize);
    for i in 0..shared {
        let block = bl_a.append(mock_payload(i), mock_signature()).unwrap();
        shared_blocks.push(block);
    }

    // B recibe exactamente la historia compartida y nada más
    let mut bl_b = InMemoryBlocklace::new();
    bl_b.merge_blocks(shared_blocks).unwrap();

    // Fase 2: A diverge con `delta` bloques usando seeds distintos
    // para garantizar hashes únicos respecto a la base compartida
    for i in 0..delta {
        bl_a.append(mock_payload(1_000_000 + i), mock_signature()).unwrap();
    }

    (bl_a, bl_b)
}

// ─── Benchmark 1: sync_delta varía ∆, N fijo ──────────────────────────────
//
// Pregunta: ¿el tiempo crece linealmente con ∆?
// Si sí → O(∆) confirmado.
// Si no → hay overhead fijo (e.g. construcción del HashSet de frontier).

fn bench_sync_delta_vs_delta(c: &mut Criterion) {
    let mut group = c.benchmark_group("sync_delta__fixed_N__varying_delta");
    let shared_n = 1_000u64; // N grande y constante
    let deltas: &[u64] = &[10, 50, 100, 200, 500];

    for &delta in deltas {
        group.throughput(Throughput::Elements(delta));
        group.bench_with_input(
            BenchmarkId::from_parameter(delta),
            &delta,
            |b, &delta| {
                // El par se construye fuera del loop — medimos solo sync_delta
                let (bl_a, bl_b) = build_pair(shared_n, delta);
                let remote_frontier = bl_b.frontier();

                b.iter(|| {
                    // sync_delta es &self → no muta el estado, es seguro reusar
                    let result = bl_a.sync_delta(&remote_frontier);
                    // Prevent dead-code elimination
                    std::hint::black_box(result);
                });
            },
        );
    }
    group.finish();
}

// ─── Benchmark 2: sync_delta varía N, ∆ fijo ──────────────────────────────
//
// Pregunta: ¿el tiempo crece con N cuando ∆ es constante?
// Si no → la eficiencia O(∆) es real.
// Si sí → hay una dependencia oculta en N (e.g. el DFS en ancestors_not_in
//          visita demasiados nodos, o rebuild_frontier_cache contamina).

fn bench_sync_delta_vs_base(c: &mut Criterion) {
    let mut group = c.benchmark_group("sync_delta__fixed_delta__varying_N");
    let fixed_delta = 50u64;
    let base_sizes: &[u64] = &[100, 500, 1_000, 5_000];

    for &shared_n in base_sizes {
        // Throughput en términos del delta transmitido — constante entre grupos.
        // Así cualquier diferencia de tiempo es overhead puro de N, no de ∆.
        group.throughput(Throughput::Elements(fixed_delta));
        group.bench_with_input(
            BenchmarkId::from_parameter(shared_n),
            &shared_n,
            |b, &shared_n| {
                let (bl_a, bl_b) = build_pair(shared_n, fixed_delta);
                let remote_frontier = bl_b.frontier();

                b.iter(|| {
                    std::hint::black_box(bl_a.sync_delta(&remote_frontier));
                });
            },
        );
    }
    group.finish();
}

// ─── Benchmark 3: merge_blocks varía ∆, N fijo ────────────────────────────
//
// Pregunta: ¿cuánto cuesta integrar los bloques recibidos?
// merge_blocks llama a rebuild_frontier_cache() → O(N_total).
// Si se confirma, es la evidencia del problema señalado en el análisis anterior.

fn bench_merge_blocks_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge_blocks__fixed_N__varying_delta");
    let shared_n = 1_000u64;
    let deltas: &[u64] = &[10, 50, 100, 200];

    for &delta in deltas {
        group.throughput(Throughput::Elements(delta));
        group.bench_with_input(
            BenchmarkId::from_parameter(delta),
            &delta,
            |b, &delta| {
                let (bl_a, bl_b) = build_pair(shared_n, delta);
                let remote_frontier = bl_b.frontier();
                let blocks_to_merge = bl_a.sync_delta(&remote_frontier);

                // Pre-construir el pool de receptores fuera del loop de Criterion
                // iter_batched los rota sin reconstruir en cada iteración
                b.iter_batched(
                    || build_pair(shared_n, delta).1,  // setup: un bl_b fresco
                    |mut bl_b_fresh| {
                        bl_b_fresh.merge_blocks(blocks_to_merge.clone()).unwrap();
                        std::hint::black_box(bl_b_fresh);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sync_delta_vs_delta,
    bench_sync_delta_vs_base,
    bench_merge_blocks_cost,
);
criterion_main!(benches);