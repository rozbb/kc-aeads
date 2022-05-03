use aes_gcm::Aes128Gcm;
use kc_aeads::{MacHteUtcAes128Gcm, UtcAes128Gcm};

use aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, Key, NewAead, Nonce};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::RngCore;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

fn bench_aead<A: NewAead + AeadInPlace>(c: &mut Criterion, name: &str) {
    let mut buffer = vec![0u8; MB];
    rand::thread_rng().fill_bytes(&mut buffer[..]);

    let key = Key::<A>::clone_from_slice(&buffer[0..<A as NewAead>::KeySize::USIZE]);
    let nonce = Nonce::<A>::clone_from_slice(&buffer[0..<A as AeadCore>::NonceSize::USIZE]);
    let associated_data = b"";
    let aead = <A as NewAead>::new(&key);

    let mut group = c.benchmark_group(name);
    for size in [1, 32, 128, KB, 8 * KB, 64 * KB, MB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("encrypt {: >8}", size)),
            size,
            |b, &size| {
                b.iter(|| {
                    aead.encrypt_in_place_detached(&nonce, associated_data, &mut buffer[0..size])
                        .expect("encryption failure!")
                });
            },
        );

        let tag = aead
            .encrypt_in_place_detached(&nonce, associated_data, &mut buffer[0..*size])
            .expect("encryption failure!");
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("decrypt {: >8}", size)),
            size,
            |b, &size| {
                b.iter(|| {
                    let mut buf_copy = buffer[0..size].to_vec();
                    aead.decrypt_in_place_detached(&nonce, associated_data, &mut buf_copy, &tag)
                        .expect("decryption failure!");
                })
            },
        );
    }
    group.finish();
}

fn bench(c: &mut Criterion) {
    bench_aead::<Aes128Gcm>(c, "Aes128Gcm");
    bench_aead::<UtcAes128Gcm>(c, "UtcAes128Gcm");
    bench_aead::<MacHteUtcAes128Gcm>(c, "MacHteUtcAes128Gcm");
}

criterion_group!(benches, bench);
criterion_main!(benches);
