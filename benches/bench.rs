// This file was adapted from
// https://github.com/PaulGrandperrin/XChaCha8Blake3Siv/blob/bbcc3874da3375a5111d113b01c4156b660ef034/benches/bench.rs
// Thanks Paul!

use aes_gcm::Aes128Gcm;
use kc_aeads::{MacHteUtcAes128Gcm, UtcAes128Gcm};

use aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, Key, NewAead, Nonce};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::RngCore;

#[allow(non_upper_case_globals)]
const KiB: usize = 1024;
#[allow(non_upper_case_globals)]
const MiB: usize = 1024 * KiB;

//
// We bench encryption and decryption of the given AEAD with (aad, msg) sizes of:
// (1B, 1B), (32B, 32B), (128B, 128B), (1KiB, 1KiB), (8KiB, 8KiB), (64KiB, 64KiB), (1MiB, 1MiB)
// and
// (0B, 1B), (0B, 32B), (0B, 128B), (0B, 1KiB), (0B, 8KiB), (0B, 64KiB), (0B, 1MiB)
//
// NOTE: Throughput numbers for nonzero AAD sizes count both AAD and message bytes
//

fn bench_aead<A: NewAead + AeadInPlace>(c: &mut Criterion, name: &str) {
    let mut buffer = vec![0u8; MiB];
    let mut associated_data = vec![0u8; MiB];
    rand::thread_rng().fill_bytes(&mut buffer[..]);
    rand::thread_rng().fill_bytes(&mut associated_data[..]);

    let key = Key::<A>::clone_from_slice(&buffer[0..<A as NewAead>::KeySize::USIZE]);
    let nonce = Nonce::<A>::clone_from_slice(&buffer[0..<A as AeadCore>::NonceSize::USIZE]);
    let aead = <A as NewAead>::new(&key);

    let mut group = c.benchmark_group(name);
    for size in [1, 32, 128, KiB, 8 * KiB, 64 * KiB, MiB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        //
        // Do benches with AAD size = message size
        //

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("encrypt [msg=aad={}B]", size)),
            &(2 * size), // Count AAD and message bytes
            |b, &combined_size| {
                b.iter(|| {
                    aead.encrypt_in_place_detached(
                        &nonce,
                        &associated_data[0..combined_size / 2],
                        &mut buffer[0..combined_size / 2],
                    )
                    .expect("encryption failure!")
                });
            },
        );

        let tag = aead
            .encrypt_in_place_detached(&nonce, &associated_data[0..*size], &mut buffer[0..*size])
            .expect("encryption failure!");
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("decrypt [msg=aad={}B]", size)),
            &(2 * size), // Count AAD and message bytes
            |b, &combined_size| {
                b.iter(|| {
                    let mut buf_copy = buffer[0..combined_size / 2].to_vec();
                    aead.decrypt_in_place_detached(
                        &nonce,
                        &associated_data[0..combined_size / 2],
                        &mut buf_copy,
                        &tag,
                    )
                    .expect("decryption failure!");
                })
            },
        );

        //
        // Now do benches with AAD size = 0
        //

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("encrypt [msg={}B,aad=0B]", size)),
            size,
            |b, &msg_size| {
                b.iter(|| {
                    aead.encrypt_in_place_detached(&nonce, b"", &mut buffer[0..msg_size])
                        .expect("encryption failure!")
                });
            },
        );

        let tag = aead
            .encrypt_in_place_detached(&nonce, b"", &mut buffer[0..*size])
            .expect("encryption failure!");
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("decrypt [msg={}B,aad=0B]", size)),
            size,
            |b, &msg_size| {
                b.iter(|| {
                    let mut buf_copy = buffer[0..msg_size].to_vec();
                    aead.decrypt_in_place_detached(&nonce, b"", &mut buf_copy, &tag)
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
