# kc-aeads

Pure Rust implementations of the key-committing (and context-committing) AEADs defined in [Bellare and Hoang '22](https://eprint.iacr.org/2022/268).

Crash course on the paper:

* The UtC transform converts an AEAD into a key-committing AEAD
* The RtC transform converts a misuse-resistant AEAD into a key-committing misuse-resistant AEAD
* The HtE transform converts a key-committing AEAD to an context-comitting (aka CMTD-4) AEAD, i.e., an AEAD whose ciphertext-tag output commits to the key, nonce, associated data, and plaintext. This is not the same as key-committing. Using an example from the paper, recall AES-GCM and hence UtC[AES-GCM] has a tag size of 128 bits. If the plaintext is empty, then this the tag is essentially a 128-bit MAC over the authenticated associated data (AAD). This is too short to be binding: for a fixed key an adversary could find two AAD strings which produce a collision in time 2^64. Thus, UtC[AES-GCM] is not AAD-committing (indeed HtE handles AAD entirely differently, using a collision-resistant hash instead of the AEAD).
* The CX Committing PRF is a PRF constructed from a block cipher. Rather than returning a single output it returns a pseudorandom pair `(com, mask)`. This is used in the construction of UtC.

## Roadmap

Low-level things implemented:

- [X] CX block cipher Committing PRF (maybe not sufficiently secure; see question below)
- [X] UtC transform
- [ ] RtC transform (not sure if I will; see question 4)
- [X] HtE transform
    - [X] HtE constructed from a generic MAC (called MacHte)
    - [X] HtE constructed from the HKDF of a generic hash function (called HkdfHte)

High-level things implemented:

- [X] UtC-transformed AES-128/256-GCM (using HKDF-SHA2 for Committing PRF)
- [X] HtE-transformed UtC-AES-128/256-GCM (using HMAC-SHA2 or HKDF-SHA2 for MAC)
- [ ] RtC-transformed AES-128-GCM-SIV
- [ ] HtE-transformed RtC-AES-128-GCM-SIV
- [ ] UtC-transformed ChaCha20-Poly1305
- [ ] HtE-transformed UtC-ChaCha20-Poly1305
- [ ] UtC-transformed XChaCha20-Poly1305
- [ ] HtE-transformed UtC-XChaCha20-Poly1305


# Questions

1. Recall HtE "commits" to a nonce and AEAD by computing a MAC over them and using the resulting MAC as an encryption key. If the encryption key size is 128 bits, then this is not a very strongly committing scheme, is it? Does that mean that HtE only gives strong commitment guarantees when the underlying AEAD has 256-bit keys or greater? Does that mean I should implement a key-expanding UtC transform which doubles the key size of the AEAD?
2. I have the CX[E] PRF implemented to produce 256-bit commitments for AES-128 and 512-bit commitments for AES-256. Is that correct? The reason I think it is is because thoerem 7.2 links key-committing security to "binding" security of the PRF. This comes down to collision resistance in the commitment. On the other hand, proposition 7.1 says that the binding security of CX[E] is limited by the collision resistance of a one-block Davies-Meyer PRF. In that case, this is totally insecure (since block size is 128) and I shouldn't use CX[E] at all.
3. The main reason I'm using CX is because someone using AES for encryption might reasonable have HW acceleration and want to use AES for PRFs and hashing too. So similar question: what should I use instead of Blake2b in the HtE transform for AES? CMAC/PMAC/CBC-MAC digests are too small.
4. It appears that RtC (Figure 16) requires the ciphertext to be at least one block long. That's a pain as far as API design goes. Is there a way around this?
5. Are CAU and CAU-C1 (Section 5) worth implementing? They have really low overhead, but it says explicitly in the discussion that key-commitment can be broken with 2^64 work. If our goal with this library is developer ease-of-use, is that bound sufficiently high?
6. I have `HkdfHte` and `MacHte`. I would much prefer to get rid of `HkdfHte` because it's strictly more expensive. The only reason it's currently there is because it's a little bit cleaner. Specifically, it offers more opportunities for domain separation and it lets the caller specify the number of bytes it wants (rather than making the caller truncate to get an AEAD key-sized output). These desires might be totally superfluous though.
7. Similarly, `HkdfComPrf` is pretty expensive too. It needs to do an `Extract` operation when being instantiated because the key sizes it receives are too small to do an `Expand` right away (recall its key sizes are double the bit level they target; why is that?).
8. What PRFs should I use for the UtC and HtE over ChaCha? I'd like to use Blake2b for the UtC committing PRF and HtE MAC. But the former usage requires more than 64 bytes of digest. Am I doomed to use HKDF-Blake2b for the PRF, just like HKDF-SHA2 in the AES ciphers?
9. It appears from [this comment](https://github.com/BLAKE3-team/BLAKE3/issues/138#issuecomment-757385386) that ChaCha20-BLAKE3-SIV gets to be almost 2x the throughput of XChaCha20Poly1305. If you just double the SIV tag size (this should cost nothing), you have a fully context-committing AEAD. Why aren't we all just doing that??

## Warning

This code has not been audited in any sense of the word. Use at your own peril.
