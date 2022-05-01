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
- [ ] RtC transform
- [X] HtE transform

High-level things implemented:

- [X] UtC-transformed AES-128/256-GCM (using CX for Committing PRF)
- [X] HtE-transformed UtC-AES-128/256-GCM (using Blake2b for MAC)
- [ ] RtC-transformed AES-128-GCM-SIV
- [ ] HtE-transformed RtC-AES-128-GCM-SIV
- [ ] UtC-transformed ChaCha20-Poly1305
- [ ] HtE-transformed UtC-ChaCha20-Poly1305
- [ ] UtC-transformed XChaCha20-Poly1305
- [ ] HtE-transformed UtC-XChaCha20-Poly1305


# Questions

1. I have the CX[E] PRF implemented to produce 256-bit commitments for AES-128 and 512-bit commitments for AES-256. Is that correct? The reason I think it is is because thoerem 7.2 links key-committing security to "binding" security of the PRF. This comes down to collision resistance in the commitment. On the other hand, proposition 7.1 says that the binding security of CX[E] is limited by the collision resistance of a one-block Davies-Meyer PRF. In that case, this is totally insecure (since block size is 128) and I shouldn't use CX[E] at all.
2. The main reason I'm using CX is because someone using AES for encryption might reasonable have HW acceleration and want to use AES for PRFs and hashing too. So similar question: what should I use instead of Blake2b in the HtE transform for AES? CMAC/PMAC/CBC-MAC digests are too small.
3. It appears that RtC (Figure 16) requires the ciphertext to be at least one block long. That's a pain as far as API design goes. Is there a way around this?
4. Are CAU and CAU-C1 (Section 5) worth implementing? They have really low overhead, but it says explicitly in the discussion that key-commitment can be broken with 2^64 work. If our goal with this library is developer ease-of-use, is that bound sufficiently high?

## Warning

This code has not been audited in any sense of the word. Use at your own peril.
