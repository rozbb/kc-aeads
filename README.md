# kc-aeads

Pure Rust implementations of the key-committing (and everything-committing) AEADs defined in [Bellare and Hoang '22](https://eprint.iacr.org/2022/268).

Crash course on the paper:

* The UtC transform converts an AEAD into a key-committing AEAD
* The RtC transform converts a misuse-resistant AEAD into a key-committing misuse-resistant AEAD
* The HtE transform converts a key-committing AEAD to an everything-comitting (aka CMTD-4) AEAD, i.e., an AEAD whose ciphertext-tag output commits to the key, nonce, associated data, and plaintext. This is not the same as key-committing. Using an example from the paper, recall AES-GCM and hence UtC[AES-GCM] has a tag size of 128 bits. If the plaintext is empty, then this the tag is essentially a 128-bit MAC over the authenticated associated data (AAD). This is too short to be binding: for a fixed key an adversary could find two AAD strings which produce a collision in time 2^64. Thus, UtC[AES-GCM] is not AAD-committing (indeed HtE handles AAD entirely differently, using a collision-resistant hash instead of the AEAD).

## Roadmap

Low-level things implemented:

[X] CX block cipher Committing PRF (maybe not sufficiently secure; see question below)
[X] UtC transform
[ ] RtC transform
[X] HtE transform

High-level things implemented:

[X] UtC-transformed AES-128/256-GCM (using CX for Committing PRF)
[X] HtE-transformed UtC-AES-128/256-GCM (using Blake2b for MAC)
[ ] UtC-transformed ChaCha20-Poly1305
[ ] HtE-transformed UtC-ChaCha20-Poly1305
[ ] UtC-transformed XChaCha20-Poly1305
[ ] HtE-transformed UtC-XChaCha20-Poly1305

# Questions

* I have the CX[E] PRF implemented to produce 256-bit commitments for AES-128 and 512-bit commitments for AES-256. Is that correct? The reason I think it is is because thoerem 7.2 links key-committing security to "binding" security of the PRF. This comes down to collision resistance in the commitment. On the other hand, proposition 7.1 says that the binding security of CX[E] is limited by the collision resistance of a one-block Davies-Meyer PRF. In that case, this is totally insecure (since block size is 128) and I shouldn't use CX[E] at all.
* The main reason I'm using CX is because someone using AES for encryption might reasonable have HW acceleration and want to use AES for PRFs and hashing too. So similar question: what should I use instead of Blake2b in the HtE transform for AES? CMAC/PMAC/CBC-MAC digests are too small.

## Warning

This code has not been audited in any sense of the word. Use at your own peril.
