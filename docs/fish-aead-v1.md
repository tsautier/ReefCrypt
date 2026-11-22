# FiSH AEAD v1

This specification defines an opt-in ChaCha20-Poly1305 format for regular IRC `PRIVMSG` text in private conversations and `#` or `&` channels. It requires FiSH to be loaded and intercepting a native IRC TCP or TLS connection. It builds on the ECB/CBC compatibility work in [PR #83](https://github.com/flakes/mirc_fish_10/pull/83). The implementation and tests belong in a separate pull request.

## Configuration and compatibility

- Keep existing ECB/CBC settings, wire formats, and defaults. A nonempty `aead_key` in the explicit network/contact section of `blow.ini` selects AEAD for that conversation. It is exactly 64 hexadecimal characters encoding an independently generated 32-byte random key. Use the same key across participants in one conversation and a different key for every other conversation. Provision it over a separate authenticated channel and rotate it when membership or trust changes.
- AEAD keys are direct and network-scoped. Legacy aliases, NickTracker, and DH1080 do not import or derive them. Removing the AEAD key restores the conversation's configured legacy behavior. Protect the INI and backups as they contain the AEAD key in recoverable form.
- For configured targets, regular outgoing `PRIVMSG` uses AEAD, including text beginning with the legacy plaintext prefix. Invalid keys, unavailable crypto, disabled outgoing encryption, a missing or mismatched network identity or target spelling for a known AEAD target, and failures to format or encrypt block the send and report a local error. There is no automatic fallback. CTCP and `CPRIVMSG` to these targets are blocked in v1. `NOTICE` and `TOPIC` retain their existing settings.
- FiSH uses the mIRC-compatible normalized `NETWORK` value for lookup. A known AEAD target without a resolvable key on the current network is blocked even when its spelling matches another configured network or is an IRC case-equivalent. This prevents a server from using a changed `NETWORK` token to make a configured target leak plaintext. Use a distinct target or remove the AEAD configuration explicitly when intentionally sending in legacy mode to an identically named target elsewhere.
- A v1 receiver only opens v1 ciphertext in an AEAD-configured conversation. Unsupported versions, malformed frames, failed authentication, and replays remain opaque. ECB/CBC ciphertext for a regular `PRIVMSG` in an AEAD conversation remains opaque. Incoming ordinary IRC plaintext can still appear in the client and carries no authentication. A valid tag proves possession of the shared conversation key. Each holder can create a message attributed by IRC to any nickname, so AEAD establishes no individual identity.

## Wire encoding and cryptography

```text
"+FISH-AEAD1 " || base64url(session_id || counter || ciphertext || tag)
session_id  = 16 bytes
counter     = 8 bytes, unsigned, big-endian
tag         = 16 bytes
```

Base64url uses the RFC 4648 URL-safe alphabet with zero unused bits, no padding, and no whitespace. Quoted strings below are ASCII without a terminating NUL.

- Traffic key: HKDF-SHA-256 extract-and-expand, 32-byte output, IKM equal to the conversation key, salt equal to the session ID, info equal to `"FiSH-AEAD1 traffic"`.
- Nonce: four zero bytes followed by the counter as encoded on the wire. AAD: `"+FISH-AEAD1 "` including its trailing space, followed by the raw session ID and encoded counter. The distinct conversation key binds scope. The wire format does not depend on nickname spelling, server prefixes, or IRCv3 tags.
- Plaintext: nonempty message bytes as supplied by the IRC client, preserving significant spaces. NUL, CR, and LF are invalid. CTCP-framed text is outside v1. Verify the full tag before releasing any plaintext to mIRC.
- The non-tag part of an IRC line has a 512-byte v1 budget including CRLF. The sender budgets the command, target, separator, wire marker, exact Base64url expansion, and CRLF, and reserves 128 bytes for the relay prefix. IRCv3 tags use their separate allowance. Oversize messages are blocked before sending, with no truncation or fragmentation. Multi-target messages that the existing socket layer can split are evaluated per recipient. A list that cannot be split is blocked if it contains an AEAD target.

## Session and replay rules

Each process starts with a new 128-bit CSPRNG session ID and a counter starting at zero. Allocation is serialized and values are consumed before sealing, even if the send later fails. Reconnects in a running process retain the session and counter. A restart creates new state. At exhaustion, sending stops until fresh process state is created. RNG failures block encryption. Cloning or restoring an already running process can duplicate its live state. Rotate the conversation key before using a restored live snapshot.

For `q` independently generated sessions under the same conversation key, the probability of a repeated session ID is at most `q(q-1)/2^129`. Rotate before `2^32` such sessions under one key, which bounds that probability below `2^-65`. This bound assumes a functioning CSPRNG and fresh session generation.

After authentication, the receiver tracks each traffic-key/session pair in a 64-counter sliding window. It accepts unseen counters within the window and rejects duplicates and older counters. At most 4096 authenticated sessions are retained per process. New sessions are refused at capacity. Unauthenticated packets do not allocate or advance replay state. Receiver replay protection is in memory and resets on process restart.

## Reference vector

All binary values below are hex. The plaintext bytes spell `FiSH AEAD v1`.

```text
conversation key  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
session ID        000102030405060708090a0b0c0d0e0f
counter           000000000000002a
traffic key       2e9cf2e06ce23001585cfd2e758eb09d3fac57b34b137bbf0e1c5a6314ecdd45
nonce             00000000000000000000002a
AAD               2b464953482d414541443120000102030405060708090a0b0c0d0e0f000000000000002a
plaintext         466953482041454144207631
ciphertext        221f9345955182bb82ec7c1d
tag               f522b1500f20fd730d0d90b531b466b5
wire              +FISH-AEAD1 AAECAwQFBgcICQoLDA0ODwAAAAAAAAAqIh-TRZVRgruC7Hwd9SKxUA8g_XMNDZC1MbRmtQ
```

## Implementation acceptance

- Verify RFC 8439 §2.8.2 and the FiSH vector using independent implementations. Run deterministic crypto tests in Win32 CI.
- Verify parallel sending, fresh process sessions, multiple channel senders, counter exhaustion and RNG failure behavior, valid out-of-order delivery, replay, and rejection without state advancement after authentication failure.
- Verify wrong keys, malformed or truncated frames, altered header/ciphertext/tag, newline and NUL rejection, and line budgets at the boundary. Verify no cleartext or downgrade on a blocked send.
- Run mIRC Win32 loopback tests with AEAD and legacy ECB/CBC conversations, including mixed-mode handling and packet capture to confirm what is emitted. Cover plain IRC and verified TLS where available.

## References

- [Nir and Langley, RFC 8439, June 2018](https://www.rfc-editor.org/rfc/rfc8439#section-2.8)
- [Krawczyk and Eronen, RFC 5869, May 2010](https://www.rfc-editor.org/rfc/rfc5869)
- [Josefsson, RFC 4648, October 2006](https://www.rfc-editor.org/rfc/rfc4648#section-5)
- [Kalt, RFC 2812, April 2000](https://www.rfc-editor.org/rfc/rfc2812#section-2.3) and [IRCv3 Message Tags size limit](https://ircv3.net/specs/extensions/message-tags#size-limit)
- [OpenSSL 3.5 EVP ChaCha20-Poly1305](https://docs.openssl.org/3.5/man3/EVP_chacha20/)
