# ReefCrypt independence plan

Inventory recorded 2026-11-28. This is a proposed migration plan, not a completed audit or a legal conclusion.

## Preservation

Before leaving the GitHub fork network, export a full Git mirror (including tags), submodule references and required submodule history, and export pull request descriptions, comments, reviews, patches and metadata. Verify restoration locally. The branch `backup/pre-detach-2026-11-28` preserves the master tip in the existing repository only.

| Branch | Recorded tip |
| --- | --- |
| master | `9b7b98e6370f4f4c6c07901fb5e70383918da18e` |
| fix/fish-10-issues | `a707568ad5057b829eb16ac9cfd1e4ec1751ca2a` |
| feat/fish-aead-v1 | `2f084d8d04fafe1fd84108404505bf0d32e20efa` |
| codex/reefcrypt-mirc-script | `3a1ac4c9f349782fe2dc73c7a3a55ac1d7b7cc35` |
| codex/reefcrypt-dirtirc | `e16ed067dadddd1d962a4f45ea7d6c452b95cd22` |
| codex/reefcrypt-name-final | `cb3251ec9bd0d1902e00f19c23365fe03ad88429` |
| vscode-files | `8884e3f6d6609c0a6c003715370d3ecbd0c9f7cb` |

Open PRs [#1](https://github.com/tsautier/ReefCrypt/pull/1) (opt-in AEAD), [#2](https://github.com/tsautier/ReefCrypt/pull/2) (script rewrite), and [#3](https://github.com/tsautier/ReefCrypt/pull/3) (ECB replacement) all target `fix/fish-10-issues`. Preserve their review history and do not merge without checking conflicts and integrated tests. Their reported tests have not been independently reproduced for this inventory.

## Licensing gate

The historical README identifies FiSH v1.30, RXD, flakes, DirtIRC, iNFekt and MinHook. GitHub does not detect a standard repository-wide license. Review file-level provenance, copyright notices and actual license grants for each inherited component; inspect MinHook at the pinned submodule revision and the actual OpenSSL distribution. Obtain clarification from rights holders where needed. Preserve attribution and do not apply a blanket license to inherited code without adequate permission. PRs #2 and #3 reduce some inherited implementation dependencies but do not establish clearance for the whole project. If clearance is unavailable, consider a separately developed implementation based on documented interoperability requirements, with legal review.

## Engineering gates

1. Review the Win32 fixes and upstream changes; integrate on a dedicated candidate branch rather than master.
2. Review and integrate script and ECB replacements and the AEAD branch, resolving overlap explicitly. Review the branding branch separately.
3. Reproduce native build and interoperability tests. Test encryption failures, malformed messages, replay, nonce uniqueness, downgrade resistance, key storage, authenticated key exchange and IRC line limits. Legacy ECB/CBC and DH1080 must be identified as compatibility modes, not modern authenticated encryption.
4. Review dependencies, memory safety, hook behavior, build reproducibility, release packaging and license notices. Publish only after the release and licensing gates pass.
5. Once preservation is verified, use GitHub's documented Leave fork network workflow if appropriate. Do not delete the original repository or overwrite history. Retain a link to upstream and contributor attribution.

References: [upstream](https://github.com/flakes/mirc_fish_10), [GitHub detaching a fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/detaching-a-fork), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).
