# #22 LIJOX Sybil / DDoS Resistance — Design v0 (Session 20)

STATUS: LIJOX-track design. Constraint zero: LIJOX stays OPEN and
PERMISSIONLESS — resistance comes from verifiable costs and wallet-local
judgment, never from admission control. No federation, no gatekeeper.

## Threat model
- T1 Registry flood: mass fake LSP manifests (grief UX, bury real
  providers).
- T2 Lookalike/phish listings: mimic a known LSP's alias/branding with
  hostile endpoints.
- T3 Registry DDoS: knock registries offline → discovery blackout.
- T4 Registry eclipse: a single registry curates/poisons what a wallet
  sees.
- T5 Post-connect misbehavior (fee gouging, channel griefing) — out of
  scope here; belongs to the divergence detector and wallet policy.

## Design stance
Identity = a secp256k1 pubkey signing a LIJOX manifest (Binding Standard
v0, BIP-340 tagged hash). Pubkeys are free to mint, so identity alone is
worthless; COST plus HISTORY make it meaningful.

## Mechanisms
- **M1 Enrollment PoW (T1):** `/lsps/register` accepted only with
  proof-of-work over (registry_id ‖ pubkey ‖ recent Bitcoin block hash),
  difficulty auto-scaled to inflow. Block-hash anchoring (OpenWhirl /
  JoinJar lineage) stales precompute farms hourly. Full-overwrite-per-
  pubkey semantics (already live on our worker) cap per-identity storage
  at O(1).
- **M2 UTXO bond attestation, optional manifest field (T1; strongest
  signal):** prove control of a UTXO ≥ X sats aged ≥ N blocks via a
  BIP-322-style signature over a manifest challenge; verifiable against
  any chain source. Capital-at-rest cost per identity — the UTXO-proof-
  collateral thesis and BOND lineage applied to discovery. Not slashing:
  a cost floor that destroys sybil budgets. Wallets rank bonded above
  PoW-only.
- **M3 First-seen + continuity (T2):** registries record first_seen per
  pubkey; alias squatting can never inherit history. Wallets render age
  and pubkey fingerprint prominently — alias is decoration, pubkey is
  identity. Lookalike defense is fingerprint-first UI, period.
- **M4 Multi-registry aggregation (T4):** reference wallet behavior =
  pull ≥2 independent registries, union by pubkey, flag single-source
  listings. An eclipse now requires collusion among registries the
  wallet chose — market discipline doing its job.
- **M5 Static, signed, mirrorable snapshots (T3):** a registry is just
  signed JSON. Serve via CDN/cache (Cloudflare-native), publish the
  snapshot signature, let anyone mirror. Availability through
  replication, not privilege. PoW + rate limits guard only the WRITE
  path.
- **M6 Wallet-local scoring (T5 boundary):** probe uptime, LSPS1/2
  conformance, fee sanity band vs peers, JIT success rate — scored
  locally, never registry-decreed. Registries carry facts; wallets carry
  judgment.

## Non-goals
No stake-slashing court, no KYC, no registry blessing, no global
reputation oracle. Anything requiring a trusted scorer is out.

## Open questions for DP
Bond floor X and age N defaults · PoW target and algorithm (lean simple:
double-SHA256) · reserve M1+M2 manifest fields in standard v0.1 now,
even if enforcement lags · probe protocol: standardized in LIJOX or
per-wallet.
