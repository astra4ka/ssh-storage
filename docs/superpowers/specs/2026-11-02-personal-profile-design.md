# Spec: isolated personal access alongside an existing installation

Status: implemented and locally verified; real Android/VPS validation remains pending.

## Objective

Allow someone who mistakenly selected team-member mode to create independent
personal access without resetting or promoting the existing identity. Preserve
the existing installation and its authorized server access. Do not promise zero
risk: Android Keystore and actual server access require real-device verification.

The user approved the direction: separate personal and existing/team profiles,
separate phone key and recovery password, no replacement of existing keys or
permissions. This spec records the concrete safety boundaries for that direction.

## Scope and assumptions

- One capability: an isolated personal profile on the same computer and phone.
- Start with exactly two profile IDs: `default` (the existing installation) and
  `personal`. The existing profile need not actually belong to a team.
- Keep Python's standard library and the existing Termux Keystore integration.
- No new service, dependency, crypto algorithm, or remote privilege mechanism.
- Creating a personal profile does not establish ownership of existing servers.
  Never infer administrative rights from a local profile name or recovery field.
- This is not a fix for the existing broader untrusted-team limitations documented
  in SECURITY.md, nor a general multi-account or multi-phone management system.

## User flow

1. Add a Profiles entry in the pairing section on computer and phone. Show the
   selected profile in the main screen and phone approval prompts.
2. Offer **Create separate personal access**, explaining before confirmation that
   it creates a different identity, starts with no servers or privileges, and
   preserves the existing profile. Cancellation must not create a key or state.
3. Create the personal profile locally on each device after explicit confirmation.
   Re-running the action offers the existing personal profile, never overwrites it.
4. Switch into that profile explicitly. On the computer create and verify a new
   recovery password during initial pairing, without the ambiguous team-member
   question. The password is never stored or sent to the phone.
5. Pair with the phone's personal profile using the existing code comparison and
   physical phone approval. The phone must have a distinct pairing identity and
   Android Keystore alias, not the main profile's SSH key.
6. The user can add a new VPS using independently supplied, already authorized
   administrative credentials and the existing confirmed setup flow. Do not use
   the old profile's phone key or SSH connection as a bootstrap credential.
7. Existing team servers do not appear in the personal profile. To authorize a
   new identity on a team server, its administrator must explicitly grant access.
8. A menu action returns to the existing profile. An ordinary launch without an
   explicit profile selector still opens the existing profile; no silent
   persistent change of the user's default profile.

## State and process boundaries

- Existing `pc.json`, `phone.json`, `vault.json`, peer lists, pairing keys, SSH key
  aliases, recovery data and server lists stay at their current paths and are not
  migrated, copied into the personal profile, reset or rewritten by creation.
- New state lives under `profiles/personal/` within the existing state root.
  Directories are private (0700), state files private (0600), with the existing
  atomic-save pattern. No arbitrary path supplied by a profile name; reject
  unknown IDs, symlinked profile roots and malformed existing state.
- Select the profile before reading language or constructing PC/Phone state.
  Prefer restarting the application with a validated profile argument rather than
  changing module-global file paths during a live session.
- Each profile has independent pairing secrets, peers, server lists, permissions
  cache, recovery public key, journal and Keystore alias.
- Personal aliases must be unique and must never fall back to `ssh-storage` or an
  existing alias on missing/corrupt state. A missing previously created key is an
  error, not an instruction to silently generate a replacement.
- Bind operations and saves to the selected profile. New-profile initialization
  failures may leave only clearly marked, resumable personal setup state; they
  must never touch the default profile or delete a key whose ownership is unclear.
- One active phone listener at a time (existing port). Switching profiles closes
  its session first; an unexpected profile/identity mismatch fails closed.

## Shared application and destructive actions

- Application code and launcher remain shared; they are not credentials. Both
  devices need the profile-capable release before personal pairing.
- Preserve the selected profile across application-update restart, but show it
  again. Keep existing update message names and fields compatible.
- Creation/switching does not silently update a phone or re-pair either profile.
- Personal pairing must not accept an empty recovery key (team-member mode).
- Pairing, cancellation, sign approval, rekey and recovery act only within the
  selected profile. Never send old-profile signing or administration requests as
  part of personal setup.
- Adapt erase actions before exposing the new profile: erasing one profile must
  never remove another profile's key, state or shared launcher/application.
  Preserve the existing default-profile erase behavior when no personal profile
  exists. If a shared uninstall would orphan another profile, block it and explain
  why; do not silently redefine it as a cross-profile wipe.
- Do not automatically install keys, disable SSH passwords, change root access,
  delete connections or revoke old keys just because a profile was created.

## Project structure and style

- `sshstore.py`: profile selection, isolated initialization, both menus, alias
  handling and profile-safe lifecycle actions.
- `ssh-storage.nix`: generated embedded application; keep byte-for-byte parity.
- `tests/test_profiles.py`: isolation, initialization failures, menu and protocol
  integration tests; keep existing tests and fixtures working.
- Existing README manuals, CHANGELOG.md and SECURITY.md: operator instructions,
  limitations, compatibility and real-device test status.
- Match existing small functions and standard-library unittest conventions:

```python
if profile not in ("default", "personal"):
    raise ValueError("Unknown profile")
```

No broad refactor of SSH setup, network crypto or team administration is included.

## Commands

From the repository root:

```sh
python3 -m unittest discover -s tests -p test_profiles.py -v
python3 scripts/sync_nix.py
python3 scripts/sync_nix.py --check
python3 -m unittest discover -s tests -v
git diff --check
```

After review and tests, optional NixOS build without activating the system:

```sh
nixos-rebuild build --flake /etc/nixos#nixos --no-update-lock-file
```

Do not switch the actual user's profile or activate server changes during agent
verification. Applying the NixOS configuration remains a separate explicit step.

## Testing strategy and acceptance criteria

- Tests first for each behavior; standard library unittest, isolated temporary
  state roots and fake Keystore at the hardware boundary.
- After personal initialization/pairing, old state bytes, old alias/key and old
  peer lists remain unchanged. Old encrypted signing sessions still work.
- Personal pairing keys, phone SSH public key and recovery key differ from those
  of the old profile; no cached servers, rights or secrets cross between them.
- Verify switching both ways, restart into the requested profile, and ordinary
  launch into default. Discovery must not silently select the wrong phone profile.
- Invalid IDs, symlink paths, existing/corrupt personal state, failed key generation,
  disk errors, interrupted password entry, denied pairing and dropped connections
  fail closed without changing default state.
- Profile erase/rekey tests prove the other profile and shared program survive.
- Wrong-profile signing and personal pairing without recovery must be rejected.
- All existing tests pass without suppressions or skipped security tests; embedded
  Nix Python matches source exactly.
- Before claiming production readiness, manually test on the actual Android phone:
  both profiles' public keys differ, the existing server still accepts the old
  profile, a disposable VPS accepts only the explicitly installed new identity,
  switching and denied approvals work, and a failed setup preserves existing access.
  Keep a provider console and separate recovery path open throughout.

## Boundaries and rollout

- Always: validate profile selection before state/key access; preserve old state;
  show the selected identity; retain audit logs; require user and phone approval.
- Ask first: any credential migration, changing the default profile, installing
  new keys on real servers, applying NixOS changes, or broader team hardening.
- Never: promote a participant by editing `recovery`, copy team credentials into
  personal state, delete existing keys, log recovery passwords, or claim server
  privileges based on a local role flag.
- Rollout: land isolated behavior and tests, synchronize generated Nix module,
  review/build, then let the user deliberately create profiles and test with a
  disposable server. Existing users stay on the legacy/default path.

## Open decision

The user approved proceeding after the concrete contract was summarized. No
additional preference is required: manual profile selection and no automatic
migration or installation on existing servers.

## Local verification result

- 110 unit/integration tests pass, including 34 profile tests. Pairing tests use
  the actual encrypted protocol over local sockets and fake only the Keystore
  hardware boundary and human prompts.
- A real CLI menu → creation → exec restart scenario preserves the existing state
  bytes; an inverted profile-check mutation is detected by the pairing test.
- Review findings for cross-profile destructive wipe-rekey and contradictory
  initialization metadata were reproduced with failing tests and fixed.
- Generated Nix source and the prepared `/etc/nixos/home/ssh-storage.nix` copy
  match. NixOS build passes and its Python matches the source exactly.
- No real personal profile, phone update, SSH authorization changes or system
  activation were performed. Android and disposable-VPS acceptance checks remain
  necessary; no guarantee of zero regressions or security certification is claimed.
