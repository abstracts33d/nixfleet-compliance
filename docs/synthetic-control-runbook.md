# Runbook -- verifying enforce-mode rollback with the synthetic control

`controls/_synthetic.nix` ships an opt-in always-fail control. Its sole
purpose is to drive the agent's enforce-mode runtime gate end-to-end on
a real host without depending on a real compliance gap.

## When to run this

After any change to:

- `nixfleet-agent`'s gate orchestration (`apply_gate_outcome`,
  `trigger_rollback_with_reason`, `process_gate_outcome`).
- The CP-side wave-promotion gate (`wave_gate.rs`).
- The boot-recovery flow (`recovery.rs`).

Or whenever you want to confirm "enforce actually enforces" before
flipping a production channel.

## Test target

A throwaway host. Options, easiest first:

1. **A QEMU VM provisioned with `nix run .#test-vm -- -h <hostname>`** from
   the fleet repo. Most isolated; the rollback only affects the VM.
2. **An idle real host** (e.g. a re-purposed laptop on the Tailnet). Same
   guarantees as a VM but takes longer to set up.
3. **A live workstation** -- only if you are willing to ssh in and
   manually `nixos-rebuild switch --flake .#hostname --target-host
   root@host` if anything goes sideways.

Do not run this against `lab` (the coordinator). A failed gate on the
host running the CP would brick fleet-wide convergence.

## Procedure

1. **Wire the synthetic control** in the test host's NixOS config:

       {inputs, ...}: {
         imports = [
           "${inputs.compliance}/controls/_synthetic.nix"
         ];
         compliance.controls.synthetic.alwaysFail.enable = true;
       }

2. **Set the host's channel to enforce.** In the consumer flake (e.g.
   `fleet/fleet.nix`), confirm the channel the test host is on has
   `compliance.mode = "enforce"`.

3. **Push, let CI sign, wait for dispatch.** The CP issues a rollout
   targeting the closure with the synthetic control enabled.

4. **Watch the agent journal on the test host:**

       journalctl -u nixfleet-agent.service -f

   Expected sequence after activation:

   ```
   compliance gate: failures -- posting per-control events count=N
   compliance gate: failures -- refusing confirm + rolling back (enforce mode)
   ```

5. **Verify the rollback landed:**

   - `readlink /run/current-system` points at the *previous* closure, not
     the one the dispatch targeted.
   - `nix-env --profile /nix/var/nix/profiles/system --list-generations`
     shows the new generation marked but the active one rolled back.
   - On the CP, the host should have a `RollbackTriggered` event
     attributed to "compliance failures: synthetic-always-fail".

6. **Tear down.** Remove the import + the channel-mode flip. Push again;
   the host re-converges to a clean closure.

## Failure modes worth distinguishing

- **Rollback didn't fire** -- agent log shows `posting per-control events`
  but no `refusing confirm`. Means the channel mode resolved to permissive
  (check `target.compliance_mode` in the dispatch envelope) or the gate
  code path you intended to test isn't running. Verify with:

      systemctl show nixfleet-agent.service --property=ExecStart
      systemctl status nixfleet-agent.service

- **Rollback fired but host is wedged** -- `nix-env --rollback` failed.
  Manual recovery: ssh as root, run `nix-env --profile
  /nix/var/nix/profiles/system --rollback` and reboot.

- **CP sees no `RollbackTriggered` event** -- agent's `evidence_signer`
  isn't loaded (no SSH host key) OR the CP rejected the event signature.
  Check agent journal for `evidence_signer.sign failed`.
