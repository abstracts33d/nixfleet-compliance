# lib/priorities.nix
#
# Map governance level strings to NixOS module override priorities.
# Stricter level -> lower number -> wins in module merge.
#
# When multiple frameworks are active (e.g., NIS2 essential + ANSSI intermediary),
# the stricter framework's values win automatically without consumer-side workarounds.
{lib}: {
  # Map a governance level to its NixOS override priority number.
  levelToPriority = level:
    {
      "paranoid" = 60;
      "strict" = 70;
      "standard" = 80;
      "minimal" = 90;
    }
    .${
      level
    }
    or 1000;

  # Wrap a value with the priority for a given governance level.
  # Usage: mkPriority "strict" 730  ->  lib.mkOverride 70 730
  mkPriority = level: value:
    lib.mkOverride
    ({
        "paranoid" = 60;
        "strict" = 70;
        "standard" = 80;
        "minimal" = 90;
      }
      .${
        level
      }
      or 1000)
    value;
}
