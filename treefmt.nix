{ pkgs, ... }:
{
  projectRootFile = "flake.nix";
  programs.mdformat.enable = true;
  programs.nixfmt.enable = true;
  programs.ruff-check.enable = true;
  programs.ruff-format.enable = true;
}
