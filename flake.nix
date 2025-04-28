{
  description = "Hunt sql commands in pcap";

  inputs = { nixpkgs.url = "github:NixOS/nixpkgs/"; };

  outputs = { self, nixpkgs, ... }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };

      devShells = pkgs.mkShell {
        buildInputs = [
          pkgs.python312
          pkgs.python312Packages.flake8
          pkgs.python312Packages.pyshark
          pkgs.python312Packages.tabulate
          pkgs.python312Packages.tqdm
          pkgs.tshark
        ];

        shellHook = ''
          flake8 PsqlHunter.py
        '';
      };
    in { devShells.x86_64-linux.default = devShells; };
}
