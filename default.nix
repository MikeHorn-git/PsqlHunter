{ pkgs ? import <nixpkgs> {} }:

pkgs.stdenv.mkDerivation rec {
  pname = "PsqlHunter";
  version = "1.0.0";

  src = pkgs.fetchFromGitHub {
    owner = "MikeHorn-git";
    repo = "PsqlHunter";
    rev = "2f435cae19a33da8964314abbc7fd4fb7fcd3c4d";
    hash = "sha256-gqIkoO4AQMxA/PmJ51gM/juTK0xMuWym0e/ce0Z2qvI=";
  };

  nativeBuildInputs = [ pkgs.python3Packages.virtualenv ];

  buildInputs = [
    pkgs.python3
    pkgs.python3Packages.appdirs
    pkgs.python3Packages.lxml
    pkgs.python3Packages.packaging
    pkgs.python3Packages.pyshark
    pkgs.python3Packages.tabulate
    pkgs.python3Packages.termcolor
    pkgs.python3Packages.tqdm
  ];

  installPhase = ''
    mkdir -p $out/bin
    cp $src/PsqlHunter.py $out/bin/PsqlHunter
    chmod +x $out/bin/PsqlHunter
  '';

  meta = with pkgs.lib; {
    description = "Hunt sql commands in pcap.";
    license = licenses.mit;
    maintainers = with maintainers; [ "MikeHorn-git" ];
  };
}
