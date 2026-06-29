{
  system ? builtins.currentSystem or "x86_64-linux",
  inputs ? import ./npins { },
  pkgs ? import inputs.nixpkgs { inherit system; },
}:
let
  inherit (pkgs) rustPlatform lib;
in
rustPlatform.buildRustPackage {
  pname = "mitm-cache";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./src
      ./Cargo.lock
      ./Cargo.toml
    ];
  };

  nativeBuildInputs = with pkgs; [
    pkg-config
  ];

  buildInputs = with pkgs; [
    aws-lc
    zstd
  ];

  env = {
    AWS_LC_SYS_USE_SYSTEM = true;
    ZSTD_SYS_USE_PKG_CONFIG = true;
  };

  cargoLock.lockFile = ./Cargo.lock;
}
