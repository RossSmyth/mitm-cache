{
  system ? builtins.currentSystem or "x86_64-linux",
  inputs ? import ./npins { },
  pkgs ? import inputs.nixpkgs { inherit system; },
  mitm-cache ? import ./. { inherit system inputs pkgs; },
}:
let
  inherit (pkgs) mkShell;
in
mkShell {
  inputsFrom = [
    mitm-cache
  ];

  packages = with pkgs; [
    rust-analyzer
    rustfmt
  ];
}
