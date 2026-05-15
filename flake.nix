{
  description = "deerquic — a QUIC implementation in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay ];
      };
      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
      };
    in
    {
      packages.${system} = rec {
        deerquic = pkgs.rustPlatform.buildRustPackage {
          pname = "deerquic";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = with pkgs; [ pkg-config ];
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          meta = with pkgs.lib; {
            description = "A feature-complete QUIC implementation in Rust";
            license = with licenses; [ mit asl20 ];
          };
        };
        default = deerquic;
      };

      devShells.${system}.default = pkgs.mkShell {
        name = "deerquic-dev";
        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
        ];
        RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        shellHook = ''
          echo "deerquic dev shell — rustc $(rustc --version)"
        '';
      };
    };
}
