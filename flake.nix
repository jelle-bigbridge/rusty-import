{
  description = "A very basic flake";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.mozilla.url = "github:oxalica/rust-overlay";

  outputs =
    { self
    , nixpkgs
    , mozilla
    , flake-utils
    }: flake-utils.lib.eachSystem [ "x86_64-linux" "x86_64-darwin" "aarch64-darwin" ] (system:

    let
      pkgs = import nixpkgs {
        inherit system;
      };
      muslPkgs = (import nixpkgs {
        localSystem = "x86_64-linux";
        overlays = [ mozilla.overlays.rust-overlay ];
      });
      # rust = (muslPkgs.rustChannelOf { channel = "stable"; }).rust.override {
      #   targets = [ "x86_64-unknown-linux-musl" ];
      # };
      rust = muslPkgs.rust-bin.stable.latest.default.override {
        targets = [ "x86_64-unknown-linux-musl" ];
      };
      rustPlatform = muslPkgs.makeRustPlatform {
        cargo = rust;
        rustc = rust;
      };

      rusty-import-musl-linux = rustPlatform.buildRustPackage {
        name = "rusty-import";
        src = ./.;
        cargoLock = { lockFile = ./Cargo.lock; };

        target = "x86_64-unknown-linux-musl";

        preBuild = ''
          export RUSTFLAGS="-C target-feature=+crt-static"
          export STATIC_BINARY="$out/bin/rusty-import"
        '';
      };


      rusty-import = pkgs.rustPlatform.buildRustPackage {
        name = "rusty-import";
        src = ./.;
        cargoLock = { lockFile = ./Cargo.lock; };

        preBuild = ''
          export STATIC_BINARY=${rusty-import-musl-linux}/bin/rusty-import
        '';
      };
    in
    {
      packages = rec {
        default = rusty-import;
        inherit rusty-import;
      };
    });
}
