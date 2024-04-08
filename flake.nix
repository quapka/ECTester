{
  description = "ECTester";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        # pythonPackages = with pkgs.python310Packages; [
        #   venvShellHook
        #   pyyaml
        #   numpy
        #   jinja2
        #   typing-extensions
        # ];
      in
      with pkgs;
      {
        devShells.default = mkShell rec {
          buildInputs = [
            ant
            jdk11
            pkg-config
            global-platform-pro
            gradle
            # libraries to test
            openssl
            boringssl
            libressl
            libtomcrypt
            libtommath
            botan2
            cryptopp

            # libraries' dependencies
            cmake
            ninja
            gawk
            automake
            go
            gtest
            libunwind
            autoconf
            libb64

            clang
            libgcrypt
            mbedtls
            nasm
            libtool
            perl

            wolfssl
            nettle
            libressl

            gmp
            libgpg-error
            wget
          ];

          LD_LIBRARY_PATH = with pkgs; pkgs.lib.makeLibraryPath [
            libtomcrypt
            cryptopp
            nettle
          ];

          # NOTE: Mixing postVenvCreation aznd shellHook results in only shellHook being called
          # shellHook = ''
          #   source ${venvDir}/bin/activate
          #   export PATH=$PATH:$HOME/projects/ts-spect-compiler/build/src/apps;
          #   export TS_REPO_ROOT=`pwd`;
          # '';
        buildBoringSSL = ''
          mkdir --parents build
          pushd build
          cmake -GNinja -DBUILD_SHARED_LIBS=1 ..
          ninja
          popd
        '';

        buildLibreSSL = ''
          ./autogen.sh
          mkdir --parents build
          pushd build
          cmake -GNinja -DBUILD_SHARED_LIBS=1 ..
          ninja
          popd
        '';

        buildIppCrypto = ''
          CC=clang CXX=clang++ cmake CMakeLists.txt -GNinja -Bbuild -DARCH=intel64  # Does not work with GCC 12+
          mkdir --parents build
          pushd build
          ninja
          popd
         '';

         buildMbedTLS = ''
           python -m venv virt
           . virt/bin/activate
           pip install -r scripts/basic.requirements.txt
           cmake -GNinja -Bbuild -DUSE_SHARED_MBEDTLS_LIBRARY=On
           cd build
           ninja
         '';

        # shellHook = ''
        #   pushd ext/mbedtls
        #   ${buildMbedTLS}
        #   popd
        # '';
        #   git submodule update --init --recursive

        #   pushd ext/boringssl
        #   ${buildBoringSSL}
        #   popd

        #   pushd ext/ipp-crypto
        #   ${buildIppCrypto}
        #   popd

        #   pushd ext/libressl
        #   ${buildLibreSSL}
        #   popd
        # '';

        };
      }
    );
}
