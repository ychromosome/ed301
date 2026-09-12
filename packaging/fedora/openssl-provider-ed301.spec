%bcond_without tests
%global commit 1ebf575a43ad60dec3efdd4ec5363c15753e33ec
%global shortcommit 1ebf575
%global snapshot 20260912
%global source_archive_sha256 2cbcf5e7514835a55178f99011e3f2bb972d1e8b577dc6ad9dde7f5545a360bf
%global provider_modulesdir %{_libdir}/ossl-modules
%global __provides_exclude_from ^%{provider_modulesdir}/.*\\.so$
%global _smp_mflags -j4

Name:           openssl-provider-ed301
Version:        0.2.0
Release:        0.1.%{snapshot}git%{shortcommit}%{?dist}
Summary:        Experimental Ed301-EdDSA and X301 OpenSSL providers
License:        Apache-2.0
URL:            https://github.com/ychromosome/ed301
# Reproducible git archive of the exact commit, not a relabelled old RPM.
Source0:        ed301-%{commit}.tar.gz
Source1:        ed301-v2.conf
Source2:        README.rpm
Source3:        check-rpm.py
Patch0:         0001-Explicitly-allow-Fedora-native-package-flags.patch

ExclusiveArch:  x86_64
BuildRequires:  cargo-rpm-macros
BuildRequires:  cargo >= 1.91
BuildRequires:  rust >= 1.91
BuildRequires:  gcc
BuildRequires:  binutils
BuildRequires:  openssl-devel >= 1:4.0.1
BuildRequires:  openssl >= 1:4.0.1
BuildRequires:  python3
BuildRequires:  rustfmt
BuildRequires:  gawk
Requires:       openssl-libs%{?_isa} >= 1:4.0.1
Requires:       openssl-libs%{?_isa} < 1:5
# Deliberately no Provides claiming v1 API compatibility.
# Mixed-generation automatic activation is unsupported.
Conflicts:      ed301-openssl-provider
Conflicts:      ed301-openssl-provider-policy
Conflicts:      x301-openssl-provider
Conflicts:      x301-openssl-provider-policy
Conflicts:      ed301-four-component-review
Provides:       bundled(crate(crypto-bigint)) = 0.7.5

%description
Ed301-EdDSA-v2 signatures and X301-v2 raw key exchange, including separately
named TLS-capable modules with the X301MLKEM1024 hybrid group. Installing
the software alone does not activate providers or change Fedora policy.
This is experimental software, not a standardized or FIPS-validated
algorithm and not a production or new compiler security approval.

%package policy
Summary:        Explicit activation of the matching Ed301 and X301 providers
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       openssl >= 1:4.0.1

%description policy
Activates the matching Ed301-EdDSA-v2 and X301-v2 TLS-capable provider modules
through Fedora's OpenSSL configuration hook. This package does not replace
the selected crypto-policy or change OpenSSL's DEFAULT TLS group list.

%package -n ed301
Summary:        Combined cryptographic providers with matching activation
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       %{name}-policy = %{version}-%{release}

%description -n ed301
A meta-package requiring the matching combined software and policy packages.
X301 does not require a separate package stream.

%prep
test "$(sha256sum %{SOURCE0} | awk '{print $1}')" = %{source_archive_sha256}
%setup -q -n ed301-%{commit}
%autopatch -p1
install -pm 0644 %{SOURCE2} README.rpm
pushd provider
%cargo_prep -v ../rust/vendor
popd
pushd rust
%cargo_prep -v vendor
popd
pushd rust/crates/x301
%cargo_prep -v ../../vendor
popd

%build
%set_build_flags
export CC=/usr/bin/gcc AR=/usr/bin/ar
export ED301_HERMETIC_PROVIDER_BUILD=1 X301_HERMETIC_PROVIDER_BUILD=1
export ED301_ALLOW_PACKAGE_BUILD_FLAGS=1 X301_ALLOW_PACKAGE_BUILD_FLAGS=1
export OPENSSL_INCLUDE_DIR=%{_includedir} OPENSSL_LIB_DIR=%{_libdir}
export CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
root="$PWD"
export RUSTC_WRAPPER="$root/phase-d/d2/tools/rustc_profile_guard.sh"
mkdir -p rpm-work/modules rpm-work/markers rpm-work/license
rustc --version --verbose > rpm-work/toolchain.txt
rpm -q rust cargo gcc openssl openssl-libs openssl-devel redhat-rpm-config > rpm-work/toolchain-rpms.txt
pushd provider
for variant in ed-normal ed-tls x-normal x-tls; do
    feature=
    case "$variant" in
        ed-normal) package=ed301-eddsa-provider; library=ed301_eddsa_v2; module=ed301_eddsa_v2 ;;
        ed-tls) package=ed301-eddsa-provider; library=ed301_eddsa_v2; module=ed301_eddsa_v2_tls; feature=tls-experiment ;;
        x-normal) package=x301-provider; library=x301_v2; module=x301_v2 ;;
        x-tls) package=x301-provider; library=x301_v2; module=x301_v2_tls; feature=tls-x301-mlkem1024 ;;
    esac
    export CARGO_TARGET_DIR="$root/rpm-work/targets/$variant"
    export ED301_PROFILE_MARKER_DIR="$root/rpm-work/markers/$variant"
    mkdir -p "$ED301_PROFILE_MARKER_DIR"
    cp "$root/rpm-work/toolchain.txt" "$ED301_PROFILE_MARKER_DIR/toolchain.txt"
    if test -n "$feature"; then
        %cargo_build -- -p "$package" --features "$feature" --locked --offline -vv
    else
        %cargo_build -- -p "$package" --locked --offline -vv
    fi
    sh "$root/rust/scripts/check-profile-markers.sh" "$ED301_PROFILE_MARKER_DIR" crypto_bigint=on "$library=on"
    install -pm 0755 "$CARGO_TARGET_DIR/rpm/lib$library.so" "$root/rpm-work/modules/$module.so"
done
unset CARGO_TARGET_DIR
export CARGO_HOME="$PWD/.cargo"
pushd crates/ed301-eddsa-provider
%cargo_license_summary -f tls-experiment
%{cargo_license -f tls-experiment} > "$root/rpm-work/license/ed301.dependencies"
popd
pushd crates/x301-provider
%cargo_license_summary -f tls-x301-mlkem1024
%{cargo_license -f tls-x301-mlkem1024} > "$root/rpm-work/license/x301.dependencies"
popd
%cargo_vendor_manifest
sed -i '/ (/d' cargo-vendor.txt
popd

%install
install -d %{buildroot}%{provider_modulesdir}
install -pm 0755 rpm-work/modules/*.so %{buildroot}%{provider_modulesdir}/
install -Dpm 0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/pki/tls/openssl.d/ed301-v2.conf

%check
%if %{with tests}
%set_build_flags
export CC=/usr/bin/gcc AR=/usr/bin/ar
export ED301_HERMETIC_PROVIDER_BUILD=1 X301_HERMETIC_PROVIDER_BUILD=1
export ED301_ALLOW_PACKAGE_BUILD_FLAGS=1 X301_ALLOW_PACKAGE_BUILD_FLAGS=1
export OPENSSL_INCLUDE_DIR=%{_includedir} OPENSSL_LIB_DIR=%{_libdir}
export CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
root="$PWD"
export RUSTC_WRAPPER="$root/phase-d/d2/tools/rustc_profile_guard.sh"
export ED301_PROFILE_MARKER_DIR="$root/rpm-work/markers/unit"
mkdir -p "$ED301_PROFILE_MARKER_DIR"
export CARGO_TARGET_DIR="$root/rpm-work/targets/unit-provider"
pushd provider
%cargo_test -- --workspace --locked --offline
popd
export CARGO_TARGET_DIR="$root/rpm-work/targets/unit-ed"
pushd rust
%cargo_test -- --workspace --locked --offline
%cargo_test -f sign-self-verify -- --workspace --locked --offline
popd
export CARGO_TARGET_DIR="$root/rpm-work/targets/unit-x"
pushd rust/crates/x301
%cargo_test -- --locked --offline
popd
python3 -I -B %{SOURCE3} "$root" "$root/rpm-work/modules" "%{_libdir}" "$root/rpm-work/checks"
%endif

%files
%license LICENSE
%license rpm-work/license/ed301.dependencies
%license rpm-work/license/x301.dependencies
%license provider/cargo-vendor.txt
%doc README.rpm
%doc specifications/Ed301-EdDSA-v2.md specifications/X301-v2.md docs/OID_REGISTRY.md
%{provider_modulesdir}/ed301_eddsa_v2.so
%{provider_modulesdir}/ed301_eddsa_v2_tls.so
%{provider_modulesdir}/x301_v2.so
%{provider_modulesdir}/x301_v2_tls.so

%files policy
%doc README.rpm
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.d/ed301-v2.conf

%files -n ed301
%doc README.rpm

%posttrans policy
echo 'Ed301-EdDSA and X301 v2 provider activation installed for new OpenSSL contexts.'
echo 'Experimental, not FIPS validated; Fedora crypto-policy and DEFAULT groups unchanged.'
exit 0

%changelog
* Sat Sep 12 2026 Martin Wolf <mwolf@adiumentum.com> - 0.2.0-0.1.20260912git1ebf575
- Combine Ed301-EdDSA-v2 and X301-v2 software under the Fedora addon naming scheme
- Separate matching policy activation and the ed301 meta-package
- Keep legacy activation conflicts explicit and retain offline source-bound builds
