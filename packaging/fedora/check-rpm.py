#!/usr/bin/env python3
"""Selected existing provider contracts plus positive stock-CLI integration.

The runner only uses newly generated test keys and the supplied build modules.
It does not edit host configuration or claim a code-generation acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

if len(sys.argv) != 5:
    raise SystemExit('usage: check-rpm.py SOURCE MODULES LIBDIR OUTPUT')
source, modules, libdir, output = (Path(x).resolve() for x in sys.argv[1:])
output.mkdir(mode=0o700)
(output / 'logs').mkdir()
(output / 'bin').mkdir()
(output / 'generated').mkdir()
(output / 'prefix').mkdir()
(output / 'prefix/lib').symlink_to(libdir, target_is_directory=True)
env = {'PATH': '/usr/bin:/bin', 'HOME': str(output), 'LC_ALL': 'C',
       'OPENSSL_CONF': '/dev/null', 'OPENSSL_MODULES': str(modules),
       'ED301V2_EXPECT_OPENSSL_PREFIX': str(output / 'prefix')}
# Fedora's GCC package-note specs consume these build identities even for
# the test harnesses. Preserve only the required RPM metadata, not arbitrary
# compiler-override variables from the calling environment.
for name in ('RPM_ARCH', 'RPM_PACKAGE_NAME', 'RPM_PACKAGE_VERSION',
             'RPM_PACKAGE_RELEASE', 'SOURCE_DATE_EPOCH'):
    if name in os.environ:
        env[name] = os.environ[name]
records = []

def run(name, args, environment=None):
    argv = list(map(str, args))
    print('STEP ' + name, flush=True)
    result = subprocess.run(argv, env=environment or env, cwd=source,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
    log = output / 'logs' / (name + '.log')
    log.write_bytes(result.stdout)
    records.append({'step': name, 'argv': argv, 'exit': result.returncode,
                    'log_sha256': hashlib.sha256(result.stdout).hexdigest()})
    (output / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    if result.returncode:
        sys.stdout.buffer.write(result.stdout)
        raise SystemExit('failed: ' + name)
    return result.stdout.decode(errors='replace')

expected = {'ed301_eddsa_v2.so', 'ed301_eddsa_v2_tls.so', 'x301_v2.so', 'x301_v2_tls.so'}
if {p.name for p in modules.iterdir()} != expected:
    raise SystemExit('shipping module inventory differs from the four approved variants')
for module in sorted(modules.iterdir()):
    exports = run(module.stem + '-exports', ['nm', '-D', '--defined-only', module])
    if [l.split()[-1] for l in exports.splitlines() if ' T ' in l] != ['OSSL_provider_init']:
        raise SystemExit('unexpected exported functions')
    dynamic = run(module.stem + '-dynamic', ['readelf', '-d', module])
    if '(RPATH)' in dynamic or '(RUNPATH)' in dynamic:
        raise SystemExit('runtime module has an embedded library search path')

run('ed-vectors', ['python3', '-I', '-B', source / 'provider-tests/gen_vectors.py', source,
                  output / 'generated/vectors.h', output / 'generated/policy_vectors_data.rs'])
run('ed-vectors-format', ['rustfmt', '--edition', '2024', output / 'generated/policy_vectors_data.rs'])
run('ed-vectors-compare', ['cmp', output / 'generated/policy_vectors_data.rs',
                         source / 'provider/crates/ed301-eddsa-provider/src/policy_vectors_data.rs'])
run('x-vectors', ['python3', '-I', '-B', source / 'provider-tests/x301/gen_vectors.py',
                 output / 'generated/generated'])
cflags = shlex.split(os.environ.get('CFLAGS', '-O2'))
ldflags = shlex.split(os.environ.get('LDFLAGS', ''))

def build(name, relative, extra=()):
    run('compile-' + name, ['gcc', *cflags, '-std=c11', '-D_GNU_SOURCE',
        '-Wall', '-Wextra', '-Werror', '-I' + str(output / 'generated'),
        '-I' + str(source / 'provider-tests'), *extra, source / relative,
        '-o', output / 'bin' / name, *ldflags, '-lssl', '-lcrypto', '-ldl', '-pthread'])

for name in ('provider_keymgmt', 'provider_signature', 'provider_context_contract'):
    build(name, 'provider-tests/' + name + '.c')
    run(name, [output / 'bin' / name])
for name in ('provider_x301_contract', 'provider_x301_hybrid_contract',
             'provider_x301_nested_properties', 'provider_x301_hybrid_kat'):
    build(name, 'provider-tests/x301/' + name + '.c')
    run(name, [output / 'bin' / name, modules])
build('x301_tls_contract', 'provider-tests/x301/provider_x301_contract.c',
      ['-DX301_PROVIDER="x301_v2_tls"'])
run('x301_tls_contract', [output / 'bin/x301_tls_contract', modules])
build('provider_default_context', 'provider-tests/provider_default_context.c')

# A child-process configuration, not a change to the installed system config.
config = output / 'process-default.cnf'
config.write_text('config_diagnostics = 1\nopenssl_conf = init\nextensions = empty_extensions\n'
    '[init]\nproviders = providers\n[providers]\ndefault = builtin\n'
    'ed301_eddsa_v2_tls = ed\nx301_v2_tls = x\n[builtin]\nactivate = 1\n'
    '[ed]\nactivate = 1\n[x]\nactivate = 1\n[empty_extensions]\n')
active = dict(env, OPENSSL_CONF=str(config))
run('process-default-context', [output / 'bin/provider_default_context'], active)

def cli(name, *arguments):
    return run(name, ['openssl', *arguments], active)

for tag, algorithm in [('ed', 'Ed301-EdDSA'), ('x', 'X301')]:
    cli(tag + '-keygen', 'genpkey', '-algorithm', algorithm, '-out', output / (tag + '.key'))
    cli(tag + '-key-check', 'pkey', '-in', output / (tag + '.key'), '-check', '-noout')
    cli(tag + '-public', 'pkey', '-in', output / (tag + '.key'), '-pubout', '-out', output / (tag + '.pub'))
    cli(tag + '-encrypted', 'pkcs8', '-topk8', '-in', output / (tag + '.key'),
        '-v2', 'aes-256-cbc', '-passout', 'pass:rpm-test-only', '-out', output / (tag + '.encrypted'))
    cli(tag + '-decrypt', 'pkey', '-in', output / (tag + '.encrypted'), '-passin', 'pass:rpm-test-only',
        '-out', output / (tag + '.roundtrip'))
    if (output / (tag + '.key')).read_bytes() != (output / (tag + '.roundtrip')).read_bytes():
        raise SystemExit('private-key roundtrip changed the test key')
    args = ['pkcs12', '-export', '-inkey', output / (tag + '.key'), '-nocerts',
            '-passout', 'pass:rpm-test-only', '-out', output / (tag + '.p12')]
    cli(tag + '-pkcs12-export', *args)
    cli(tag + '-pkcs12-import', 'pkcs12', '-in', output / (tag + '.p12'), '-nocerts', '-noenc',
        '-passin', 'pass:rpm-test-only', '-out', output / (tag + '.p12.key'))
    cli(tag + '-pkcs12-public', 'pkey', '-in', output / (tag + '.p12.key'), '-pubout',
        '-out', output / (tag + '.p12.pub'))
    if (output / (tag + '.pub')).read_bytes() != (output / (tag + '.p12.pub')).read_bytes():
        raise SystemExit('PKCS12 changed the key identity')

cli('ca-certificate', 'req', '-new', '-x509', '-key', output / 'ed.key', '-subj', '/CN=RPM test CA',
    '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', output / 'ca.crt')
cli('leaf-key', 'genpkey', '-algorithm', 'Ed301-EdDSA', '-out', output / 'leaf.key')
cli('leaf-request', 'req', '-new', '-key', output / 'leaf.key', '-subj', '/CN=rpm.test.example',
    '-addext', 'subjectAltName=DNS:rpm.test.example', '-out', output / 'leaf.csr')
if 'self-signature verify OK' not in cli('csr-verify', 'req', '-in', output / 'leaf.csr', '-verify', '-noout'):
    raise SystemExit('stock req did not attest CSR verification')
cli('leaf-issue', 'x509', '-req', '-in', output / 'leaf.csr', '-CA', output / 'ca.crt',
    '-CAkey', output / 'ed.key', '-set_serial', '2', '-days', '1', '-copy_extensions', 'copy',
    '-out', output / 'leaf.crt')
cli('chain-verify', 'verify', '-no-CApath', '-no-CAstore', '-CAfile', output / 'ca.crt',
    '-check_ss_sig', '-verify_hostname', 'rpm.test.example', output / 'leaf.crt')
cli('peer-key', 'genpkey', '-algorithm', 'X301', '-out', output / 'peer.key')
cli('peer-public', 'pkey', '-in', output / 'peer.key', '-pubout', '-out', output / 'peer.pub')
cli('derive-a', 'pkeyutl', '-derive', '-inkey', output / 'x.key', '-peerkey', output / 'peer.pub',
    '-out', output / 'shared-a')
cli('derive-b', 'pkeyutl', '-derive', '-inkey', output / 'peer.key', '-peerkey', output / 'x.pub',
    '-out', output / 'shared-b')
shared = (output / 'shared-a').read_bytes()
if len(shared) != 38 or shared == bytes(38) or shared != (output / 'shared-b').read_bytes():
    raise SystemExit('bidirectional X301 derive mismatch')
(output / 'RESULT.json').write_text(json.dumps({'status': 'PASS', 'commands': len(records),
    'scope': 'selected provider contracts and process-default CLI, no installed-policy or codegen acceptance',
    'source_changes': False, 'host_activation': False}, indent=2) + '\n')
print('RPM_FUNCTIONAL_CHECKS=PASS commands=' + str(len(records)))
