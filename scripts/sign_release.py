#!/usr/bin/env python3
"""
Sign Release - Build-time signing script for Boundary Daemon.

This script is used during the release build process to:
1. Generate signing keys (if needed)
2. Hash all daemon Python modules
3. Create a signed manifest
4. Output files for distribution

Usage:
    # Generate a new signing keypair
    python scripts/sign_release.py keygen --output keys/

    # Sign a release
    python scripts/sign_release.py sign \
        --daemon-dir daemon/ \
        --version 2.0.0 \
        --key keys/signing.key \
        --output dist/

    # Verify a signed release
    python scripts/sign_release.py verify \
        --manifest dist/manifest.json \
        --daemon-dir daemon/ \
        --public-key keys/signing.pub

Examples:
    # Development: Generate keys and sign
    $ python scripts/sign_release.py keygen -o .keys/
    $ python scripts/sign_release.py sign -d daemon/ -v dev -k .keys/signing.key

    # CI/CD: Sign with existing key
    $ python scripts/sign_release.py sign \\
        -d daemon/ \\
        -v ${VERSION} \\
        -k ${SIGNING_KEY_PATH} \\
        -o dist/

Security Notes:
    - Keep the private signing key OFFLINE and secure
    - The public key should be embedded in your deployment config
    - Verify signatures before running any daemon code
    - Rotate keys periodically and on any suspected compromise
"""

import argparse
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from daemon.integrity.code_signer import CodeSigner
    from daemon.integrity.integrity_verifier import IntegrityVerifier
except ImportError:
    # Fallback for standalone execution
    print("Warning: Running in standalone mode", file=sys.stderr)
    CodeSigner = None


def cmd_keygen(args):
    """Generate a new signing keypair."""
    if CodeSigner is None:
        print("Error: CodeSigner not available", file=sys.stderr)
        return 1

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    signer = CodeSigner()
    private_key, public_key = signer.generate_keypair()

    # Save private key
    private_path = output_dir / "signing.key"
    with open(private_path, 'wb') as f:
        f.write(private_key)
    os.chmod(private_path, 0o600)  # Owner read/write only
    print(f"Private key saved to: {private_path}")

    # Save public key
    public_path = output_dir / "signing.pub"
    with open(public_path, 'wb') as f:
        f.write(public_key)
    print(f"Public key saved to: {public_path}")

    # Also save hex-encoded versions for config embedding
    hex_path = output_dir / "signing.pub.hex"
    with open(hex_path, 'w') as f:
        f.write(public_key.hex())
    print(f"Public key (hex) saved to: {hex_path}")

    print()
    print("=" * 60)
    print("IMPORTANT SECURITY NOTES:")
    print("=" * 60)
    print(f"1. Keep {private_path} OFFLINE and secure")
    print(f"2. Add {public_path} to your deployment configuration")
    print("3. Never commit the private key to version control")
    print("4. Consider using hardware security modules (HSM) for production")
    print("=" * 60)

    return 0


def cmd_sign(args):
    """Sign a daemon release."""
    if CodeSigner is None:
        print("Error: CodeSigner not available", file=sys.stderr)
        return 1

    daemon_dir = Path(args.daemon_dir)
    if not daemon_dir.exists():
        print(f"Error: Daemon directory not found: {daemon_dir}", file=sys.stderr)
        return 1

    key_path = Path(args.key)
    if not key_path.exists():
        print(f"Error: Signing key not found: {key_path}", file=sys.stderr)
        return 1

    output_dir = Path(args.output) if args.output else daemon_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Signing daemon release v{args.version}")
    print(f"  Daemon directory: {daemon_dir}")
    print(f"  Signing key: {key_path}")
    print(f"  Output: {output_dir}")
    print()

    try:
        signer = CodeSigner(
            signing_key_path=str(key_path),
            signer_id=args.signer_id,
        )

        # Create and sign manifest
        manifest, signature = signer.sign_directory(
            str(daemon_dir),
            args.version,
            metadata={
                'signed_by': args.signer_id,
                'git_commit': os.environ.get('GIT_COMMIT', 'unknown'),
                'build_number': os.environ.get('BUILD_NUMBER', 'unknown'),
            },
        )

        # Save manifest and signature
        manifest_path = output_dir / "manifest.json"
        signer.save_manifest(manifest, signature, str(manifest_path))

        print(f"Signed {len(manifest.modules)} modules")
        print(f"Manifest: {manifest_path}")
        print(f"Signature: {manifest_path}.sig")
        print()
        print(f"Public key for verification: {signer.public_key}")

        # Verify immediately
        if args.verify:
            print()
            print("Verifying signature...")
            verifier = IntegrityVerifier(
                manifest_path=str(manifest_path),
                daemon_dir=str(daemon_dir),
                public_key_hex=signer.public_key,
            )
            result = verifier.verify(check_unauthorized=False)
            if result.is_valid:
                print(f"Verification PASSED: {result.modules_passed} modules OK")
            else:
                print(f"Verification FAILED: {result.status.value}")
                return 1

        return 0

    except Exception as e:
        print(f"Error signing release: {e}", file=sys.stderr)
        return 1


def cmd_verify(args):
    """Verify a signed release."""
    if CodeSigner is None:
        print("Error: Verifier not available", file=sys.stderr)
        return 1

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"Error: Manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    daemon_dir = Path(args.daemon_dir)
    if not daemon_dir.exists():
        print(f"Error: Daemon directory not found: {daemon_dir}", file=sys.stderr)
        return 1

    # Load public key
    public_key_hex = None
    if args.public_key:
        key_path = Path(args.public_key)
        if key_path.suffix == '.hex':
            with open(key_path, 'r') as f:
                public_key_hex = f.read().strip()
        else:
            with open(key_path, 'rb') as f:
                public_key_hex = f.read().hex()

    print(f"Verifying manifest: {manifest_path}")
    print(f"Daemon directory: {daemon_dir}")
    print()

    try:
        verifier = IntegrityVerifier(
            manifest_path=str(manifest_path),
            daemon_dir=str(daemon_dir),
            public_key_hex=public_key_hex,
            strict_mode=args.strict,
        )

        result = verifier.verify(check_unauthorized=args.strict)

        print(f"Status: {result.status.value}")
        print(f"Modules checked: {result.modules_checked}")
        print(f"Modules passed: {result.modules_passed}")
        print(f"Modules failed: {result.modules_failed}")
        print(f"Duration: {result.duration_ms:.1f}ms")

        if result.daemon_version:
            print(f"Daemon version: {result.daemon_version}")

        if result.failures:
            print()
            print("Failures:")
            for failure in result.failures:
                print(f"  - [{failure['type']}] {failure['message']}")

        print()
        if result.is_valid:
            print("VERIFICATION PASSED")
            return 0
        else:
            print("VERIFICATION FAILED")
            return 1

    except Exception as e:
        print(f"Error verifying: {e}", file=sys.stderr)
        return 1


def cmd_hash(args):
    """Hash a single file or directory (for debugging)."""
    if CodeSigner is None:
        print("Error: CodeSigner not available", file=sys.stderr)
        return 1

    target = Path(args.target)

    signer = CodeSigner()

    if target.is_file():
        module_hash = signer.hash_file(str(target))
        print(f"File: {module_hash.path}")
        print(f"SHA256: {module_hash.sha256}")
        print(f"Size: {module_hash.size} bytes")
        print(f"Modified: {module_hash.modified}")
    elif target.is_dir():
        hashes = signer.hash_directory(str(target))
        print(f"Hashed {len(hashes)} files:")
        for h in hashes:
            print(f"  {h.sha256[:16]}  {h.path}")
    else:
        print(f"Error: Not found: {target}", file=sys.stderr)
        return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog='sign_release',
        description='Sign and verify Boundary Daemon releases',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # keygen
    keygen_parser = subparsers.add_parser('keygen', help='Generate signing keypair')
    keygen_parser.add_argument(
        '-o', '--output',
        default='.',
        help='Output directory for keys',
    )
    keygen_parser.set_defaults(func=cmd_keygen)

    # sign
    sign_parser = subparsers.add_parser('sign', help='Sign a daemon release')
    sign_parser.add_argument(
        '-d', '--daemon-dir',
        required=True,
        help='Path to daemon directory',
    )
    sign_parser.add_argument(
        '-v', '--version',
        required=True,
        help='Version string (e.g., 2.0.0)',
    )
    sign_parser.add_argument(
        '-k', '--key',
        required=True,
        help='Path to signing private key',
    )
    sign_parser.add_argument(
        '-o', '--output',
        help='Output directory for manifest',
    )
    sign_parser.add_argument(
        '--signer-id',
        default='release-build',
        help='Identifier for the signer',
    )
    sign_parser.add_argument(
        '--no-verify',
        dest='verify',
        action='store_false',
        default=True,
        help='Skip immediate verification',
    )
    sign_parser.set_defaults(func=cmd_sign)

    # verify
    verify_parser = subparsers.add_parser('verify', help='Verify a signed release')
    verify_parser.add_argument(
        '-m', '--manifest',
        required=True,
        help='Path to manifest.json',
    )
    verify_parser.add_argument(
        '-d', '--daemon-dir',
        required=True,
        help='Path to daemon directory',
    )
    verify_parser.add_argument(
        '-p', '--public-key',
        help='Path to public key file',
    )
    verify_parser.add_argument(
        '--strict',
        action='store_true',
        help='Fail on unauthorized files',
    )
    verify_parser.set_defaults(func=cmd_verify)

    # hash
    hash_parser = subparsers.add_parser('hash', help='Hash a file or directory')
    hash_parser.add_argument('target', help='File or directory to hash')
    hash_parser.set_defaults(func=cmd_hash)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
