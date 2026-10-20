"""Original fixture inputs, signed/validated with pinned Python-TUF.

Generate once: randomized public RSA/ECDSA signatures are committed as fixtures.
No private key is written. Runtime test consumers need neither Python nor TUF.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, Root, Targets, Snapshot, Timestamp, MetaFile, TargetFile

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def string(value):
    return json.dumps(value, ensure_ascii=False)


def raw(value):
    return f'@crypto.decode_hex("{value.hex()}").unwrap()'


def signed(obj, signer):
    value = Metadata(obj)
    value.sign(signer)
    return value


fixtures = []
crypto_lines = ["// Generated from original inputs using securesystemslib 1.5.1 / cryptography 50.0.2."]
client_lines = ["// Generated from original repositories signed with Python-TUF 7.0.1; not upstream test data."]
for kind in ["ed25519", "rsa", "ecdsa"]:
    signer = {"ed25519": CryptoSigner.generate_ed25519,
              "rsa": lambda: CryptoSigner.generate_rsa(size=2048),
              "ecdsa": CryptoSigner.generate_ecdsa}[kind]()
    public = signer.public_key
    message = "MoonTUF reference 茅\n".encode()
    signature = signer.sign(message)
    public.verify_signature(signature, message)
    key = public.to_dict()
    fixtures.append({"kind": kind, "key": key, "message": message.hex(), "signature": signature.signature})
    crypto_lines += ["", "///|", f'test "Python {kind} signature and malformed-input isolation" {{',
        f'  let key = {string(key["keyval"]["public"])}',
        f'  let signature = {string(signature.signature)}',
        f'  assert_true(@crypto.valid_public_key({string(key["keytype"])}, {string(key["scheme"])}, key))',
        f'  assert_true(@crypto.verify_signature({string(key["keytype"])}, {string(key["scheme"])}, key, {raw(message)}, signature).unwrap())',
        f'  assert_false(@crypto.verify_signature({string(key["keytype"])}, {string(key["scheme"])}, key, b"tampered", signature).unwrap())',
        f'  assert_false(@crypto.valid_public_key({string(key["keytype"])}, {string(key["scheme"])}, "malformed"))', "}"]
    root = Root(expires=NOW, consistent_snapshot=True)
    for role in ["root", "timestamp", "snapshot", "targets"]:
        root.add_key(public, role)
    root_md = signed(root, signer)
    target = b"trusted-update"
    targets = Targets(expires=NOW)
    targets.targets["plugins/demo.bin"] = TargetFile.from_data("plugins/demo.bin", target, ["sha512"])
    targets_md = signed(targets, signer)
    snapshot = Snapshot(expires=NOW)
    snapshot.meta["targets.json"] = MetaFile.from_data(1, targets_md.to_bytes(), ["sha512"])
    snapshot_md = signed(snapshot, signer)
    timestamp = Timestamp(expires=NOW)
    timestamp.snapshot_meta = MetaFile.from_data(1, snapshot_md.to_bytes(), ["sha512"])
    timestamp_md = signed(timestamp, signer)
    root.verify_delegate("timestamp", timestamp_md.signed_bytes, timestamp_md.signatures)
    root.verify_delegate("snapshot", snapshot_md.signed_bytes, snapshot_md.signatures)
    root.verify_delegate("targets", targets_md.signed_bytes, targets_md.signatures)
    targets.targets["plugins/demo.bin"].verify_length_and_hashes(target)
    crypto_lines[-1] = "}"
    client_lines += ["", "///|", f'test "Python {kind} repository SHA512 chain target stream and local resume" {{',
        f'  let root = {raw(root_md.to_bytes())}',
        f'  let timestamp = {raw(timestamp_md.to_bytes())}',
        f'  let snapshot = {raw(snapshot_md.to_bytes())}',
        f'  let targets = {raw(targets_md.to_bytes())}',
        '  let client = @client.open_trusted_root(root, "2026-10-20T00:00:00Z").unwrap()',
        '    .accept_timestamp(timestamp).unwrap().accept_snapshot(snapshot).unwrap().accept_targets(targets).unwrap()',
        '  assert_true(client.ready())',
        '  let verified = client.verify_top_level_target("plugins/demo.bin", b"trusted-update").unwrap()',
        '  assert_eq(verified.length(), 14L)',
        '  assert_true(client.verify_top_level_target("plugins/demo.bin", b"evil") is Err(_))',
        '  let stream = client.open_top_level_stream("plugins/demo.bin").unwrap()',
        '  stream.write(b"trusted-").unwrap()',
        '  stream.write(b"update").unwrap()',
        '  assert_eq(stream.finish().unwrap().sha256(), verified.sha256())',
        '  let restored = @client.restore_state(client.save_state(), root, "2026-10-20T00:00:00Z").unwrap().finish_root_chain().unwrap()',
        '  assert_eq(restored.verify_top_level_target("plugins/demo.bin", b"trusted-update").unwrap().sha256(), verified.sha256())',
        '  assert_true(client.top_level_target_request_name("plugins/demo.bin").unwrap().has_prefix("plugins/"))', "}"]
(ROOT / "testdata").mkdir(exist_ok=True)
(ROOT / "testdata/python-crypto.json").write_text(json.dumps(fixtures, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
(ROOT / "crypto/reference_generated_test.mbt").write_text("\n".join(crypto_lines) + "\n", encoding="utf-8")
(ROOT / "client/reference_generated_test.mbt").write_text("\n".join(client_lines) + "\n", encoding="utf-8")
print("Generated three public signature and three complete SHA512 repository cases; no private keys saved")
