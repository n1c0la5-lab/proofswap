#!/usr/bin/env python3
"""Generate stagenet test vectors for proofswap-xmr-verify (milestone M1b).

Status: scaffold. Written for M1a, NOT run yet (no stagenet coins, node not synced).

What it does when run with --execute:
  1. Checks that the daemon (127.0.0.1:38081) is a synchronized *stagenet* node and
     that wallet-rpc (127.0.0.1:38083) answers. Anything else aborts.
  2. Opens the `payee` wallet, reads its primary address and creates one fresh
     subaddress.
  3. Opens the `payer` wallet and makes these transfers (stagenet coins only):
       std      -> payee primary address
       sub      -> payee subaddress (single destination: R = r*D, no additional keys)
       multi    -> payee subaddress + payee primary (additional tx keys)
       unlock   -> payee primary with unlock_time != 0 (negative R3)
  4. For each tx: `get_tx_proof` (txid, address, message) from the payer wallet, and
     Monero's own verdict via `check_tx_proof`. That verdict is the oracle the Rust
     tests compare against, which is what makes these vectors non-circular.
  5. Fetches each tx blob from the daemon: POST /get_transactions
     {"txs_hashes": [...], "decode_as_json": false} -> as_hex.
  6. Writes test-vectors/stagenet-<UTC date>.json with positive and negative cases:
     wrong message, wrong address, V1 header, amount below requirement, subaddress
     checked as standard address, unlock_time != 0, txid not matching the blob.

Secrets: the wallet-rpc digest login is read from ~/monero/wallets/.rpc-login
("user:password") and the wallet password from ~/monero/wallets/.wallet-pass. Their
contents are never printed, logged or written to the output file. The output file
contains only public chain data, public addresses, messages and proofs.

Usage:
  python3 scripts/gen-test-vectors.py              # plan only, no RPC call
  python3 scripts/gen-test-vectors.py --execute    # spends stagenet coins
"""

import argparse
import datetime
import json
import os
import sys
import time
import urllib.request

DAEMON = "http://127.0.0.1:38081"
WALLET_RPC = "http://127.0.0.1:38083/json_rpc"
WALLET_DIR = os.path.expanduser("~/monero/wallets")
RPC_LOGIN_FILE = os.path.join(WALLET_DIR, ".rpc-login")
WALLET_PASS_FILE = os.path.join(WALLET_DIR, ".wallet-pass")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(REPO, "test-vectors")

# Message format from SPEC 6.1. The canister id is a fixed placeholder principal;
# the verifier only needs a well-formed one.
CANISTER_ID = "ryjl3-tyaaa-aaaaa-aaaba-cai"
PICO = 10**12
AMOUNTS = {
    "std": PICO // 10,      # 0.1 sXMR
    "sub": PICO // 20,      # 0.05
    "multi_sub": PICO // 50,  # 0.02
    "multi_std": PICO // 40,  # 0.025
    "unlock": PICO // 100,  # 0.01
}
UNLOCK_TIME = 10_000_000  # block height far in the future (negative vector only)


def message(order_id):
    return f"proofswap:v1:{CANISTER_ID}:{order_id}"


def read_secret(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


class WalletRpc:
    def __init__(self):
        user, _, password = read_secret(RPC_LOGIN_FILE).partition(":")
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, WALLET_RPC, user, password)
        self.opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(mgr))

    def call(self, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}).encode()
        req = urllib.request.Request(WALLET_RPC, data=body, headers={"Content-Type": "application/json"})
        with self.opener.open(req, timeout=120) as resp:
            out = json.load(resp)
        if "error" in out:
            # error messages from wallet-rpc do not contain the password
            raise RuntimeError(f"wallet-rpc {method}: {out['error'].get('message')}")
        return out["result"]

    def open(self, name):
        self.call("open_wallet", {"filename": name, "password": read_secret(WALLET_PASS_FILE)})


def daemon(path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(DAEMON + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def preflight():
    info = daemon("/get_info")
    if not info.get("stagenet") or info.get("mainnet") or info.get("testnet"):
        sys.exit("ABORT: daemon is not a stagenet node")
    if not info.get("synchronized"):
        sys.exit(f"ABORT: daemon not synchronized ({info.get('height')}/{info.get('target_height')})")
    return info


def fetch_blob(txid):
    res = daemon("/get_transactions", {"txs_hashes": [txid], "decode_as_json": False})
    txs = res.get("txs") or []
    if len(txs) != 1 or not txs[0].get("as_hex"):
        raise RuntimeError(f"tx {txid} not returned by the daemon (pruned or missing)")
    t = txs[0]
    return {"as_hex": t["as_hex"], "block_height": t.get("block_height"), "in_pool": t.get("in_pool")}


def transfer(w, dests, unlock_time=0):
    res = w.call("transfer", {
        "destinations": [{"address": a, "amount": amt} for a, amt in dests],
        "priority": 0,
        "unlock_time": unlock_time,
        "get_tx_key": False,
    })
    return res["tx_hash"]


def proof_and_oracle(w, txid, address, msg):
    sig = w.call("get_tx_proof", {"txid": txid, "address": address, "message": msg})["signature"]
    chk = w.call("check_tx_proof", {"txid": txid, "address": address, "message": msg, "signature": sig})
    return sig, {"good": chk["good"], "received": chk.get("received", 0)}


def oracle(w, txid, address, msg, sig):
    try:
        chk = w.call("check_tx_proof", {"txid": txid, "address": address, "message": msg, "signature": sig})
        return {"good": chk["good"], "received": chk.get("received", 0)}
    except RuntimeError as e:
        return {"good": False, "error": str(e)}


def vector(name, txid, blob, address, msg, proof, min_amount, expect, monero):
    return {
        "name": name,
        "txid": txid,
        "tx": blob,
        "address": address,
        "message": msg,
        "proof": proof,
        "min_amount": min_amount,
        "expect": expect,      # what proofswap-xmr-verify must return
        "monero": monero,      # what monero-wallet-rpc check_tx_proof said
    }


def run():
    info = preflight()
    w = WalletRpc()

    w.open("payee")
    payee_std = w.call("get_address", {"account_index": 0})["address"]
    payee_sub = w.call("create_address", {"account_index": 0, "label": "proofswap-vectors"})["address"]
    w.call("close_wallet")

    w.open("payer")
    payer_std = w.call("get_address", {"account_index": 0})["address"]
    w.call("refresh")
    bal = w.call("get_balance", {"account_index": 0})
    need = sum(AMOUNTS.values()) + PICO // 10  # plus fees margin
    if bal["unlocked_balance"] < need:
        sys.exit(f"ABORT: payer unlocked balance {bal['unlocked_balance']} < {need} piconero")

    txs = {
        "std": transfer(w, [(payee_std, AMOUNTS["std"])]),
        "sub": transfer(w, [(payee_sub, AMOUNTS["sub"])]),
        "multi": transfer(w, [(payee_sub, AMOUNTS["multi_sub"]), (payee_std, AMOUNTS["multi_std"])]),
        "unlock": transfer(w, [(payee_std, AMOUNTS["unlock"])], unlock_time=UNLOCK_TIME),
    }
    time.sleep(5)
    blobs = {k: fetch_blob(v) for k, v in txs.items()}

    out = []
    m1, m2 = message(1), message(2)

    # positive
    sig, mon = proof_and_oracle(w, txs["std"], payee_std, m1)
    out.append(vector("std_ok", txs["std"], blobs["std"], payee_std, m1, sig, AMOUNTS["std"],
                      {"ok": True, "received": AMOUNTS["std"]}, mon))
    # negatives on the same proof
    out.append(vector("std_wrong_message", txs["std"], blobs["std"], payee_std, m2, sig, 1,
                      {"error": "InvalidProof"}, oracle(w, txs["std"], payee_std, m2, sig)))
    out.append(vector("std_wrong_address", txs["std"], blobs["std"], payer_std, m1, sig, 1,
                      {"error": "InvalidProof"}, oracle(w, txs["std"], payer_std, m1, sig)))
    v1 = "OutProofV1" + sig[len("OutProofV2"):]
    out.append(vector("std_v1_header", txs["std"], blobs["std"], payee_std, m1, v1, 1,
                      {"error": "ProofV1"}, oracle(w, txs["std"], payee_std, m1, v1)))
    out.append(vector("std_insufficient", txs["std"], blobs["std"], payee_std, m1, sig, AMOUNTS["std"] + 1,
                      {"error": "InsufficientAmount"}, mon))
    out.append(vector("std_txid_mismatch", txs["sub"], blobs["std"], payee_std, m1, sig, 1,
                      {"error": "TxidMismatch"}, None))

    sig, mon = proof_and_oracle(w, txs["sub"], payee_sub, m1)
    out.append(vector("sub_ok", txs["sub"], blobs["sub"], payee_sub, m1, sig, AMOUNTS["sub"],
                      {"ok": True, "received": AMOUNTS["sub"]}, mon))
    # subaddress keys checked as a standard address: re-encoding with prefix 24 is
    # done by the Rust test from the decoded keys (no Base58 code here).
    out.append(vector("sub_as_standard", txs["sub"], blobs["sub"], payee_sub, m1, sig, 1,
                      {"error": "InvalidProof", "reencode_as": "standard"}, None))

    sig, mon = proof_and_oracle(w, txs["multi"], payee_sub, m1)
    out.append(vector("multi_sub_ok", txs["multi"], blobs["multi"], payee_sub, m1, sig, AMOUNTS["multi_sub"],
                      {"ok": True, "received": AMOUNTS["multi_sub"]}, mon))
    sig, mon = proof_and_oracle(w, txs["multi"], payee_std, m1)
    out.append(vector("multi_std_ok", txs["multi"], blobs["multi"], payee_std, m1, sig, AMOUNTS["multi_std"],
                      {"ok": True, "received": AMOUNTS["multi_std"]}, mon))

    sig, mon = proof_and_oracle(w, txs["unlock"], payee_std, m1)
    out.append(vector("unlock_time_set", txs["unlock"], blobs["unlock"], payee_std, m1, sig, 1,
                      {"error": "UnlockTimeSet"}, mon))

    w.call("close_wallet")

    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, f"stagenet-{datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d}.json")
    doc = {
        "generator": "scripts/gen-test-vectors.py",
        "network": "stagenet",
        "daemon_height": info.get("height"),
        "canister_id": CANISTER_ID,
        "vectors": out,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"WROTE {len(out)} vectors to {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--execute", action="store_true", help="really call the RPCs and spend stagenet coins")
    args = ap.parse_args()
    if not args.execute:
        print("PLAN ONLY (no RPC call). Would:")
        print(f"  check {DAEMON}/get_info is stagenet + synchronized")
        print(f"  use wallet-rpc {WALLET_RPC} with wallets payer, payee in {WALLET_DIR}")
        print(f"  send {len(AMOUNTS)} stagenet transfers, total {sum(AMOUNTS.values())} piconero + fees")
        print(f"  write test-vectors/stagenet-<date>.json under {OUT_DIR}")
        print("NOTHING WRITTEN. Re-run with --execute.")
        return
    run()


if __name__ == "__main__":
    main()
