#!/usr/bin/env python

# https://www.youtube.com/watch?v=sPMRyB-rTd0

import base64
import binascii
import click
import datetime
import hashlib
import hmac
import json
from typing import Dict, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

AES_KEY_SIZE_BIT = 256
PBKDF2_ITERATIONS = 50000
HMAC_SECRET = b"if you remove/change this, please make sure you know the consequences!"
HASH_STANDIN = b"--to-be-calculated--"
TIMED_OBJECTIVES = (
    "ama",
    "auto",
    "autosens",
    "config",
    "exam",
    "maxbasal",
    "maxiob",
    "maxiobzero",
    "openloop",
    "smb",
    "usage",
)
BOOL_OBJECTIVES = (
    "ObjectivesActionsUsed",
    "ObjectivesDisconnectUsed",
    "ObjectivesLoopUsed",
    "ObjectivesProfileSwitchUsed",
    "ObjectivesReconnectUsed",
    "ObjectivesScaleUsed",
    "ObjectivesTempTargetUsed",
    "ObjectivesbgIsAvailableInNS",
    "ObjectivespumpStatusIsAvailableInNS",
)
INT_OBJECTIVES = {
    "ObjectivesmanualEnacts": "420",
}


def check_file_hash(outer_json_blob: bytes, outer_json: Dict) -> None:
    """Test integrity of whole preferences file"""
    # It's HMAC-SHA256 after static-hash-substitution with a magic phrase
    file_hash = outer_json["security"]["file_hash"]
    hashed_json = outer_json_blob.replace(file_hash.encode("utf8"), HASH_STANDIN)
    calc_hash = hmac.new(
        key=HMAC_SECRET, msg=hashed_json, digestmod="sha256"
    ).hexdigest()
    if calc_hash != file_hash:
        raise RuntimeError("calculated and apparent file hashes do not match")


def derive_key(outer_json: Dict, password: bytes) -> bytes:
    """Derive an AES key from an input password"""
    return PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=AES_KEY_SIZE_BIT // 8,
        salt=binascii.unhexlify(outer_json["security"]["salt"]),
        iterations=PBKDF2_ITERATIONS,
    ).derive(password)


def decrypt_content(outer_json: Dict, derived_key: bytes) -> Tuple[int, bytes, Dict]:
    """Decrypt the preferences content blob given a deserialized input file and key"""
    content_blob = base64.b64decode(outer_json["content"])
    iv_sz = content_blob[0]
    iv = content_blob[1 : iv_sz + 1]
    data = content_blob[iv_sz + 1 :]
    inner_json_blob = AESGCM(derived_key).decrypt(iv, data, None)
    if (
        outer_json["security"]["content_hash"]
        != hashlib.sha256(inner_json_blob).hexdigest()
    ):
        raise RuntimeError("calculated and apparent crypted blob hashes do not match")
    # sup dawg herd you like json so i put json in your json so you can encrypt it like a fucker
    return iv_sz, iv, inner_json_blob


def slurp_ts(ts: str) -> str:
    """Convert a preferences timestamp (millis) to dt object"""
    return datetime.datetime.fromtimestamp(int(ts) / 1000).isoformat()


def mk_inner_blob(preferences: Dict) -> bytes:
    """Prepare an inner preferences blob"""
    return (
        json.dumps(preferences, indent=0, separators=(",", ":"))
        .replace("\n", "")
        .replace("/", "\\/")
        .encode("utf8")
    )


def encrypt_inner_blob(inner_blob: bytes, derived_key: bytes, iv: bytes) -> bytes:
    """AES-GCM encrypt an inner blob with a derived key and IV"""
    return AESGCM(derived_key).encrypt(iv, inner_blob, None)


def deserialize_settings(blob: bytes, password: str) -> Tuple[Dict, Dict, int, bytes]:
    """Input the settings file"""
    outer_json = json.loads(blob)
    check_file_hash(blob, outer_json)
    derived_key = derive_key(outer_json, password.encode("utf8"))
    try:
        iv_sz, iv, inner_json_blob = decrypt_content(outer_json, derived_key)
    except InvalidTag as ex:
        raise click.ClickException("Invalid password") from ex
    preferences = json.loads(inner_json_blob)
    return outer_json, preferences, iv_sz, iv


def serialize_settings(
    outer_json: Dict, preferences: Dict, iv_sz: int, iv: bytes, password: str
) -> bytes:
    """Output the settings file"""
    # serialize it
    new_inner_json_blob = mk_inner_blob(preferences)
    # derive key
    derived_key = derive_key(outer_json, password.encode("utf8"))
    # encrypt it
    new_inner_json_ct = encrypt_inner_blob(new_inner_json_blob, derived_key, iv)
    # place it
    outer_json["content"] = base64.b64encode(
        bytes((iv_sz,)) + iv + new_inner_json_ct
    ).decode("utf8")
    # store the hash of the inner
    outer_json["security"]["content_hash"] = hashlib.sha256(
        new_inner_json_blob
    ).hexdigest()
    # set the standin of the outer
    outer_json["security"]["file_hash"] = HASH_STANDIN.decode("utf8")
    outer_json["security"]["file_hash"] = hmac.new(
        key=HMAC_SECRET,
        msg=json.dumps(outer_json, indent=2).replace("/", "\\/").encode("utf8"),
        digestmod="sha256",
    ).hexdigest()
    # Kotlin over-escapes forward slashes, so be silly
    return json.dumps(outer_json, indent=2).replace("/", "\\/").encode("utf8")


def pass_objectives(preferences: Dict) -> Dict:
    """Set all objectives into a passing state"""
    for bool_obj in BOOL_OBJECTIVES:
        preferences[bool_obj] = "true"
    for int_obj, dankvalue in INT_OBJECTIVES.items():
        preferences[int_obj] = dankvalue
    rfn = int(datetime.datetime.now().timestamp() * 1000)
    for timed_obj in TIMED_OBJECTIVES:
        preferences[f"Objectives_{timed_obj}_started"] = str(rfn)
        preferences[f"Objectives_{timed_obj}_accomplished"] = str(rfn)
    return preferences


def reset_objectives(preferences: Dict) -> Dict:
    """Set all objectives into a cleared state"""
    for bool_obj in BOOL_OBJECTIVES:
        preferences[bool_obj] = "false"
    for int_obj in INT_OBJECTIVES:
        preferences[int_obj] = "0"
    for timed_obj in TIMED_OBJECTIVES:
        preferences[f"Objectives_{timed_obj}_started"] = "0"
        preferences[f"Objectives_{timed_obj}_accomplished"] = "0"
    return preferences


def dump_objectives(preferences: Dict) -> None:
    """Dump all objectives to stdout"""
    for bool_obj in BOOL_OBJECTIVES:
        if bool_obj in preferences:
            print(f"{bool_obj}: {preferences[bool_obj]}")
        else:
            print(f"{bool_obj}: missing")
    for int_obj in INT_OBJECTIVES:
        if int_obj in preferences:
            print(f"{int_obj}: {preferences[int_obj]}")
        else:
            print(f"{int_obj}: missing")
    for timed_obj in TIMED_OBJECTIVES:
        _started = f"Objectives_{timed_obj}_started"
        if _started in preferences:
            if preferences[_started] == "0":
                print(f"{_started}: 0 (clear)")
            else:
                print(f"{_started}: {slurp_ts(preferences[_started])}")
        else:
            print(f"{_started}: missing")
        _accomplished = f"Objectives_{timed_obj}_accomplished"
        if _accomplished in preferences:
            if preferences[_accomplished] == "0":
                print(f"{_accomplished}: 0 (clear)")
            else:
                print(f"{_accomplished}: {slurp_ts(preferences[_accomplished])}")
        else:
            print(f"{_accomplished}: missing")
