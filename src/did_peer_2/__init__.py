"""did:peer:2 implementation."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from base58 import b58encode
from dataclasses import dataclass
from enum import Enum
import json
import re
from typing import Any, Dict, List, Sequence
from hashlib import sha256


# Regex
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PATTERN = re.compile(rf"^did:peer:2(\.[AEVIDS]z[{B58}]{46}|\.+[A-Za-z0-9_-]+)+$")

# Multiformats
MULTIBASE_BASE58_BTC = "z"
MULTIHASH_SHA256 = b"\x12\x20"


class PurposeCode(Enum):
    """Purpose codes for did:peer:2."""

    assertion = "A"
    key_agreement = "E"
    authentication = "V"
    capability_invocation = "I"
    capability_delegation = "D"
    service = "S"

    def to_verification_relationship(self) -> str:
        """Convert the purpose code to a verification relationship."""
        return {
            "A": "assertionMethod",
            "E": "keyAgreement",
            "V": "authentication",
            "I": "capabilityInvocation",
            "D": "capabilityDelegation",
        }[self.value]


KeyPurposes = (
    PurposeCode.assertion,
    PurposeCode.key_agreement,
    PurposeCode.authentication,
    PurposeCode.capability_invocation,
    PurposeCode.capability_delegation,
)


common_string_abbreviations = {
    "type": "t",
    "DIDCommMessaging": "dm",
    "serviceEndpoint": "s",
    "routingKeys": "r",
    "accept": "a",
}

reverse_common_string_abbreviations = {
    v: k for k, v in common_string_abbreviations.items()
}


def abbreviate_service(service: Dict[str, Any]) -> Dict[str, Any]:
    """Recursivley replace common strings with abbreviations.

    This method will replace keys in the service dictionary with their
    abbreviations as outlined in the Common String Abbreviations. The type of
    the service will also be abbreviated, if applicable.
    """
    service = {common_string_abbreviations.get(k, k): v for k, v in service.items()}
    if "t" in service:
        service["t"] = common_string_abbreviations.get(service["t"], service["t"])

    for k, v in service.items():
        if isinstance(v, dict):
            service[k] = abbreviate_service(v)
        if isinstance(v, list):
            service[k] = [
                abbreviate_service(e) if isinstance(e, dict) else e for e in v
            ]

    return service


def expand_service(service: Dict[str, Any]) -> Dict[str, Any]:
    """Reverse the abbreviations in a service dictionary.

    This method will perform the inverse of abbreviate_service, replacing
    abbreviations with their full string.
    """
    service = {
        reverse_common_string_abbreviations.get(k, k): v for k, v in service.items()
    }
    if "type" in service:
        service["type"] = reverse_common_string_abbreviations.get(
            service["type"], service["type"]
        )

    for k, v in service.items():
        if isinstance(v, dict):
            service[k] = expand_service(v)
        if isinstance(v, list):
            service[k] = [expand_service(e) if isinstance(e, dict) else e for e in v]

    return service


def bytes_to_b64(data: bytes) -> str:
    """Encode bytes to base64url, without padding."""
    return urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64_to_bytes(data: str) -> bytes:
    """Decode unpadded base64url to bytes."""
    return urlsafe_b64decode(data + "=" * (-len(data) % 4))


def encode_service(service: Dict[str, Any]) -> str:
    """Encode a service dictionary into a string."""
    return bytes_to_b64(
        json.dumps(abbreviate_service(service), separators=(",", ":")).encode("utf-8")
    )


def decode_service(data: str) -> Dict[str, Any]:
    """Decode a service string into a dictionary."""
    return expand_service(json.loads(b64_to_bytes(data).decode("utf-8")))


MultibaseEncodedKey = str


@dataclass
class KeySpec:
    """Key specification for did:peer:2."""

    purpose: PurposeCode
    material: MultibaseEncodedKey

    @classmethod
    def assertion(cls, material: str) -> "KeySpec":
        return cls(PurposeCode.assertion, material)

    @classmethod
    def key_agreement(cls, material: str) -> "KeySpec":
        return cls(PurposeCode.key_agreement, material)

    @classmethod
    def encryption(cls, material: str) -> "KeySpec":
        return cls(PurposeCode.key_agreement, material)

    @classmethod
    def authentication(cls, material: str) -> "KeySpec":
        return cls(PurposeCode.authentication, material)

    @classmethod
    def verification(cls, material: str) -> "KeySpec":
        return cls(PurposeCode.authentication, material)

    @classmethod
    def capability_invocation(cls, material: str) -> "KeySpec":
        return cls(PurposeCode.capability_invocation, material)

    @classmethod
    def capability_delegation(cls, material: str) -> "KeySpec":
        return cls(PurposeCode.capability_delegation, material)


def multibase_to_vm_type(key: MultibaseEncodedKey) -> str:
    """Determine the vm type from the multibase encoded key."""
    if key.startswith("z6Mk"):
        return "Ed25519VerificationKey2020"
    if key.startswith("z6LS"):
        return "X25519KeyAgreementKey2020"
    raise ValueError(f"Unsupported key type: {key}")


def multibase_to_context(key: MultibaseEncodedKey) -> List[str]:
    """Determine the required context from the multibase encoded key."""
    if key.startswith("z6Mk"):
        return ["https://w3id.org/security/suites/ed25519-2020/v1"]
    if key.startswith("z6LS"):
        return ["https://w3id.org/security/suites/x25519-2020/v1"]
    raise ValueError(f"Unsupported key type: {key}")


def generate(keys: Sequence[KeySpec], services: Sequence[Dict[str, Any]]):
    """Generate a did:peer:2 DID from keys and services.

    This method will generate a did:peer:2 DID from the provided keys and services.

    Key material in the keys parameter must be multibase encoded keys.
    """
    enocded_keys = "".join([f".{key.purpose.value}{key.material}" for key in keys])
    encoded_services = "".join(
        [
            f".{PurposeCode.service.value}" + encode_service(service)
            for service in services
        ]
    )
    return f"did:peer:2{enocded_keys}{encoded_services}"


def resolve(did: str) -> Dict[str, Any]:
    """Resolve a did:peer:2 DID."""
    if not PATTERN.match(did):
        raise ValueError(f"Invalid did:peer:2: {did}")

    document = {}
    document["@context"] = ["https://www.w3.org/ns/did/v1"]
    document["id"] = did

    elements = did.split(".")[1:]
    print(elements)
    keys = []
    services = []
    for element in elements:
        purpose = PurposeCode(element[0])
        if purpose in KeyPurposes:
            keys.append(KeySpec(purpose, element[1:]))
        else:
            assert purpose == PurposeCode.service
            services.append(decode_service(element[1:]))

    additional_contexts = set()
    for index, key in enumerate(keys, start=1):
        verification_method = {
            "type": multibase_to_vm_type(key.material),
            "id": f"#key-{index}",
            "controller": did,
            "publicKeyMultibase": key.material,
        }
        document.setdefault("verificationMethod", []).append(verification_method)
        document.setdefault(key.purpose.to_verification_relationship(), []).append(
            f"#key-{index}"
        )
        additional_contexts.update(multibase_to_context(key.material))

    document["@context"].extend(additional_contexts)

    unidentified_index = 0
    for service in services:
        if "id" not in service:
            if unidentified_index == 0:
                service["id"] = "#service"
            else:
                service["id"] = f"#service-{unidentified_index}"
            unidentified_index += 1
        document.setdefault("service", []).append(service)

    return document


def peer2to3(did: str) -> str:
    """Derive a did:peer:3 DID from a did:peer:2 DID."""
    if not PATTERN.match(did):
        raise ValueError(f"Invalid did:peer:2: {did}")

    raw = MULTIHASH_SHA256 + sha256(did[10:].encode()).digest()
    return "did:peer:3" + MULTIBASE_BASE58_BTC + b58encode(raw).decode()
