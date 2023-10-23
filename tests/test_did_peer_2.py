from did_peer_2 import generate, peer2to3, resolve, KeySpec, resolve_peer3

# ruff: noqa: E501


def test_generate_resolve():
    did = generate(
        [
            KeySpec.authentication("z6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc"),
            KeySpec.key_agreement("z6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR"),
        ],
        [
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "http://example.com/didcomm",
                    "accept": ["didcomm/v2"],
                    "routingKeys": ["did:example:123456789abcdefghi#key-1"],
                },
            },
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "http://example.com/another",
                    "accept": ["didcomm/v2"],
                    "routingKeys": ["did:example:123456789abcdefghi#key-2"],
                },
            },
        ],
    )
    assert (
        did
        == "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ"
    )

    resolved = resolve(did)
    assert resolved == {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ",
        "verificationMethod": [
            {
                "id": "#key-1",
                "controller": "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ",
                "type": "Multikey",
                "publicKeyMultibase": "z6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc",
            },
            {
                "id": "#key-2",
                "controller": "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ",
                "type": "Multikey",
                "publicKeyMultibase": "z6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR",
            },
        ],
        "authentication": ["#key-1"],
        "keyAgreement": ["#key-2"],
        "service": [
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "http://example.com/didcomm",
                    "accept": ["didcomm/v2"],
                    "routingKeys": ["did:example:123456789abcdefghi#key-1"],
                },
                "id": "#service",
            },
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "http://example.com/another",
                    "accept": ["didcomm/v2"],
                    "routingKeys": ["did:example:123456789abcdefghi#key-2"],
                },
                "id": "#service-1",
            },
        ],
        "alsoKnownAs": ["did:peer:3zQmd6RdU6e2nDrLn1rjwdA5Buzq7wJwsv3WJ1AgrwKYJoLE"],
    }


def test_2_to_3():
    did = "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
    as3 = peer2to3(did)
    assert as3 == "did:peer:3zQmS19jtYDvGtKVrJhQnRFpBQAx3pJ9omx2HpNrcXFuRCz9"


def test_resolve_3():
    did = "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
    as3 = peer2to3(did)
    doc = resolve_peer3(did, as3)
    assert doc
