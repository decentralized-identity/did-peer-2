# did-peer-2

A minimal did:peer:2 (and 3) library.

did:peer:2 has (or will soon be) superseded by [did:peer:4](https://github.com/dbluhm/did-peer-4). Even so, we anticipate did:peer:2 being around for at least a while longer. This library is built against the most recent version of the did:peer:2 spec.

## DID Peer 2 Specification

If `numalgo` == `2`, the generation mode is similar to Method 0 (and therefore also did:key) with the ability to specify additional keys in the generated DID Document. This method is necessary when both an encryption key and a signing key are required. This method also enables including services in the generated DID Document.

> [!NOTE]
> The first iteration of this method left some elements of the encoding and decoding process underspecified. Clarifications have been made to this specification to resolve this. These clarifications will be noted by appending "(clarified)" to the relevant statements.

``` json
peer-did-method-2 = "did:peer:2" 1*element 
element = "." ( purposecode transform encnumbasis / service )
purposecode = "A" / "E" / "V" / "I" / "D" / "S" 
keypurpose = 
transform = "z"
encnumbasis = 46*BASE58BTC
service = 1*B64URL
```

### Generating a `did:peer:2`

When generating a `did:peer:2`, take as inputs a set of keys and their purpose. Each key's purpose corresponds to the [Verification Relationship](https://www.w3.org/TR/did-core/#verification-relationships) it will hold in the DID Document generated from the DID.

Abstractly, these inputs may look like the following:

```json
[
  {
    "purpose": "verification",
    "publicKeyMultibase": "z6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc"
  },
  {
    "purpose": "encryption",
    "publicKeyMultibase": "z6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR"
  }
]
```

To encode these keys:

* Construct a multibase, multicodec form of each public key to be included.
* Prefix each encoded key with a period character (.) and single character from the purpose codes table below.
* Concatenate the prefixed encoded keys. The inputs above will result in:
    ```
    .Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR
    ```

In addition to keys, `did:peer:2` can encode one or more [services](https://www.w3.org/TR/did-core/#services).

The service SHOULD follow the DID Core specification for services.

For use with `did:peer:2`, service `id` attributes MUST be relative. The service MAY omit the `id`; however, this is NOT recommended (clarified).

Consider the following service as input:

```json
{
  "type": "DIDCommMessaging",
  "serviceEndpoint": {
    "uri": "http://example.com/didcomm",
    "accept": [
      "didcomm/v2"
    ],
    "routingKeys": [
      "did:example:123456789abcdefghi#key-1"
    ]
  }
}
```

To encode a service:

* Start with the JSON structure for your service, like the example input above.
* Recursively replace common strings in key names and type value with abbreviations from the abbreviations table below (clarified). For the above input, this will result in:
    ```
    {
      "t": "dm",
      "s": {
        "uri": "http://example.com/didcomm",
        "a": [
          "didcomm/v2"
        ],
        "r": [
          "did:example:123456789abcdefghi#key-1"
        ]
      }
    }
    ```
* Convert to string, and remove unnecessary whitespace, such as spaces and newlines. For the above input, this will result in:
    ```
    {"t":"dm","s":{"uri":"http://example.com/didcomm","a":["didcomm/v2"],"r":["did:example:123456789abcdefghi#key-1"]}}
    ```
* Base64URL Encode String (Padding MUST be removed as the "=" character is, per the DID Core Specification, not permitted in a DID). For the above example, this will result in:
    ```
    eyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ
    ```
* Prefix encoded service with a period character (.) and S. For the above input, this will result in:
    ```
    .SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ0tleXMiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ
    ```
* For any additional services, repeat the steps above and concatenate each additional service to the previous (clarified). This will result in a string like the following (newline added between service strings for clarity; in practice, there will be no whitespace between the concatenated services):
    ```
    .SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ0tleXMiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ
    .SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ
    ```

Finally, to create the DID, concatenate the following values:

- `did:peer:2`
- Encoded, concatenated, and prefixed keys.
- Encoded, concatenated, and prefixed services.

This concatenation will result in a value like the following:

```
did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ
```

### Lookup Tables

#### Common String Abbreviations

| Common String         | Abbreviation  |
|-----------------------|---------------|
| type                  | t             |
| DIDCommMessaging      | dm            |
| serviceEndpoint       | s             |
| routingKeys           | r             |
| accept                | a             |

#### Purpose Codes

| Purpose Code | Verification Relationship     |
|--------------|-------------------------------|
| **A**        | Assertion                     |
| **E**        | Key Agreement (Encryption)    |
| **V**        | Authentication (Verification) |
| **I**        | Capability Invocation         |
| **D**        | Capability Delegation         |
| **S**        | Service                       |


#### Multicodec Prefix Name to Verification Method Type (clarified)

| Multicodec Prefix Name             | Verification Method Type   |
|------------------------------------|----------------------------|
| ed25519-pub                        | Ed25519VerificationKey2020 |
| x25519-pub                         | X25519KeyAgreementKey2020  |

### Resolving a `did:peer:2`

> [!NOTE]
> Below is the normative approach to resolving did:peer:2 DIDs. However, it is often the case that the resolved value is only used within a particular component. In this case, some of these rules may be relaxed. For instance, the verification material may be transformed into a JWK or other representation if the resolving component is more accustomed to working with those key representations. It is not strictly necessary to first represent the document as described here only to immediately transform it into the more familiar representation. Shortcuts like these are not problematic unless they impact the function of the DID Document.
>
> The `id` value of the Document, verification method, and service objects MUST be set as outlined below. These values are used to reference elements of the document and must be consistent across implementations regardless of shortcuts taken within the resolver.

When Resolving the peer DID into a DID Document, the process is reversed:

* Start with an empty document with the DID Core context (clarified):
    ```json
    {
        "context": ["https://www.w3.org/ns/did/v1"]
    }
    ```
    * If any of the keys in the DID are ed25519, add the following context:
        ```
        https://w3id.org/security/suites/ed25519-2020/v1
        ```
    * If any of the keys in the DID are x25519, add the following context:
        ```
        https://w3id.org/security/suites/x25519-2020/v1
        ```
* Set the `id` of the document to the DID being resolved.
* Optionally, set the `alsoKnownAs` to the `did:peer:3` value corresponding to the DID being resolved.
* Split the DID string into elements.
* For each element with a purpose corresponding to a key, transform keys into verification methods in the DID Document:
    * Remove the period (.) and the Purpose prefix. Consider the remaining string the "encoded key."
    * Create an empty object. Consider this value the "verification method."
    * Set the `type` of the verification method according to the multicodec prefix using the lookup table above (clarified).
    * Set the `id` of the verification method to `#key-N` where `N` is an incrementing number starting at `1` (clarified). The keys MUST be processed in the order they appear in the DID string. For example, if you have the DID (whitespace added for example only):
        ```
        did:peer:2
            .Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc
            .Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR
            .SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ
            .SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ
        ```
        The key with purpose code `V` and encoded key value `z6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc` will have the `id`: `#key-1`.
        The key with purpose code `E` and encoded key value `z6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR` will have the `id`: `#key-2`.
    * Set the `controller` of the verification method to the value of the DID being resolved.
    * Set the `publicKeyMultibase` of the verification method to the value of the encoded key.
    * Append this object to `verificationMethod` of the document (clarified).
    * Append a reference to the verification method to the appropriate verification relationship, using the lookup table above. The reference should be the exact value used in the `id` of the verification method (clarified). For example, using the DID above and the key with purpose code `V`:
        ```
        {
          ... // Context and other elements previously added to the document
          "authentication": [..., "#key-1"]
        }
        ```
* For each element with a purpose corresponding to a service, transform the service and add to the DID Document:
    * Remove the period (.) and S prefix.
    * Base64URL Decode String.
    * Parse as JSON.
    * Replace abbreviations in key names and type value with common names from the abbreviations table above.
    * If the `id` is NOT set (clarified):
        * Set `id` to `#service` for the first such service.
        * For all subsequent services WITHOUT an `id`, set `id` to `#service-1`, `#service-2`, etc. incrementing the integer with each service, starting from `1`.

> [!NOTE]
> It is  not possible to express a verification method not controlled by the controller of the DID Document with `did:peer:2`.


```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ",
  "verificationMethod": [
    {
      "id": "#key-1",
      "controller": "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ",
      "type": "Ed25519VerificationKey2020",
      "publicKeyMultibase": "z6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc"
    },
    {
      "id": "#key-2",
      "controller": "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ",
      "type": "X25519KeyAgreementKey2020",
      "publicKeyMultibase": "z6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR"
    }
  ],
  "authentication": [
    "#key-1"
  ],
  "keyAgreement": [
    "#key-2"
  ],
  "service": [
    {
      "type": "DIDCommMessaging",
      "serviceEndpoint": {
        "uri": "http://example.com/didcomm",
        "accept": [
          "didcomm/v2"
        ],
        "routingKeys": [
          "did:example:123456789abcdefghi#key-1"
        ]
      },
      "id": "#service"
    },
    {
      "type": "DIDCommMessaging",
      "serviceEndpoint": {
        "uri": "http://example.com/another",
        "accept": [
          "didcomm/v2"
        ],
        "routingKeys": [
          "did:example:123456789abcdefghi#key-2"
        ]
      },
      "id": "#service-1"
    }
  ]
}
```

### DID Peer 3: DID Shortening with SHA-256 Hash

If `numalgo` == `3`, the generation mode is similar to Method 2, but with a shorter DID identifier derived from a SHA-256 hash of the original identifier. The benefit of using Method 3 over Method 2 is the ability to have smaller size didcomm messages as `did:peer:2.` dids tend to be verbose in nature. Method 3 peer dids can only be used after a peer did method 2 has been exchange with the other party and thus can map the shortened did to the longform one. In order to send a message encrypted with method 3 you first MUST send a discover-feature message (using the method 2 as the `to` field) to make sure that the receiving agent is capable of resolving method 3 dids.

```
peer-did-method-3 = "did:peer:3" transform encnumbasis
transform = "z"
encnumbasis = 46*BASE58BTC
```

*   Start with the DID generated using Method 2.
*   Take the SHA-256 hash of the generated DID (excluding the "did:peer:2" prefix).
*   Encode the hash using the base58btc multibase encoding.
*   Construct the final Method 3 DID by concatenating the prefix "did:peer:3" with the encoded hash.

For example, if the Method 2 DID is:

```
did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0
```

First, remove the prefix "did:peer:2":

```
.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0
```

Take the SHA-256 hash of the remaining string and represent as a multi-hash, multi-base encoded(base58btc) string:

```
zQmS19jtYDvGtKVrJhQnRFpBQAx3pJ9omx2HpNrcXFuRCz9
```

Finally, concatenate the prefix "did:peer:3" with the computed and encoded hash:

```
did:peer:3zQmS19jtYDvGtKVrJhQnRFpBQAx3pJ9omx2HpNrcXFuRCz9
```
