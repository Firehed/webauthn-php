Cleanup Tasks

- [x] Pull across PublicKeyInterface
- [x] Pull across ECPublicKey
- [ ] Move key formatting into COSE key/turn COSE into key parser?
- [ ] Clearly define public scoped interfaces and classes
  - Public:
    - [x] ResponseParser (interface?)
    - [x] Challenge (DTO / serialization-safety in session)
    - [x] RelyingParty
    - [x] CredentialInterface
      - [ ] getId()? how to feed into nav.credentials.get{pk.allowCredentials}
  - Internal:
    - [x] Attestations
    - [x] AuthenticatorData
    - [x] BinaryString
    - [x] Credential
    - [x] Certificate
  - TBD:
    - [ ] CreateResponse/GetResponse (pub interfaces/priv impl?)
    - [ ] Errors
- [x] Rework BinaryString to avoid binary in stack traces
- [x] Use BinaryString consistently
  - [ ] COSEKey.decodedCbor
  - [ ] Attestations\FidoU2F.data
- [ ] Establish required+best practices for data storage
  - [x] CredentialInterface + codec?
  - Relation to user
  - [x] Keep signCount up to date (7.2.21)
  - 7.1.22 ~ credential in use
- [ ] Scan through repo for FIXMEs & missing verify steps
  - [x] Counter handling in (7.2.21)
  - [x] isUserVerificationRequired - configurability (7.1.15, 7.2.17)
  - [ ] Trust anchoring (7.1.20; result of AO.verify)
  - [ ] How to let client apps assess trust ambiguity (7.1.21)
  - [ ] Match algorithm in create() to createOptions (7.1.16)
- [ ] BC plan for verification trust paths
- [ ] Attestation statment return type/info
- [ ] BinaryString easier comparison?
- [ ] Lint issues, import sorting

Security/Risk:
- [ ] Certificate chain (7.1.20-21)
- [ ] RP policy for cert attestation type / attestation trustworthiness (7.1.21)
- [ ] Sign count LTE stored value (7.2.21)

Blocked?
- [ ] ClientExtensionResults (7.1.4, 7.1.17, 7.2.4, 7.2.18)
    All of the handling seems to be optional. I could not get it to ever come out non-empty.
- [ ] TokenBinding (7.1.10, 7.2.14)
    Unsupported except in Edge?

Naming?
- [ ] Codecs\Credential
- [ ] Codecs - static vs instance?
- [ ] Credential::getSafeId()
- [ ] ResponseParser -> Codecs?
- [ ] CreateResponse/GetResponse -> Add interfaces?

Nice to haves/Future scope:
- [ ] Refactor FIDO attestation to not need AD.getAttestedCredentialData
    - grab credential from AD
    - check PK type
- [ ] ExpiringChallenge & ChallengeInterface
- [ ] JSON generators:
  - [ ] PublicKeyCredentialCreationOptions
  - [ ] PublicKeyCredentialRequestOptions
      - note: no way to do straight json to arraybuffer?
      - emit as jsonp?
- [ ] Permit changing the Relying Party ID

Testing:
- [ ] Happy path w/ FidoU2F
- [ ] Happy path with macOS/Safari WebAuthn
- [s] Challenge mismatch (create+get)
- [s] Origin mismatch (CDJ)
- [s] RPID mismatch (AuthenticatorData)
- [s] !userPresent
- [s] !userVerified & required
- [s] !userVerified & not required
- [ ] PK mismatched in verify??
- [x] App-persisted data SerDe


Workflow for README:
~ see examples
  - (create.pk.excludeCredentials)
~ after get.verify(), save new challenge

tl;dr:
- set up RelyingParty

Register:
    - create a short-lived Challenge and stick in session
    - send data into js api
    - send response back and parse with ResponseParser
    - if verification succeeds, store credential associated with user ~ use CredentialCodec
Login:
    - create a short-lived Challenge and stick in session
    - optional: load user's existing Credentials & pass to publicKey.allowCredentials
    - send data into js api
    - send response back and parse with ResponseParser
    - look up stored credential from response
    - if verification succeeds, update stored credential


General resources:
- https://www.w3.org/TR/webauthn-2/
- https://www.w3.org/TR/2021/REC-webauthn-2-20210408/ (spec implemented to this version)
- https://webauthn.guide/

- https://developer.apple.com/videos/play/wwdc2021/10106/
