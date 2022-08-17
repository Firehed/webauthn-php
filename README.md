Cleanup Tasks

- [ ] Pull across PublicKeyInterface
- [ ] Pull across ECPublicKey
- [ ] Move key formatting into COSE key/turn COSE into key parser?
- [ ] Clearly define public scoped interfaces and classes
  - Public:
    - [ ] ResponseParser (interface?)
    - [ ] Challenge (DTO / serialization-safety)
    - [ ] RelyingParty
  - Internal:
    - [ ] Attestations
    - [ ] AuthenticatorData
  - TBD:
    - [ ] BinaryString
    - [ ] Certificate
    - [ ] CreateResponse/GetResponse (pub interfaces/priv impl?)
    - [ ] Credential (same^ / figure out serialization BC)
- [ ] Rework BinaryString to avoid binary in stack traces
- [ ] Use BinaryString consistently
- [ ] Establish required+best practices for data storage
  - Relation to user
  - Keep signCount up to date
  - 7.1.22 ~ credential in use
- [ ] Scan through repo for FIXMEs & missing verify steps
  - [ ] Counter handling in (7.2.21)
  - [ ] ClientExtensionResults (7.1.4, 7.1.17, 7.2.4, 7.2.18)
  - [ ] TokenBinding (7.1.10, 7.2.14)
  - [ ] isUserVerificationRequired - configurability (7.1.15, 7.2.17)
  - [ ] Trust anchoring (7.1.20; result of AO.verify)
  - [ ] How to let client apps assess trust ambiguity (7.1.21)
  - [ ] Match algorithm in create() to createOptions (7.1.16)
- [ ] BC plan for verification trust paths

Testing:

- [ ] Happy path w/ FidoU2F
- [ ] Happy path with macOS/Safari WebAuthn
- [ ] Challenge mismatch (create+get)
- [ ] Origin mismatch (CDJ)
- [ ] RPID mismatch (AuthenticatorData)
- [ ] !userPresent
- [ ] !userVerified & required
- [ ] !userVerified & not required
- [ ] PK mismatched in verify??
- [ ] App-persisted data SerDe
