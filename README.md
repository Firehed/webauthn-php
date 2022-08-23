# WebAuthn for PHP

A way to move beyond passwords

## What is WebAuthn?

## Crash Course

This will cover the basic workflows for integrating this library to your web application.
Classes referenced in the examples omit the `Firehed\WebAuthn` namespace prefix for brevity.

Note: there's a complete set of examples in the [`examples`](examples) directory.

### Setup

Create a `RelyingParty` instance.
This **MUST** match the complete origin that users will interact with; e.g. `https://login.example.com:1337`.
The protocol is always required; the port must only be present if using a non-standard port and must be excluded for standard ports.

```php
$rp = new RelyingParty('https://www.example.com');
```

Important: WebAuthn will only work in a "secure context".
This means that the domain MUST run over `https`, with a sole exception for `localhost`.
See https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts for more info.

### Registering a WebAuthn credential to a user

This step takes place either when a user is first registering, or later on to supplement or replace their password.

1) Create a new, random Challenge.
This may be stored in a user's session or equivalent; it needs to be kept statefully server-side.
Send it to the user as base64.

```php
<?php

// Generate challenge
$challenge = Challenge::random();

// Store server-side; adjust to your app's needs
session_start();
$_SESSION['webauthn_challenge'] = $challenge;

// Send to user
header('Content-type: application/json');
echo json_encode($challenge->getBase64());
```

2) In client Javascript code, read the challege and provide it to the WebAuthn APIs.
You will also need the registering user's identifier and some sort of username

```javascript
// See https://www.w3.org/TR/webauthn-2/#sctn-sample-registration for a more annotated example

if (!window.PublicKeyCredential) {
    // Browser does not support WebAuth. Exit and fall back to another flow.
    return
}

// This comes from your app/database, fetch call, etc. Depending on your app's
// workflow, the user may or may not have a password (which isn't relevant to WebAuthn).
const userInfo = {
    name: 'Username', // chosen name or email, doesn't really matter
    id: 'abc123', // any unique id is fine; uuid or PK is preferable
}

const response = await fetch('above challenge endpoint')
const challengeB64 = await response.json()
const challenge = atob(challengeB64) // base64-decode

const createOptions = {
    publicKey: {
        rp: {
            name: 'My website',
        },
        user: {
            name: userInfo.name,
            displayName: 'User Name',
            id: Uint8Array.from(user.id, c => charCodeAt(0)),
        },
        challenge: Uint8Array.from(challenge, c => c.charCodeAt(0)),
        pubKeyCredParams: [
            {
                alg: -7, // ES256
                type: "public-key",
            },
        ],
    },
    attestation: 'direct',
}

// Call the WebAuthn browser API and get the response. This may throw, which you
// should handle. Example: user cancels or never interacts with the device.
const credential = await navigator.credentials.create(createOptions)

// Format the credential to send to the server. This must match the format
// handed by the ResponseParser class. The formatting code below can be used
// without modification.
const dataForResponseParser = {
    rawId: Array.from(new Uint8Array(credential.rawId)),
    type: credential.type,
    attestationObject: Array.from(new Uint8Array(credential.response.attestationObject)),
    clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
}

// Send this to your endpoint - adjust to your needs.
const request = new Request('/below parsing endpoint', {
    body: JSON.stringify(dataForResponseParser),
    headers: {
        'Content-type: application/json',
    },
    method: 'POST',
})
const result = await fetch(request)
// handle result, update user with status if desired.
```

3) Parse and verify the response and, if successful, associate with the user.

```php
<?php

$json = file_get_contents('php://stdin');
$data = json_decode($json, true);

$parser = new ResponseParser();
$createResponse = $parser->parseCreateResponse($data);

$rp = $valueFromSetup; // e.g. $diContainer->get(RelyingParty::class);
$challenge = $_SESSION['webauthn_challenge'];

try {
    $credential = $createResponse->verify($challenge, $rp);
} catch {
    // Verification failed. Send an error to the user?
    header('HTTP/1.1 403 Unauthorized');
    return;
}

// Store the credential associated with the authenticated user. This is
// incredibly application-specific. Below is a sample table.
/*
CREATE TABLE user_credentials (
    id text PRIMARY KEY,
    user_id text,
    credential text,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
*/

$codec = new Codecs\Credential();
$encodedCredential = $codec->encode($credential);
$pdo = getDatabaseConnection();
$stmt = $pdo->prepare('INSERT INTO user_credentials (id, user_id, credential) VALUES (?, ?, ?);');
$result = $stmt->execute([
    $credential->getSafeId(),
    $user->getId(), // $user comes from your authn process
    $encodedCredential,
]);

// Continue with normal application flow, error handling, etc.
header('HTTP/1.1 200 OK');
```

4) There is no step 4. The verified credential is now stored and associated with the user!

### Authenticating a user with an existing WebAuthn credential

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
- [x] Refactor FIDO attestation to not need AD.getAttestedCredentialData
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
