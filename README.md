# Web Authentication for PHP

A way to move beyond passwords

[![Test](https://github.com/Firehed/webauthn-php/actions/workflows/test.yml/badge.svg)](https://github.com/Firehed/webauthn-php/actions/workflows/test.yml)
[![Static analysis](https://github.com/Firehed/webauthn-php/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/Firehed/webauthn-php/actions/workflows/static-analysis.yml)
[![Lint](https://github.com/Firehed/webauthn-php/actions/workflows/lint.yml/badge.svg)](https://github.com/Firehed/webauthn-php/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/Firehed/webauthn-php/branch/main/graph/badge.svg?token=xr69yhtCBl)](https://codecov.io/gh/Firehed/webauthn-php)

## What is Web Authentication?
Web Authentication, frequently referenced as `WebAuthn`, is a set of technologies and APIs to provide user authentication using modern cryptography.
Instead of passwords and hashing, WebAuthn allows users to generate encryption keypairs, provide the public key to the server, and authenticate by signing server-generated challenges using the private key that never leaves their possession.

This means that servers _never touch sensitive data_ and _cannot leak authentication information_ should a breach ever occur.
This also means that users do not have to manage passwords for individual websites, and can instead rely on tools provided by operating systems, browsers, and hardware security keys.

## Using this library: A Crash Course

This will cover the basic workflows for integrating this library to your web application.

> [!NOTE]
> The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
> NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
> "MAY", and "OPTIONAL" in this document are to be interpreted as
> described in BCP 14 [RFC2119] [RFC8174] when, and only when, they
> appear in all capitals, as shown here.

### Sample Code
There's a complete set of working examples in the [`examples`](examples) directory.
Application logic is kept to a bare minimum in order to highlight the most important workflow steps.

### Install

```sh
composer require firehed/webauthn
```

### Setup

Create a `RelyingPartyInterface` instance.
See [Relying Party](#relying-parties) for more information about selecting an implementation.

```php
$rp = new \Firehed\WebAuthn\SingleOriginRelyingParty('https://www.example.com');
```


Also create a `ChallengeManagerInterface`.
This will store and validate the one-time use challenges that are central to the WebAuthn protocol.
See the [Challenge Management](#challenge-management) section below for more information.

```php
session_start();
$challengeManager = new \Firehed\WebAuthn\SessionChallengeManager();
```

> [!IMPORTANT]
> WebAuthn will only work in a "secure context".
> This means that the domain MUST run over `https`, with a sole exception for `localhost`.
> See [https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts]() for more info.

### Registering a WebAuthn credential to a user

This step takes place either when a user is first registering, or later on to supplement or replace their password.

1) Create an endpoint that will return a new, random Challenge.
Send it to the user as base64.

```php
<?php

// Generate challenge
$challenge = $challengeManager->createChallenge();

// Send to user
header('Content-type: application/json');
echo json_encode($challenge->getBase64());
```

2) In client Javascript code, read the challege and provide it to the WebAuthn APIs.
You will also need the registering user's identifier and some sort of username

```javascript
// See https://www.w3.org/TR/webauthn-2/#sctn-sample-registration for a more annotated example

if (!window.PublicKeyCredential) {
    // Browser does not support WebAuthn. Exit and fall back to another flow.
    return
}

// This comes from your app/database, fetch call, etc. Depending on your app's
// workflow, the user may or may not have a password (which isn't relevant to WebAuthn).
const userInfo = {
    name: 'Username', // chosen name or email, doesn't really matter
    id: 'abc123', // any unique id is fine; uuid or PK is preferable
}

const response = await fetch('/readmeRegisterStep1.php')
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
            id: Uint8Array.from(userInfo.id, c => c.charCodeAt(0)),
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
    transports: credential.response.getTransports(),
}

// Send this to your endpoint - adjust to your needs.
const request = new Request('/readmeRegisterStep3.php', {
    body: JSON.stringify(dataForResponseParser),
    headers: {
        'Content-type': 'application/json',
    },
    method: 'POST',
})
const result = await fetch(request)
// handle result, update user with status if desired.
```

3) Parse and verify the response and, if successful, associate with the user.

> [!NOTE]
> The `publicKey.user.id` field can be looked up and used later on during authentication.

```php
<?php

use Firehed\WebAuthn\{
    Codecs,
    ArrayBufferResponseParser,
};

$json = file_get_contents('php://input');
$data = json_decode($json, true);

$parser = new ArrayBufferResponseParser();
$createResponse = $parser->parseCreateResponse($data);

try {
    // $challengeManager and $rp are the values from the setup step
    $credential = $createResponse->verify($challengeManager, $rp);
} catch (Throwable) {
    // Verification failed. Send an error to the user?
    header('HTTP/1.1 403 Unauthorized');
    return;
}

// Store the credential associated with the authenticated user. See
// "Registration & Credential Storage" in the README for more info.

$codec = new Codecs\Credential();
$encodedCredential = $codec->encode($credential);
$pdo = getDatabaseConnection();
$stmt = $pdo->prepare('INSERT INTO credentials (storage_id, user_id, credential) VALUES (:storage_id, :user_id, :encoded);');
$result = $stmt->execute([
    'storage_id' => $credential->getStorageId(),
    'user_id' => $user->getId(), // $user comes from your authn process
    'encoded' => $encodedCredential,
]);

// Continue with normal application flow, error handling, etc.
header('HTTP/1.1 200 OK');
```

4) There is no step 4. The verified credential is now stored and associated with the user!

### Authenticating a user with an existing WebAuthn credential

Note: this workflow may be a little different if supporting [passkeys](https://developer.apple.com/passkeys/).
Updated samples will follow.

Before starting, you will need to collect the username or id of the user trying to authenticate, and retrieve the user info from storage.
This assumes the same schema from the previous Registration example.

1) Create an endpoint that will return a Challenge and any credentials associated with the authenticating user:

```php
<?php

use Firehed\WebAuthn\Codecs;

session_start();

$pdo = getDatabaseConnection();
$user = getUserByName($pdo, $_POST['username']);
if ($user === null) {
    header('HTTP/1.1 404 Not Found');
    return;
}
$_SESSION['authenticating_user_id'] = $user['id'];

// See examples/functions.php for how this works
$credentialContainer = getCredentialsForUserId($pdo, $user['id']);

$challenge = $challengeManager->createChallenge();

// Send to user
header('Content-type: application/json');
echo json_encode([
    'challengeB64' => $challenge->getBase64(),
    'credential_ids' => $credentialContainer->getBase64Ids(),
]);
```

2) In client Javascript code, read the data from above and provide it to the WebAuthn APIs.

```javascript
// Get this from a form, etc.
const username = document.getElementById('username').value

// This can be any format you want, as long as it works with the above code
const response = await fetch('/readmeLoginStep1.php', {
    method: 'POST',
    body: 'username=' + username,
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    },
})

const data = await response.json()

// Format for WebAuthn API
const getOptions = {
    publicKey: {
        challenge: Uint8Array.from(atob(data.challengeB64), c => c.charCodeAt(0)),
        allowCredentials: data.credential_ids.map(id => ({
            id: Uint8Array.from(atob(id), c => c.charCodeAt(0)),
            type: 'public-key',
        }))
    },
}

// Similar to registration step 2

// Call the WebAuthn browser API and get the response. This may throw, which you
// should handle. Example: user cancels or never interacts with the device.
const credential = await navigator.credentials.get(getOptions)

// Format the credential to send to the server. This must match the format
// handed by the ResponseParser class. The formatting code below can be used
// without modification.
const dataForResponseParser = {
    rawId: Array.from(new Uint8Array(credential.rawId)),
    type: credential.type,
    authenticatorData: Array.from(new Uint8Array(credential.response.authenticatorData)),
    clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
    signature: Array.from(new Uint8Array(credential.response.signature)),
    userHandle: Array.from(new Uint8Array(credential.response.userHandle)),
}

// Send this to your endpoint - adjust to your needs.
const request = new Request('/readmeLoginStep3.php', {
    body: JSON.stringify(dataForResponseParser),
    headers: {
        'Content-type': 'application/json',
    },
    method: 'POST',
})
const result = await fetch(request)
// handle result - if it went ok, perform any client needs to finish auth process
```

3) Parse and verify the response. If successful, update the credential & finish app login process.

```php
<?php

use Firehed\WebAuthn\{
    Codecs,
    ArrayBufferResponseParser,
};

session_start();

$json = file_get_contents('php://input');
$data = json_decode($json, true);

$parser = new ArrayBufferResponseParser();
$getResponse = $parser->parseGetResponse($data);
$userHandle = $getResponse->getUserHandle();

$credentialContainer = getCredentialsForUserId($pdo, $_SESSION['authenticating_user_id']);
if ($userHandle !== null && $userHandle !== $_SESSION['authenticating_user_id']) {
    throw new Exception('User handle does not match authentcating user');
}

try {
    // $challengeManager and $rp are the values from the setup step
    $updatedCredential = $getResponse->verify($challengeManager, $rp, $credentialContainer);
} catch (Throwable) {
    // Verification failed. Send an error to the user?
    header('HTTP/1.1 403 Unauthorized');
    return;
}
// Update the credential
$codec = new Codecs\Credential();
$encodedCredential = $codec->encode($updatedCredential);
$stmt = $pdo->prepare('UPDATE credentials SET credential = :encoded WHERE storage_id = :storage_id AND user_id = :user_id');
$result = $stmt->execute([
    'storage_id' => $updatedCredential->getStorageId(),
    'user_id' => $_SESSION['authenticating_user_id'],
    'encoded' => $encodedCredential,
]);

header('HTTP/1.1 200 OK');
// Send back whatever your webapp needs to finish authentication
```

> [!NOTE]
> The `$userHandle` value provides flexibility for different authentication flows.
> If null, the authenticator does not support user handles, and you MUST use a user-provided value to look up who is authenticating.
> If a value is present, it will match a previously-registered `publicKey.user.id` value.
> The userHandle SHOULD be used to cross-reference a user-provided id if set, and MAY be used to look up the authenticating user.
> In either case, the previously-registered credentials in `$credentialContainer` MUST be fetched based on the user name or id.
>
> See [Autofill-assited requests](#autofill-assisted-requests) and [WebAuthn §7.2 Step 6](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-verifying-assertion) for more details.

## Additional details

### Relying Parties

In layperson's terms, a Relying Party is the server performing authentication.
WebAuthn credentials are based on a specific Relying Party Identifier (`rpId`), and this is used to restrict the origins future authentication can be performed from.

To support this, the library supports multiple options for configuring the `rpId` for different use-cases:

| Implementation | Usage |
| --- | --- |
| `SingleOriginRelyingParty` | Users only authenticate from a single host (e.g. `www.yoursite.com`) |
| `MultiOriginRelyingParty` | Users may authenticate from multiple specific subdomains (e.g. `www.yoursite.com` and `app.yoursite.com`) |
| `WildcardRelyingParty` | Users may authenticate from any arbitrary subdomain of a given domain |

Both the registration and authentication processes allow for specifying the `rpId` in the Javascript client code.
The value defaults to the page origin unless explicitly specified.
Applications MAY use a less-specific host as the `rpId`, so long as it's a valid registrable domain.

> [!IMPORTANT]
> Once a credential is created, it's permanently associated with the `rpId` used during creation.
> Further use of that credential is restricted at a protocol level to the same `rpId`.

Example: For a WebAuthn flow on `https://www.example.com:8443`, the `rpId` will default to `www.example.com`.
It MAY be overridden to `example.com`.
It MAY NOT be set to `com` (not registrable),
`other.example.com` (mismatch of current host),
`test.www.example.com` (more specific than current host),
or `www.example.co` (different registrable domain).

In all cases, the WebAuthn protocol does not allow credential sharing across multiple domains.
E.g. a credential cannot be shared between `example.co.jp` and `example.us`.

See the [specification](https://www.w3.org/TR/webauthn-2/#relying-party-identifier) for more details.

Tip: using `MultiOriginRelyingParty` with a single origin can help with future-proofing.
```php
$rp = new \Firehed\WebAuthn\MultiOriginRelyingParty(['https://www.example.com'], 'example.com');
```

```js
// registration or authentication flow on www.example.com
const createOptions = {
    publicKey: {
        rp: {
            id: 'example.com',
        },
        // ...
```


#### Terminology

* `origin` The combination of scheme, host, and (if applicable) non-standard port.
  Examples: `https://www.example.com`, `https://example.com`, `https://different.example.com:8443`, `http://localhost:8080`.
  Do NOT include the port if using the protocol-standard port (i.e. 443 for https)
* `rpId` The Relying Party Identifier.
  This is the host component of a URL; e.g. a domain or subdomain.
  It does not include a port or scheme.
  Examples: `example.com`, `www.example.com`, `localhost`.


### Autofill-assisted requests

The simplest implementation of WebAuthn still starts with a traditional username field.
To make a more streamlined authentication experience, you may use Conditional Medation and Autofill-assisted requests.

#### During registration

Ensure that the `user.id` field is set appropriately.
This SHOULD be an immutable value, such as (but not limited to) a primary key in a database.

#### During authentication

* Split apart the process of generating a challenge from looking up and providing previously-registered credential IDs.
  This is genreally useful for all flows, but required to support Conditional Mediation since you don't know the user ahead of time.

* Add a check for Conditional Mediation support. If supported, use it.

  ```js
  const isCMA = await PublicKeyCredential.isConditionalMediationAvailable()
  if (!isCMA) {
    // Autofill-assisted requests are not supported. Fall back to username flow.
    return
  }
  const challenge = await getChallenge() // existing API call
  const getOptions = {
    publicKey: {
      challenge,
      // Set other options as appropriate
    },
    mediation: 'conditional', // Add this
  }
  const credential = await navigator.credentials.get(getOptions)
  // proceed as usual
  ```

* Adjust verification API to use the userHandle from the credential.
  This can be done either/or to have a single authentication endpoint.

  ```php
  // ...
  $getResponse = $parser->parseGetResponse($data);
  $userHandle = $getResponse->getUserHandle();
  $userId = $_POST['username'] ?? null; // match your existing form/API formats
  if ($userHandle === null) {
    assert($userId !== null);
    $user = findUserById($userId); // ORM lookup, etc
  } else {
    $user = findUserById($userHandle);
    assert($userId === $user->id || $userId === null);
  }
  $credentialContainer = getCredentialsForUser($user);
  // ...
  ```



Cleanup Tasks

- [x] Pull across PublicKeyInterface
- [x] Pull across ECPublicKey
- [x] Move key formatting into COSE key/turn COSE into key parser?
- [x] Clearly define public scoped interfaces and classes
  - Public:
    - [x] ResponseParser (interface?)
    - [x] Challenge (DTO / serialization-safety in session)
    - [x] RelyingParty
    - [x] CredentialInterface
    - [x] Responses\AttestationInterface & Responses\AssertionInterface
    - [x] Errors
  - Internal:
    - [x] Attestations
    - [x] AuthenticatorData
    - [x] BinaryString
    - [x] Credential
    - [x] Certificate
    - [x] CreateRespose & GetResponse
- [x] Rework BinaryString to avoid binary in stack traces
- [x] Use BinaryString consistently
  - [ ] COSEKey.decodedCbor
  - [ ] Attestations\FidoU2F.data
- [x] Establish required+best practices for data storage
  - [x] CredentialInterface + codec?
  - [x] Relation to user
  - [x] Keep signCount up to date (7.2.21)
  - [x] 7.1.22 ~ credential in use
- [ ] Scan through repo for FIXMEs & missing verify steps
  - [x] Counter handling in (7.2.21)
  - [x] isUserVerificationRequired - configurability (7.1.15, 7.2.17)
  - [ ] Trust anchoring (7.1.20; result of AO.verify)
  - [ ] How to let client apps assess trust ambiguity (7.1.21)
  - [ ] Match algorithm in create() to createOptions (7.1.16)
- [ ] BC plan for verification trust paths
- [x] Attestation statment return type/info
- [x] BinaryString easier comparison?
- [x] Lint issues
- [ ] Import sorting

Security/Risk:
- [ ] Certificate chain (7.1.20-21)
- [ ] RP policy for cert attestation type / attestation trustworthiness (7.1.21)
- [ ] Sign count LTE stored value (7.2.21)

Blocked?
- [ ] ClientExtensionResults (7.1.4, 7.1.17, 7.2.4, 7.2.18)
    All of the handling seems to be optional. I could not get it to ever come out non-empty.
- [x] TokenBinding (7.1.10, 7.2.14)
    Unsupported except in Edge?
    Removed in level 3 spec

Naming?
- [ ] Codecs\Credential
- [ ] Codecs - static vs instance?
- [x] Credential::getStorageId()
- [ ] ResponseParser -> Codecs?
- [x] CreateResponse/GetResponse -> Add interfaces?
- [ ] Parser -> parseXResponse => parse{Attestation|Assertion}Data
- [x] Error\* -> Errors\*

Nice to haves/Future scope:
- [x] Refactor FIDO attestation to not need AD.getAttestedCredentialData
    - grab credential from AD
    - check PK type
- [x] ExpiringChallenge & ChallengeInterface
- [ ] JSON generators:
  - [ ] PublicKeyCredentialCreationOptions
  - [ ] PublicKeyCredentialRequestOptions
      - note: no way to do straight json to arraybuffer?
      - emit as jsonp?
- [ ] Permit changing the Relying Party ID
- [ ] Refactor COSEKey to support other key types, use enums & ADT-style composition
- [ ] GetResponse userHandle
- [x] Assertion.verify (CredentialI | CredentialContainer)

Testing:
- [x] Happy path w/ FidoU2F
- [x] Happy path with macOS/Safari WebAuthn
- [x] Challenge mismatch (create+get)
- [x] Origin mismatch (CDJ)
- [x] RPID mismatch (AuthenticatorData)
- [s] !userPresent
- [x] !userVerified & required
- [s] !userVerified & not required
- [ ] PK mismatched in verify??
- [x] App-persisted data SerDe
- [ ] Parser handling of bad input formats

## Best Practices

### Data Handling

Use the _exact data format_ shown in the examples above (`dataForResponseParser`) and use the `ResponseParser` class to process them.
Those wire formats are covered by semantic versioning and guaranteed to not have breaking changes outside of a major version.

#### Upcoming `.toJSON()` support
Browsers are starting to support a [`.toJSON()`](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#browser_compatibility) method on the WebAuthn PublicKeyCredential response objects.
There is also a [polyfill](https://github.com/github/webauthn-json) available.
As browser support for this format increases, it will become the recommended approach for sending responses back to the server for verification.

If - and only if - you use that format (either natively or through a polyfill), update the JS code on both calls:
```js
const dataForResponseParser = credential.toJSON()
```
and on the receiving APIs, replace `ArrayBufferResponseParser` with `JsonResponseParser`.

### Challenge management

Challenges are a [cryptographic nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) that ensure a login attempt works only once.
Their single-use nature is critical to the security of the WebAuthn protocol.

Your application SHOULD use one of the library-provided `ChallengeManagerInterface` implementations to ensure the correct behavior.

| Implementation | Usage |
| --- | --- |
| `SessionChallengeManager` | Manages challenges through native PHP [Sessions](https://www.php.net/manual/en/intro.session.php). |

If one of the provided options is not suitable, you MAY implement the interface yourself or manage challenges manually.
In the event you find this necessary, you SHOULD open an Issue and/or Pull Request for the library that indicates the shortcoming.

> [!WARNING]
> You MUST validate that the challenge was generated by your server recently and has not already been used.
> **Failing to do so will compromise the security of the protocol!**
> Implementations MUST NOT trust a client-provided value.
> The built-in `ChallengeManagerInterface` implementations will handle this for you.

Challenges generated by your server SHOULD expire after a short amount of time.
You MAY use the `ExpiringChallenge` class for convenience (e.g. `$challenge = ExpiringChallenge::withLifetime(60);`), which will throw an exception if the specified expiration window has been exceeded.
It is RECOMMENDED that your javascript code uses the `timeout` setting (denoted in milliseconds) and matches the server-side challenge expiration, give or take a few seconds.

> [!NOTE]
> The W3C specification recommends a timeout in the range of 15-120 seconds.

### Error Handling

The library is built around a "fail loudly" principle.
During both the registration and authentication process, if an exception is not thrown it means that the process succeeded.
Be prepared to catch and handle these exceptions.
All exceptions thrown by the library implement `Firehed\WebAuthn\Errors\WebAuthnErrorInterface`, so if you want to only catch library errors (or test for them in a generic error handler), use that interface.

### Registration & Credential Storage

A sample database table may look _something_ like this:

```sql
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    storage_id TEXT UNIQUE,
    credential TEXT,
    nickname TEXT
);
```

You may also want other metadata such as insertion and/or update times, time of last use, etc.
Such data is outside of the scope of this library.

If during a persistence operation any data would be truncated, the application MUST detect this and raise an error.
Often, this means enabling `PDO::ERRMODE_EXCEPTION` and ensuring the database instance has sufficiently strict runtime settings.

#### `user_id`
Reference to your users table.
Users SHOULD be able to associate more than one credential with their account,
and SHOULD have a mechanism to add additional and remove existing credentials.
This will be specific to your application.

#### `storage_id`
This is the output of `$credential->getStorageId()`.
It MAY be used as a primary key (e.g. having only an `id` field, and populating it with `->getStorageId()`).
The value will always be plain ASCII.

The raw value is [at most 1,023 bytes](https://www.w3.org/TR/webauthn-3/#credential-id), and is exported as Base64URL, so storage should support **at least `1,364` characters**.

This field SHOULD have a `UNIQUE` index.
If during storage the unique constraint is violated AND it's associated with a different user,
your application MUST handle this situation,
either by returning an error or de-associating the existing record with the other user.
See https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential section 7.1 step 22 for more info.

#### `credential`
This is the output of `Firehed\WebAuthn\Codecs\Credential::encode($credential)`.
When retreived from the database for use during authentication, it should be unserialized with the complementing `->decode()` method on the same class.

This field SHOULD support storing at least 4KiB, and it's RECOMMENDED to support storing at least 64KiB (commonly `TEXT` or `varchar(65535)`).
The value will always be plain ASCII.
To reduce the stored size, you MAY pass `storeRegistrationData: false` to the codec's constructor; be aware that doing so will eliminate the ability to re-validate credentials in the future.

This format IS COVERED by semantic versioning.

#### `nickname`
The `nickname` field is optional, and (if used) stores a user-provided value that they can use when managing credentials.
Only the owner of the credential should be able to see this nickname.



### Authentication

- The `verify()` method called during authentication returns an updated credential.
  Your application SHOULD update the persisted value each time this happens.
  Doing so increases security, as it improves the ability to detect and act on replay attacks.

## Versioning and Backwards Compatibility

This library follows Semantic Versioning.
Note that classes or methods marked as `@internal` are NOT covered by the same guarantees.
Anything intended explicitly for public use has been marked with `@api`.
If there are any unclear areas, please file an issue.

There are additional notes in Best Practices / Data Handling around this.

## Supported Identifiers

When generating a credential, the client will attest to its authenticity.
Due to an inability to generate responses with all formats, not all are supported (the risk of implementing to the spec without sufficient testing is too great).

| Format | Supported | Spec | Notes |
| --- | --- | --- | --- |
| `packed` | ✅⚠️[^limited-trust-path] | 8.2 | |
| `tpm` | ❌ | 8.3 | |
| `android-key` | ❌ | 8.4 | |
| `android-safetynet` | ❌ | 8.5 | |
| `fido-u2f` | ✅ | 8.6 | YubiKeys and similar U2F stateless devices. |
| `none` | ✅ | 8.7 | Used by Apple in Safari when using Passkeys (even when direct attestation is requested) |
| `apple` | ✅⚠️ [^ext-vec], [^limited-trust-path] | 8.8 | Apple no longer appears to use this format, instead providing non-attested credentials (fmt=none). |
| `compound` | ❌ | 8.9 | This format only appears in the editor's draft of the spec and is not yet on the official registry. |

If you receive an `UnhandledMatchError` from the library pertaining to a format, please file an issue.
The library aims to have full format coverage eventually, but _needs your help_ in order to get there.

## Resources and Errata

This library is a rework of [`u2f-php`](https://github.com/Firehed/u2f-php), which is built around a much earlier version of the spec known as U2F, pioneered by YubiCo with their YubiKey products.
WebAuthn continues to support YubiKeys (and other U2F devices), as does this library.
Instead of building a v2 of that library, a clean break was found to be easier:

- There's no need to deal with moving the Composer package (the u2f name no longer makes sense)
- A lot of the data storage mechanisms needed to be significantly reworked
- The platform extensibility in WebAuthn did not translate well to the previous structures
- Dropping support for older PHP versions & using new features simplified a lot

WebAuthn spec:

- https://www.w3.org/TR/webauthn-2/
- https://www.w3.org/TR/2021/REC-webauthn-2-20210408/ (spec implemented to this version)

General quickstart guide:
- https://webauthn.guide/

Intro to passkeys:
- https://developer.apple.com/videos/play/wwdc2021/10106/

[^ext-vec]: Support is based on [unofficial test vectors](https://github.com/w3c/webauthn/issues/1633).
[^limited-trust-path]: Handling of attestation trust path is limited.
