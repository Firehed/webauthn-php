// See https://www.w3.org/TR/webauthn-2/#sctn-sample-registration for a more annotated example

const startRegister = async (e) => {
    e.preventDefault()

    if (!window.PublicKeyCredential) {
        // Browser does not support WebAuthn. Exit and fall back to another flow.
        return
    }

    const challengeReq = await fetch('/getChallenge.php')
    const challenge = await challengeReq.json()

    const username = document.getElementById('username').value

    const response = await fetch('/readmeRegisterStep1.php', {
        method: 'POST',
        body: 'username=' + username,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        },
    })
    const responseData = await response.json()
    const userInfo = responseData.user

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
            // This base64-decodes the response and translates it into the
            // Webauthn-required format.
            challenge: Uint8Array.from(atob(challenge.b64), c => c.charCodeAt(0)),
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
}
