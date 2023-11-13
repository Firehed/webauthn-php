const startLogin = async (e) => {
    e.preventDefault()

    const challengeReq = await fetch('/getChallenge.php')
    const challenge = await challengeReq.json()

    const username = document.getElementById('username').value
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
            challenge: Uint8Array.from(atob(challenge.b64), c => c.charCodeAt(0)),
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

}
