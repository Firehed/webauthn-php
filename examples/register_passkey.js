const getChallenge = async () => {
  const req = new Request('/getchallenge.php', {
    method: 'GET',
  })
  const res = await fetch(req)
  const challengeB64 = await res.json()
  console.debug('challenge b64', challengeB64)
  const challenge = atob(challengeB64)
  return Uint8Array.from(challenge, c => c.charCodeAt(0))
}

const getExistingCredentialIds = async (username) => {
  const req = new Request('/getcredentialids.php?username=' + username, {
    method: 'GET',
  })
  const res = await fetch(req)
  const encodedIds = await res.json()
  return encodedIds.map(
    id => Uint8Array.from(atob(id), c => c.charCodeAt(0))
  )
}

const postJson = async (url, data) => {
  const req = new Request(url, {
    body: JSON.stringify(data),
    headers: {
      'Content-type': 'application/json',
    },
    method: 'POST',
  })
  const result = await fetch(req)
  if (result.ok) {
    return await result.json()
  }
}

const doregister = async (e) => {
  e.preventDefault()
  const challenge = await getChallenge()

  const username = document.getElementById('r_username').value
  console.debug(username)
  // { id, name }
  const userInfo = await postJson('/createUser.php', { username })

  const createArgs = {
    publicKey: {
      challenge,
      pubKeyCredParams: [{alg: -7, type: "public-key"}],
      rp: {
        // Never user-visible?
        name: "My fancy site pt2",
      },
      user: {
        // Shown in account selection UI when not restricted by
        // allowCredentials
        name: userInfo.name,
        // Never user-visible?
        displayName: 'display name',
        // displayName: "Eric S.",
        // userHandle field during login
        id: Uint8Array.from(userInfo.id, c => c.charCodeAt(0)),
      },
      // let yubikeys run natively?
      // authenticatorSelection: {
      //   authenticatorAttachment: "cross-platform",
      // },
      attestation: "direct",
    }
  }
  
  const credential = await navigator.credentials.create(createArgs)
  // console.debug(credential)
  // console.debug(credential.response)
  // console.debug(credential.response.getTransports()) <-- not defined in all
  // browsers (yet). will contain enum{usb,ble,nfc,internal}[]
  const req = new Request('/display_registration.php', {
    body: JSON.stringify({
      rawId: new Uint8Array(credential.rawId),
      type: credential.type,
      attestationObject: new Uint8Array(credential.response.attestationObject),
      clientDataJSON: new Uint8Array(credential.response.clientDataJSON),
      // Not part of upstream parsing but needed to attach (normally would come
      // from auth'd session or something)
      username,
    }),
    headers: {
      'Content-type': 'application/json',
    },
    method: 'POST',
  })
  const debugInfo = await fetch(req)
  console.debug(await debugInfo.text())
}

const dologin = async (e) => {
  e.preventDefault()
  const username = document.getElementById('l_username').value

  // if (!PublicKeyCredential.isConditionalMediationAvailable || !PublicKeyCredential.isConditionalMediationAvailable()) {
  //   console.error('no mediation')
  //   // cannot autofill
  //   // get credential IDs associated with user?
  // }

  const challenge = await getChallenge()
  const existingCredentialIds = await getExistingCredentialIds(username)
  const options = {
    publicKey: {
      challenge,
      allowCredentials: existingCredentialIds.map(id => ({
        id,
        type: 'public-key',
        // transports: ['usb', 'ble', 'nfc', 'internal'],
      })),
    },
    // remove this if the user didn't autofill
    // mediation: "conditional"
  }
  console.debug('options', options)

  const credential = await navigator.credentials.get(options)
  console.debug('credential', credential)
  const req = new Request('/display_login.php', {
    body: JSON.stringify({
      rawId: new Uint8Array(credential.rawId),
      type: credential.type,
      authenticatorData: Array.from(new Uint8Array(credential.response.authenticatorData)),
      clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
      signature: Array.from(new Uint8Array(credential.response.signature)),
      userHandle: Array.from(new Uint8Array(credential.response.userHandle)),
      // see above
      username,
    }),
    headers: {
      'Content-type': 'application/json',
    },
    method: 'POST',
  })
  const debugInfo = await fetch(req)
  console.debug(await debugInfo.text())

}

// doregister()
// dologin()
