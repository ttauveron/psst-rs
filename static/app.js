const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()
const AES_GCM_NONCE_BYTES = 12
const AES_GCM_KEY_BYTES = 32
let latestSecretReference = null
let pendingTurnstileConfig = null

window.onPsstTurnstileLoad = () => {
  if (pendingTurnstileConfig) {
    renderTurnstileWidget(pendingTurnstileConfig)
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const createRoot = document.getElementById("create-app")
  if (createRoot) {
    bootCreatePage(createRoot).catch((error) => {
      console.error(error)
      setText("create-status", "Internal error while encrypting locally.")
    })
  }

  const readRoot = document.getElementById("read-app")
  if (readRoot) {
    bootReadPage(readRoot).catch((error) => {
      console.error(error)
      setText("read-status", "Unable to decrypt this secret.")
    })
  }
})

function getUtf8ByteLength(value) {
  return textEncoder.encode(value).length
}

async function encryptPlaintext(plaintext) {
  const plaintextBytes = textEncoder.encode(plaintext)
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  )
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key))
  const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES))
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintextBytes),
  )

  return { rawKey, nonce, ciphertext }
}

async function decryptCiphertext(rawKey, nonce, ciphertext) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    "AES-GCM",
    false,
    ["decrypt"],
  )
  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    cryptoKey,
    ciphertext,
  )

  return textDecoder.decode(plaintextBuffer)
}

function getFragmentKey(locationLike) {
  return locationLike.hash.slice(1)
}

function decodeKeyFragment(rawKey) {
  const keyBytes = base64UrlToBytes(rawKey)
  if (keyBytes.length !== AES_GCM_KEY_BYTES) {
    throw new Error("Invalid key length")
  }

  return keyBytes
}

function clearFragmentFromLocation(historyLike, locationLike) {
  historyLike.replaceState(
    null,
    "",
    `${locationLike.pathname}${locationLike.search}`,
  )
}

async function bootCreatePage(root) {
  const form = document.getElementById("create-form")
  const input = document.getElementById("secret-input")
  const ttlSelect = document.getElementById("ttl-select")
  const createButton = document.getElementById("create-button")
  const shareLink = document.getElementById("share-link")
  const result = document.getElementById("create-result")
  const copyButton = document.getElementById("copy-link-button")
  const deleteButton = document.getElementById("delete-secret-button")
  const turnstileTokenInput = document.getElementById("turnstile-token")
  const maxSecretBytes = Number(root.dataset.maxSecretBytes)
  const enableCreate = root.dataset.enableCreate === "true"
  const turnstileSiteKey = root.dataset.turnstileSiteKey || ""

  updateSecretSize(input.value, maxSecretBytes)
  input.addEventListener("input", () => {
    armTurnstileForNextSecret(turnstileState, createButton)
    updateSecretSize(input.value, maxSecretBytes)
  })

  if (!enableCreate) {
    createButton.disabled = true
    ttlSelect.disabled = true
    input.disabled = true
    setText("create-status", "Secret creation is temporarily disabled.")
    return
  }

  const turnstileState = createTurnstileState()
  pendingTurnstileConfig = {
    siteKey: turnstileSiteKey,
    tokenInput: turnstileTokenInput,
    createButton,
    state: turnstileState,
  }
  if (window.turnstile && typeof window.turnstile.render === "function") {
    renderTurnstileWidget(pendingTurnstileConfig)
  }
  syncCreateButtonState(createButton, turnstileState)

  ttlSelect.addEventListener("change", () => {
    armTurnstileForNextSecret(turnstileState, createButton)
  })

  form.addEventListener("submit", async (event) => {
    event.preventDefault()
    setText("create-status", "")
    setText("create-result-status", "")
    setText("copy-status", "")
    setText("delete-status", "")

    const plaintext = input.value
    const plaintextBytes = textEncoder.encode(plaintext)

    if (plaintextBytes.length === 0) {
      setText("create-status", "The secret must not be empty.")
      return
    }

    if (plaintextBytes.length > maxSecretBytes) {
      setText(
        "create-status",
        `The secret exceeds the ${maxSecretBytes} UTF-8 byte limit.`,
      )
      return
    }

    if (!turnstileState.ready) {
      setText("create-status", "Anti-abuse verification failed to load. Reload the page and try again.")
      return
    }

    if (turnstileState.consumed) {
      resetTurnstile(turnstileState)
      syncCreateButtonState(createButton, turnstileState)
      setText("create-status", "Complete the anti-abuse verification before creating another secret.")
      return
    }

    const turnstileToken = turnstileTokenInput ? turnstileTokenInput.value : ""
    if (!turnstileToken) {
      setText("create-status", "Complete the anti-abuse verification before creating a secret.")
      return
    }

    createButton.disabled = true
    createButton.textContent = "Encrypting..."

    try {
      const { rawKey, nonce, ciphertext } = await encryptPlaintext(plaintext)

      const response = await fetch("/api/create", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ciphertext: bytesToBase64Url(ciphertext),
          nonce: bytesToBase64Url(nonce),
          expires_in_seconds: Number(ttlSelect.value),
          turnstile_token: turnstileToken,
        }),
      })
      turnstileState.consumed = true
      syncCreateButtonState(createButton, turnstileState)

      const payload = await readJson(response)
      if (!response.ok) {
        throw new Error(payload.error || "Secret creation failed.")
      }

      const shareUrl = buildShareUrl(
        root.dataset.publicBaseUrl,
        payload.id,
        bytesToBase64Url(rawKey),
      )

      latestSecretReference = {
        id: payload.id,
        deleteToken: payload.delete_token,
      }
      shareLink.value = shareUrl
      result.hidden = false
      result.scrollIntoView({ behavior: "smooth", block: "nearest" })
      setText(
        "create-result-status",
        "psst link generated. The server does not know the key, and the secret can be read only once.",
      )
    } catch (error) {
      latestSecretReference = null
      setText("create-result-status", "")
      setText("create-status", mapCreateErrorMessage(error))
    } finally {
      syncCreateButtonState(createButton, turnstileState)
      createButton.textContent = "Create psst link"
    }
  })

  copyButton.addEventListener("click", async () => {
    if (!shareLink.value) {
      return
    }

    try {
      await copyText(shareLink.value)
      setText("copy-status", "Link copied.")
    } catch (_error) {
      setText("copy-status", "Automatic copy is unavailable, please copy the link manually.")
    }
  })

  deleteButton.addEventListener("click", async () => {
    if (!latestSecretReference) {
      setText("delete-status", "No active secret is available to delete.")
      return
    }

    deleteButton.disabled = true
    setText("delete-status", "")

    try {
      const response = await fetch(`/api/delete/${encodeURIComponent(latestSecretReference.id)}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          delete_token: latestSecretReference.deleteToken,
        }),
      })

      const payload = await readJson(response)
      if (!response.ok) {
        throw new Error(payload.error || "Early deletion failed.")
      }

      latestSecretReference = null
      shareLink.value = ""
      result.hidden = true
      setText("create-result-status", "")
      setText("delete-status", "Secret deleted before first read.")
      setText("create-status", "The secret has been destroyed. Create a new link if needed.")
    } catch (error) {
      setText("delete-status", mapDeleteErrorMessage(error))
    } finally {
      deleteButton.disabled = false
    }
  })
}

function createTurnstileState() {
  return {
    ready: false,
    consumed: false,
    widgetId: null,
    rendered: false,
  }
}

function renderTurnstileWidget(config) {
  const widgetRoot = document.getElementById("turnstile-widget")
  const {
    siteKey,
    tokenInput,
    createButton,
    state,
  } = config

  if (!widgetRoot || !siteKey || !window.turnstile || typeof window.turnstile.render !== "function" || state.rendered) {
    return
  }

  state.widgetId = window.turnstile.render(widgetRoot, {
    sitekey: siteKey,
    theme: "light",
    responseField: false,
    callback(token) {
      updateTurnstileToken(state, createButton, tokenInput, token)
    },
    "expired-callback"() {
      state.ready = true
      state.consumed = false
      if (tokenInput) {
        tokenInput.value = ""
      }
      syncCreateButtonState(createButton, state)
      if (!latestSecretReference) {
        setText("create-status", "Anti-abuse verification expired. Complete it again before retrying.")
      }
    },
    "error-callback"() {
      state.ready = false
      state.consumed = false
      if (tokenInput) {
        tokenInput.value = ""
      }
      syncCreateButtonState(createButton, state)
      if (!latestSecretReference) {
        setText("create-status", "Anti-abuse verification failed to load. Reload the page and try again.")
      }
    },
  })

  state.ready = true
  state.rendered = true
  syncCreateButtonState(createButton, state)
}

function resetTurnstile(state) {
  if (!state || state.widgetId === null || !window.turnstile || typeof window.turnstile.reset !== "function") {
    return
  }

  const tokenInput = document.getElementById("turnstile-token")
  if (tokenInput) {
    tokenInput.value = ""
  }
  state.consumed = false
  window.turnstile.reset(state.widgetId)
}

function armTurnstileForNextSecret(state, button) {
  if (!state || !state.consumed) {
    return
  }

  resetTurnstile(state)
  syncCreateButtonState(button, state)
  setText("create-status", "Complete the anti-abuse verification before creating another secret.")
}

function updateTurnstileToken(state, button, tokenInput, token) {
  state.ready = true
  state.consumed = false
  if (tokenInput) {
    tokenInput.value = token
  }
  syncCreateButtonState(button, state)
}

function syncCreateButtonState(button, turnstileState) {
  if (!button || !turnstileState) {
    return
  }

  const tokenInput = document.getElementById("turnstile-token")
  const hasToken = tokenInput ? tokenInput.value.length > 0 : false
  button.disabled = !turnstileState.ready || !hasToken || turnstileState.consumed
}

async function bootReadPage(root) {
  const secretId = root.dataset.secretId
  const decryptButton = document.getElementById("decrypt-secret-button")
  const copyButton = document.getElementById("copy-secret-button")
  const secretOutput = document.getElementById("secret-output")

  decryptButton.addEventListener("click", async () => {
    const rawKey = getFragmentKey(window.location)

    if (copyButton) {
      copyButton.hidden = true
    }
    secretOutput.hidden = true
    secretOutput.textContent = ""
    setText("read-status", "")
    setText("read-copy-status", "")

    if (!rawKey) {
      setText("read-status", "Incomplete link: missing key.")
      return
    }

    decryptButton.disabled = true
    decryptButton.textContent = "Decrypting..."

    try {
      const keyBytes = decodeKeyFragment(rawKey)
      const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}`)
      const payload = await readJson(response)

      if (!response.ok) {
        throw new Error("Secret not found, expired, or already read.")
      }

      const plaintext = await decryptCiphertext(
        keyBytes,
        base64UrlToBytes(payload.nonce),
        base64UrlToBytes(payload.ciphertext),
      )

      clearFragmentFromLocation(history, window.location)
      secretOutput.hidden = false
      secretOutput.textContent = plaintext
      if (copyButton) {
        copyButton.hidden = false
      }
      setText("read-status", "Secret decrypted locally. The fragment has been removed from the URL.")
      decryptButton.disabled = true
      decryptButton.textContent = "Secret already read"
      return
    } catch (error) {
      setText("read-status", mapReadErrorMessage(error))
    }

    decryptButton.disabled = false
    decryptButton.textContent = "Decrypt secret"
  })

  if (copyButton) {
    copyButton.addEventListener("click", async () => {
      if (!secretOutput.textContent) {
        return
      }

      try {
        await copyText(secretOutput.textContent)
        setText("read-copy-status", "Secret copied.")
      } catch (_error) {
        setText("read-copy-status", "Automatic copy is unavailable, please copy the secret manually.")
      }
    })
  }
}

function updateSecretSize(plaintext, maxSecretBytes) {
  const currentBytes = getUtf8ByteLength(plaintext)
  const sizeNode = document.getElementById("secret-size")
  sizeNode.textContent = String(currentBytes)
  sizeNode.parentElement.classList.toggle("over-limit", currentBytes > maxSecretBytes)
}

function buildShareUrl(publicBaseUrl, secretId, keyFragment) {
  const normalizedBaseUrl = publicBaseUrl.endsWith("/")
    ? publicBaseUrl
    : `${publicBaseUrl}/`
  const url = new URL(`s/${secretId}`, normalizedBaseUrl)
  url.hash = keyFragment
  return url.toString()
}

function setText(id, value) {
  const node = document.getElementById(id)
  if (node) {
    node.textContent = value
  }
}

async function copyText(value) {
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    await navigator.clipboard.writeText(value)
    return
  }

  const helper = document.createElement("textarea")
  helper.value = value
  helper.setAttribute("readonly", "")
  helper.style.position = "absolute"
  helper.style.left = "-9999px"
  document.body.appendChild(helper)
  helper.select()

  try {
    const copied = document.execCommand("copy")
    if (!copied) {
      throw new Error("Copy command failed.")
    }
  } finally {
    helper.remove()
  }
}

function mapCreateErrorMessage(error) {
  const message = error && error.message ? error.message : ""

  if (message.includes("temporarily disabled")) {
    return "Secret creation is temporarily disabled."
  }

  if (message.includes("global active secret quota")) {
    return "The service has reached its active secret limit. Please try again later."
  }

  if (message.includes("global storage quota")) {
    return "The service has reached its storage limit. Please try again later."
  }

  if (message.includes("turnstile verification failed")) {
    return "Anti-abuse verification failed. Complete the challenge again and retry."
  }

  if (message.includes("turnstile verification is unavailable")) {
    return "Anti-abuse verification is temporarily unavailable. Please try again later."
  }

  if (message.includes("turnstile_token")) {
    return "Complete the anti-abuse verification before creating a secret."
  }

  if (message.includes("rate limit exceeded")) {
    return "Too many requests from this network. Please wait and try again."
  }

  return message || "Secret creation failed."
}

function mapReadErrorMessage(error) {
  const message = error && error.message ? error.message : ""

  if (message.includes("not found") || message.includes("expired") || message.includes("already read")) {
    return "Secret not found, expired, or already read."
  }

  if (message.includes("Invalid key length") || message.includes("DataError")) {
    return "Invalid or malformed key. Check the full link before trying again."
  }

  if (message.includes("decrypt") || message.includes("OperationError")) {
    return "Invalid key or corrupted data. Check the full link."
  }

  if (message.includes("rate limit exceeded")) {
    return "Too many read attempts from this network. Please wait and try again."
  }

  return message || "Unable to decrypt this secret."
}

function mapDeleteErrorMessage(error) {
  const message = error && error.message ? error.message : ""

  if (message.includes("not found")) {
    return "The secret is already unavailable."
  }

  return message || "Early deletion failed."
}

async function readJson(response) {
  try {
    return await response.json()
  } catch (_error) {
    return {}
  }
}

function bytesToBase64Url(bytes) {
  let binary = ""
  const chunkSize = 0x8000

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize)
    binary += String.fromCharCode(...chunk)
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
}

function base64UrlToBytes(value) {
  const padding = (4 - (value.length % 4)) % 4
  const base64 = `${value}${"=".repeat(padding)}`
    .replace(/-/g, "+")
    .replace(/_/g, "/")
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }

  return bytes
}

if (globalThis.__psstTestHooks) {
  Object.assign(globalThis.__psstTestHooks, {
    AES_GCM_NONCE_BYTES,
    armTurnstileForNextSecret,
    base64UrlToBytes,
    bootCreatePage,
    bootReadPage,
    buildShareUrl,
    bytesToBase64Url,
    clearFragmentFromLocation,
    createTurnstileState,
    decodeKeyFragment,
    decryptCiphertext,
    encryptPlaintext,
    getFragmentKey,
    getUtf8ByteLength,
    mapCreateErrorMessage,
    mapDeleteErrorMessage,
    mapReadErrorMessage,
    renderTurnstileWidget,
    resetTurnstile,
    syncCreateButtonState,
    updateSecretSize,
    updateTurnstileToken,
  })
}
