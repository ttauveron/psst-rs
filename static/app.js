const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()
const AES_GCM_NONCE_BYTES = 12
const TURNSTILE_PLACEHOLDER_TOKEN = "pending-step-7"
let latestSecretReference = null

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

async function bootCreatePage(root) {
  const form = document.getElementById("create-form")
  const input = document.getElementById("secret-input")
  const ttlSelect = document.getElementById("ttl-select")
  const createButton = document.getElementById("create-button")
  const shareLink = document.getElementById("share-link")
  const result = document.getElementById("create-result")
  const copyButton = document.getElementById("copy-link-button")
  const deleteButton = document.getElementById("delete-secret-button")
  const maxSecretBytes = Number(root.dataset.maxSecretBytes)
  const enableCreate = root.dataset.enableCreate === "true"

  updateSecretSize(input.value, maxSecretBytes)
  input.addEventListener("input", () => {
    updateSecretSize(input.value, maxSecretBytes)
  })

  if (!enableCreate) {
    createButton.disabled = true
    ttlSelect.disabled = true
    input.disabled = true
    setText("create-status", "Secret creation is temporarily disabled.")
    return
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault()
    setText("create-status", "")
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

    createButton.disabled = true
    createButton.textContent = "Encrypting..."

    try {
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

      const response = await fetch("/api/create", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ciphertext: bytesToBase64Url(ciphertext),
          nonce: bytesToBase64Url(nonce),
          expires_in_seconds: Number(ttlSelect.value),
          turnstile_token: TURNSTILE_PLACEHOLDER_TOKEN,
        }),
      })

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
      setText(
        "create-status",
        "Link generated. The server does not know the key, and the secret can be read only once.",
      )
    } catch (error) {
      latestSecretReference = null
      setText("create-status", mapCreateErrorMessage(error))
    } finally {
      createButton.disabled = false
      createButton.textContent = "Encrypt and create link"
    }
  })

  copyButton.addEventListener("click", async () => {
    if (!shareLink.value) {
      return
    }

    try {
      await navigator.clipboard.writeText(shareLink.value)
      setText("copy-status", "Link copied.")
    } catch (_error) {
      shareLink.select()
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
      setText("delete-status", "Secret deleted before first read.")
      setText("create-status", "The secret has been destroyed. Create a new link if needed.")
    } catch (error) {
      setText("delete-status", mapDeleteErrorMessage(error))
    } finally {
      deleteButton.disabled = false
    }
  })
}

async function bootReadPage(root) {
  const secretId = root.dataset.secretId
  const decryptButton = document.getElementById("decrypt-secret-button")
  const secretOutput = document.getElementById("secret-output")

  decryptButton.addEventListener("click", async () => {
    const rawKey = window.location.hash.slice(1)

    secretOutput.hidden = true
    secretOutput.textContent = ""
    setText("read-status", "")

    if (!rawKey) {
      setText("read-status", "Incomplete link: missing key.")
      return
    }

    decryptButton.disabled = true
    decryptButton.textContent = "Decrypting..."

    try {
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        base64UrlToBytes(rawKey),
        "AES-GCM",
        false,
        ["decrypt"],
      )

      const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}`)
      const payload = await readJson(response)

      if (!response.ok) {
        throw new Error("Secret not found, expired, or already read.")
      }

      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: base64UrlToBytes(payload.nonce),
        },
        cryptoKey,
        base64UrlToBytes(payload.ciphertext),
      )

      history.replaceState(null, "", `${window.location.pathname}${window.location.search}`)
      secretOutput.hidden = false
      secretOutput.textContent = textDecoder.decode(plaintextBuffer)
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
}

function updateSecretSize(plaintext, maxSecretBytes) {
  const currentBytes = textEncoder.encode(plaintext).length
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

  if (message.includes("turnstile_token")) {
    return "The anti-abuse verification is not wired into the UI yet."
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
