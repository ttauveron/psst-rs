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
      setText("create-status", "Erreur interne pendant le chiffrement local.")
    })
  }

  const readRoot = document.getElementById("read-app")
  if (readRoot) {
    bootReadPage(readRoot).catch((error) => {
      console.error(error)
      setText("read-status", "Impossible de dechiffrer ce secret.")
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
    setText("create-status", "La creation est temporairement desactivee.")
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
      setText("create-status", "Le secret ne doit pas etre vide.")
      return
    }

    if (plaintextBytes.length > maxSecretBytes) {
      setText(
        "create-status",
        `Le secret depasse la limite de ${maxSecretBytes} octets UTF-8.`,
      )
      return
    }

    createButton.disabled = true
    createButton.textContent = "Chiffrement..."

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
        throw new Error(payload.error || "La creation du secret a echoue.")
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
        "Lien genere. Le serveur ne connait pas la cle, et le secret ne pourra etre lu qu'une fois.",
      )
    } catch (error) {
      latestSecretReference = null
      setText("create-status", mapCreateErrorMessage(error))
    } finally {
      createButton.disabled = false
      createButton.textContent = "Chiffrer et creer le lien"
    }
  })

  copyButton.addEventListener("click", async () => {
    if (!shareLink.value) {
      return
    }

    try {
      await navigator.clipboard.writeText(shareLink.value)
      setText("copy-status", "Lien copie.")
    } catch (_error) {
      shareLink.select()
      setText("copy-status", "Copie automatique indisponible, copiez le lien manuellement.")
    }
  })

  deleteButton.addEventListener("click", async () => {
    if (!latestSecretReference) {
      setText("delete-status", "Aucun secret actif a supprimer.")
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
        throw new Error(payload.error || "La suppression anticipee a echoue.")
      }

      latestSecretReference = null
      shareLink.value = ""
      result.hidden = true
      setText("delete-status", "Secret supprime avant lecture.")
      setText("create-status", "Le secret a ete detruit. Il faut creer un nouveau lien si necessaire.")
    } catch (error) {
      setText("delete-status", mapDeleteErrorMessage(error))
    } finally {
      deleteButton.disabled = false
    }
  })
}

async function bootReadPage(root) {
  const rawKey = window.location.hash.slice(1)
  const secretId = root.dataset.secretId

  if (!rawKey) {
    setText("read-status", "Lien incomplet : cle manquante.")
    return
  }

  try {
    const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}`)
    const payload = await readJson(response)

    if (!response.ok) {
      throw new Error("Secret introuvable, expire ou deja lu.")
    }

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      base64UrlToBytes(rawKey),
      "AES-GCM",
      false,
      ["decrypt"],
    )

    const plaintextBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64UrlToBytes(payload.nonce),
      },
      cryptoKey,
      base64UrlToBytes(payload.ciphertext),
    )

    history.replaceState(null, "", `${window.location.pathname}${window.location.search}`)
    document.getElementById("secret-output").hidden = false
    document.getElementById("secret-output").textContent = textDecoder.decode(plaintextBuffer)
    setText("read-status", "Secret dechiffre localement. Le fragment a ete efface de l'URL.")
  } catch (error) {
    document.getElementById("secret-output").hidden = true
    document.getElementById("secret-output").textContent = ""
    setText("read-status", mapReadErrorMessage(error))
  }
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
    return "La creation est temporairement desactivee."
  }

  if (message.includes("global active secret quota")) {
    return "Le service a atteint sa limite de secrets actifs. Reessayez plus tard."
  }

  if (message.includes("global storage quota")) {
    return "Le service a atteint sa limite de stockage. Reessayez plus tard."
  }

  if (message.includes("turnstile_token")) {
    return "La verification anti-abus n'est pas encore active cote interface."
  }

  return message || "La creation du secret a echoue."
}

function mapReadErrorMessage(error) {
  const message = error && error.message ? error.message : ""

  if (message.includes("introuvable") || message.includes("expire") || message.includes("deja lu")) {
    return "Secret introuvable, expire ou deja lu."
  }

  if (message.includes("decrypt") || message.includes("dechiffrer") || message.includes("OperationError")) {
    return "Cle invalide ou donnees corrompues. Verifiez le lien complet."
  }

  return message || "Impossible de dechiffrer ce secret."
}

function mapDeleteErrorMessage(error) {
  const message = error && error.message ? error.message : ""

  if (message.includes("not found")) {
    return "Le secret est deja indisponible."
  }

  return message || "La suppression anticipee a echoue."
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
