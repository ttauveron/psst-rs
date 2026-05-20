import assert from "node:assert/strict"
import { webcrypto } from "node:crypto"
import fs from "node:fs"
import test from "node:test"
import vm from "node:vm"

const appSource = fs.readFileSync(new URL("../../static/app.js", import.meta.url), "utf8")

class FakeClassList {
  constructor() {
    this.classes = new Set()
  }

  toggle(name, force) {
    if (force) {
      this.classes.add(name)
      return true
    }

    this.classes.delete(name)
    return false
  }

  contains(name) {
    return this.classes.has(name)
  }
}

class FakeElement {
  constructor(id = "") {
    this.id = id
    this.value = ""
    this.textContent = ""
    this.hidden = false
    this.disabled = false
    this.dataset = {}
    this.listeners = new Map()
    this.parentElement = null
    this.classList = new FakeClassList()
    this.style = {}
    this.attributes = new Map()
  }

  addEventListener(type, handler) {
    this.listeners.set(type, handler)
  }

  async trigger(type) {
    const handler = this.listeners.get(type)
    assert.ok(handler, `expected listener for ${type}`)
    await handler({
      preventDefault() {},
    })
  }

  appendChild(_child) {}

  remove() {}

  scrollIntoView() {}

  select() {}

  setAttribute(name, value) {
    this.attributes.set(name, value)
  }
}

class FakeDocument {
  constructor() {
    this.elements = new Map()
    this.listeners = new Map()
    this.body = new FakeElement("body")
  }

  addEventListener(type, handler) {
    this.listeners.set(type, handler)
  }

  createElement(tagName) {
    return new FakeElement(tagName)
  }

  execCommand(_command) {
    return true
  }

  getElementById(id) {
    return this.elements.get(id) || null
  }

  register(id, element) {
    element.id = id
    this.elements.set(id, element)
    return element
  }
}

class FakeHistory {
  constructor(locationLike) {
    this.locationLike = locationLike
    this.calls = []
  }

  replaceState(state, title, url) {
    this.calls.push([state, title, url])
    const parsed = new URL(url, `https://example.test${this.locationLike.pathname}`)
    this.locationLike.pathname = parsed.pathname
    this.locationLike.search = parsed.search
    this.locationLike.hash = parsed.hash
  }
}

function loadApp({ fetchImpl } = {}) {
  const document = new FakeDocument()
  const locationLike = {
    hash: "",
    pathname: "/",
    search: "",
  }
  const history = new FakeHistory(locationLike)
  const testHooks = {}
  const navigator = {
    clipboard: {
      async writeText() {},
    },
  }

  const context = {
    URL,
    Uint8Array,
    TextEncoder,
    TextDecoder,
    Response,
    Request,
    Headers,
    console,
    crypto: webcrypto,
    navigator,
    document,
    history,
    location: locationLike,
    window: {
      location: locationLike,
      turnstile: undefined,
    },
    fetch: fetchImpl || (async () => new Response("{}")),
    setTimeout,
    clearTimeout,
    btoa(value) {
      return Buffer.from(value, "binary").toString("base64")
    },
    atob(value) {
      return Buffer.from(value, "base64").toString("binary")
    },
    __psstTestHooks: testHooks,
  }
  context.window.history = history
  context.window.navigator = navigator
  context.window.crypto = webcrypto
  context.globalThis = context

  vm.createContext(context)
  vm.runInContext(appSource, context, { filename: "static/app.js" })

  return {
    document,
    history,
    hooks: testHooks,
    locationLike,
  }
}

function setupReadPage(app, secretId = "secret-123") {
  const root = app.document.register("read-app", new FakeElement("read-app"))
  root.dataset.secretId = secretId
  app.document.register("decrypt-secret-button", new FakeElement("decrypt-secret-button"))
  const copyButton = app.document.register("copy-secret-button", new FakeElement("copy-secret-button"))
  copyButton.hidden = true
  const secretOutput = app.document.register("secret-output", new FakeElement("secret-output"))
  secretOutput.hidden = true
  app.document.register("read-status", new FakeElement("read-status"))
  app.document.register("read-copy-status", new FakeElement("read-copy-status"))
  return root
}

test("encryptPlaintext and decryptCiphertext round-trip a secret locally", async () => {
  const app = loadApp()
  const { hooks } = app

  const encrypted = await hooks.encryptPlaintext("héllo 🔐")
  const decrypted = await hooks.decryptCiphertext(
    encrypted.rawKey,
    encrypted.nonce,
    encrypted.ciphertext,
  )

  assert.equal(decrypted, "héllo 🔐")
  assert.equal(encrypted.rawKey.length, 32)
  assert.equal(encrypted.nonce.length, hooks.AES_GCM_NONCE_BYTES)
})

test("updateSecretSize counts UTF-8 bytes and toggles the over-limit class", () => {
  const app = loadApp()
  const metric = app.document.register("secret-size", new FakeElement("secret-size"))
  const metricParent = new FakeElement("metric-parent")
  metric.parentElement = metricParent

  app.hooks.updateSecretSize("🔐", 3)
  assert.equal(metric.textContent, "4")
  assert.equal(metricParent.classList.contains("over-limit"), true)

  app.hooks.updateSecretSize("ok", 3)
  assert.equal(metric.textContent, "2")
  assert.equal(metricParent.classList.contains("over-limit"), false)
})

test("bootReadPage reports a missing fragment key before doing any fetch", async () => {
  let fetchCount = 0
  const app = loadApp({
    fetchImpl: async () => {
      fetchCount += 1
      return new Response("{}")
    },
  })
  const root = setupReadPage(app)
  const decryptButton = app.document.getElementById("decrypt-secret-button")

  await app.hooks.bootReadPage(root)
  await decryptButton.trigger("click")

  assert.equal(fetchCount, 0)
  assert.equal(
    app.document.getElementById("read-status").textContent,
    "Incomplete link: missing key.",
  )
})

test("bootReadPage rejects malformed keys before consuming the secret", async () => {
  let fetchCount = 0
  const app = loadApp({
    fetchImpl: async () => {
      fetchCount += 1
      return new Response("{}")
    },
  })
  const root = setupReadPage(app)
  const decryptButton = app.document.getElementById("decrypt-secret-button")
  app.locationLike.hash = "#bad-key"

  await app.hooks.bootReadPage(root)
  await decryptButton.trigger("click")

  assert.equal(fetchCount, 0)
  assert.equal(
    app.document.getElementById("read-status").textContent,
    "Invalid or malformed key. Check the full link before trying again.",
  )
  assert.equal(decryptButton.disabled, false)
  assert.equal(decryptButton.textContent, "Decrypt secret")
})

test("bootReadPage decrypts the payload locally and removes the fragment from the URL", async () => {
  const plaintext = "top secret"
  const cryptoApp = loadApp()
  const encrypted = await cryptoApp.hooks.encryptPlaintext(plaintext)
  let fetchHeaders = null

  const app = loadApp({
    fetchImpl: async (_url, options) => {
      fetchHeaders = options.headers
      return new Response(
        JSON.stringify({
          ciphertext: cryptoApp.hooks.bytesToBase64Url(encrypted.ciphertext),
          nonce: cryptoApp.hooks.bytesToBase64Url(encrypted.nonce),
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
          },
        },
      )
    },
  })
  const root = setupReadPage(app, "read-secret")
  const decryptButton = app.document.getElementById("decrypt-secret-button")
  const copyButton = app.document.getElementById("copy-secret-button")
  const secretOutput = app.document.getElementById("secret-output")
  app.locationLike.pathname = "/s/read-secret"
  app.locationLike.search = "?utm=test"
  app.locationLike.hash = `#${cryptoApp.hooks.bytesToBase64Url(encrypted.rawKey)}`

  await app.hooks.bootReadPage(root)
  await decryptButton.trigger("click")

  assert.ok(fetchHeaders)
  assert.equal(
    fetchHeaders["X-Psst-Key-Digest"],
    await cryptoApp.hooks.computeKeyDigest(encrypted.rawKey),
  )
  assert.equal(app.history.calls.length, 1)
  assert.deepEqual(app.history.calls[0], [null, "", "/s/read-secret?utm=test"])
  assert.equal(app.locationLike.hash, "")
  assert.equal(secretOutput.hidden, false)
  assert.equal(secretOutput.textContent, plaintext)
  assert.equal(copyButton.hidden, false)
  assert.equal(
    app.document.getElementById("read-status").textContent,
    "Secret decrypted locally. The fragment has been removed from the URL.",
  )
  assert.equal(decryptButton.disabled, true)
  assert.equal(decryptButton.textContent, "Secret already read")
})

test("bootReadPage restores the button when the server rejects the key digest", async () => {
  const cryptoApp = loadApp()
  const encrypted = await cryptoApp.hooks.encryptPlaintext("top secret")
  const app = loadApp({
    fetchImpl: async () =>
      new Response(
        JSON.stringify({
          error: "invalid read key",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        },
      ),
  })
  const root = setupReadPage(app, "read-secret")
  const decryptButton = app.document.getElementById("decrypt-secret-button")
  app.locationLike.hash = `#${cryptoApp.hooks.bytesToBase64Url(encrypted.rawKey)}`

  await app.hooks.bootReadPage(root)
  await decryptButton.trigger("click")

  assert.equal(
    app.document.getElementById("read-status").textContent,
    "Invalid key or corrupted data. Check the full link.",
  )
  assert.equal(decryptButton.disabled, false)
  assert.equal(decryptButton.textContent, "Decrypt secret")
})
