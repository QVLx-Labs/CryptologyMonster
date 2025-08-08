/*
Cryptology Monster

$t@$h, QVLx Labs
*/

document.addEventListener("DOMContentLoaded", () => {
  const container = document.getElementById("toolContainer");
  const select = document.getElementById("toolSelect");

  const tools = {
    passwordGen: () => {
      container.innerHTML = `
        <label><b>Password length: </b>
          <input type="number" id="pwLength" min="8" max="128" value="32">
        </label>
        <br>
    
        <div class="checkbox-wrapper">
          <label class="checkbox-label">
            <input type="checkbox" id="pwDeterministic">
            Deterministic (seeded) mode
          </label>
        </div>
    
        <div id="pwDeterministicFields" style="display:none;">
          <input type="text" id="pwSeed" placeholder="Seed phrase (memorable sentence)">
          <input type="text" id="pwSite" placeholder="Site tag / domain (required)">
          <input type="number" id="pwCounter" placeholder="Counter (default 1)" min="1" value="1" style="width: 140px;">
        </div>
    
        <br><button onclick="generatePassword()">Generate</button>`;
    },
    entropy: () => {
      container.innerHTML = `
        <textarea id="entropyInput" placeholder="Enter your text here..."></textarea><br>
        <button onclick="calculateEntropy()">Calculate Entropy</button>`;
    },
    encrypt: () => {
      container.innerHTML = `
        <textarea id="plainText" placeholder="Enter plaintext here..."></textarea><br>
        <div class="checkbox-wrapper">
          <label class="checkbox-label">
            <input type="checkbox" id="usePassword">
            Use password-based key (PBKDF2)
          </label>
        </div>
        <div id="pbkdf2Inputs" style="display:none;">
          <input type="password" id="passwordInput" placeholder="Enter password"><br>
          <input type="text" id="saltInput" placeholder="Optional salt (hex)"><br>
        </div>
        <button onclick="encryptText()">Encrypt and Download</button>`;
    },
    decrypt: () => {
      container.innerHTML = `
        <label><b>Cyphertext (.bin):</b></label>
        <input type="file" id="encryptedFile"><br>
        <label><b>Key (.bin):</b></label>
        <input type="file" id="keyFile">
    
        <div class="checkbox-wrapper">
          <label class="checkbox-label">
            <input type="checkbox" id="usePassword">
            Use password-based key (PBKDF2)
          </label>
        </div>
    
        <div id="pbkdf2Inputs" style="display:none;">
          <input type="password" id="passwordInput" placeholder="Enter password"><br>
        </div>
    
        <textarea id="decryptedText" placeholder="Decrypted output will appear here..."></textarea><br>
        <button onclick="decryptFile()">Decrypt</button>
      `;
    },
    passwordStrength: () => {
      container.innerHTML = `
        <input type="text" id="pwInput" placeholder="Enter password"><br>
        <button onclick="checkStrength()">Check</button>`;
    },
    base64: () => {
      container.innerHTML = `
        <textarea id="b64Input" placeholder="Enter text here..."></textarea><br>
        <div class="button-row">
          <button onclick="b64Encode()">Encode</button>
          <button onclick="b64Decode()">Decode</button>
        </div>`;
    },
    base32: () => {
      container.innerHTML = `
        <textarea id="b32Input" placeholder="Enter text here..."></textarea><br>
        <div class="button-row">
          <button onclick="b32Encode()">Encode</button>
          <button onclick="b32Decode()">Decode</button>
        </div>`;
    },
    hash: () => {
      container.innerHTML = `
        <label><b>Algorithm:</b>
          <select id="hashAlgo">
            <option value="SHA-256">SHA-256</option>
            <option value="SHA-384">SHA-384</option>
            <option value="SHA-512">SHA-512</option>
          </select>
        </label><br>
    
        <textarea id="hashInput" placeholder="Enter text to hash..."></textarea><br>
        <div class="button-row">
          <button onclick="hashText()">Hash Text</button>
        </div>
    
        <hr>
    
        <label><b>File:</b> <input type="file" id="hashFile"></label><br>
        <div class="button-row">
          <button onclick="hashFile()">Hash File</button>
        </div>`;
    },
    rsaKeypair: () => {
      container.innerHTML = `
        <label><b>RSA Key Size:</b>
          <select id="rsaBits">
            <option value="2048">2048</option>
            <option value="3072">3072</option>
            <option value="4096">4096</option>
          </select>
        </label><br>
        <button onclick="generateRSA()">Generate RSA Keypair</button>`;
    },
    ed25519Keypair: () => {
      container.innerHTML = `
        <p><b>Ed25519 keypair is fixed at 256-bit.</b></p>
        <button onclick="generateEd25519()">Generate Ed25519 Keypair</button>`;
    },
    compareStrings: () => {
      container.innerHTML = `
        <textarea id="cmpStr1" placeholder="Enter first string..."></textarea><br>
        <textarea id="cmpStr2" placeholder="Enter second string..."></textarea><br>
        <button onclick="compareStrings()">Compare</button>`;
    },
    pgp: () => {
      container.innerHTML = `
        <label><b>Name:</b> <input type="text" id="pgpName" placeholder="Alice Example"></label><br>
        <label><b>Email:</b> <input type="email" id="pgpEmail" placeholder="alice@example.com"></label><br>
        <label><b>Comment (optional):</b> <input type="text" id="pgpComment" placeholder="QVLx Labs"></label><br>
    
        <div class="checkbox-wrapper">
          <label class="checkbox-label">
            <input type="checkbox" id="pgpUsePass" checked>
            Protect private key with a passphrase
          </label>
        </div>
        <input type="password" id="pgpPass" placeholder="Passphrase (recommended)"><br>
    
        <label><b>Algorithm:</b>
          <select id="pgpAlgo">
            <option value="ed25519">Ed25519 (recommended)</option>
            <option value="rsa-2048">RSA 2048</option>
            <option value="rsa-3072">RSA 3072</option>
            <option value="rsa-4096">RSA 4096</option>
          </select>
        </label><br>
    
        <label><b>Expiration (days, optional):</b>
          <input type="number" id="pgpExpiryDays" min="0" placeholder="e.g., 365 (0 = no expiry)">
        </label><br>
    
        <button onclick="generatePGP()">Generate PGP Keypair</button>
      `;
    },
    hmac: () => {
      container.innerHTML = `
        <label><b>Algorithm:</b>
          <select id="hmacAlgo">
            <option value="SHA-256">HMAC-SHA-256</option>
            <option value="SHA-384">HMAC-SHA-384</option>
            <option value="SHA-512">HMAC-SHA-512</option>
          </select>
        </label><br>
        <textarea id="hmacMsg" placeholder="Message to sign..."></textarea><br>
        <input type="text" id="hmacKey" placeholder="Secret key (text or hex)">
        <div class="checkbox-wrapper">
          <label class="checkbox-label"><input type="checkbox" id="hmacKeyHex"> Key is hex</label>
        </div>
        <div class="button-row">
          <button onclick="hmacSign()">Sign</button>
          <button onclick="hmacVerify()">Verify</button>
        </div>
        <input type="text" id="hmacSig" placeholder="Signature to verify (hex or base64url)">
        <div class="checkbox-wrapper">
          <label class="checkbox-label"><input type="checkbox" id="hmacSigHex"> Signature is hex</label>
        </div>
      `;
    },
    
    jwt: () => {
      container.innerHTML = `
        <textarea id="jwtInput" placeholder="Paste JWT here (header.payload.signature)"></textarea><br>
        <div class="button-row">
          <button onclick="decodeJWT()">Decode</button>
        </div>
        <hr>
        <p><b>Optional HMAC (HS256/384/512) verification</b></p>
        <input type="text" id="jwtSecret" placeholder="Shared secret (text or hex)">
        <div class="checkbox-wrapper">
          <label class="checkbox-label"><input type="checkbox" id="jwtSecretHex"> Secret is hex</label>
        </div>
        <div class="button-row">
          <button onclick="verifyJWT()">Verify Signature (HS*)</button>
        </div>
      `;
    },
    
    fileCrypto: () => {
      container.innerHTML = `
        <p><b>Encrypt File (AES-GCM)</b></p>
        <input type="file" id="fcFile"><br>
        <div class="checkbox-wrapper">
          <label class="checkbox-label"><input type="checkbox" id="fcUsePassword"> Use password (PBKDF2)</label>
        </div>
        <input type="password" id="fcPassword" placeholder="Password (if checked)" style="display:none;">
        <div class="button-row">
          <button onclick="encryptFileAESGCM()">Encrypt & Download</button>
        </div>
        <hr>
        <p><b>Decrypt File</b></p>
        <input type="file" id="fcEncFile"><br>
        <div class="checkbox-wrapper">
          <label class="checkbox-label"><input type="checkbox" id="fcUsePasswordDec"> Password mode</label>
        </div>
        <input type="password" id="fcPasswordDec" placeholder="Password (if password mode)" style="display:none;">
        <input type="file" id="fcKeyFile" placeholder="key.bin (raw 32 bytes)">
        <div class="button-row">
          <button onclick="decryptFileAESGCM()">Decrypt</button>
        </div>
      `;
    },
    
    pgpOps: () => {
      container.innerHTML = `
        <p><b>PGP Encrypt</b></p>
        <textarea id="pgpPlain" placeholder="Message to encrypt..."></textarea><br>
        <textarea id="pgpPub" placeholder="Recipient public key (ASCII-armored)"></textarea><br>
        <button onclick="pgpEncrypt()">Encrypt</button>
        <hr>
        <p><b>PGP Decrypt</b></p>
        <textarea id="pgpCipher" placeholder="Armored PGP message"></textarea><br>
        <textarea id="pgpPriv" placeholder="Your private key (ASCII-armored)"></textarea><br>
        <input type="password" id="pgpPrivPass" placeholder="Private key passphrase (if any)"><br>
        <button onclick="pgpDecrypt()">Decrypt</button>
        <hr>
        <p><b>PGP Sign / Verify</b></p>
        <textarea id="pgpSignMsg" placeholder="Message to sign..."></textarea><br>
        <textarea id="pgpSignPriv" placeholder="Signing private key (ASCII-armored)"></textarea><br>
        <input type="password" id="pgpSignPass" placeholder="Passphrase (if any)"><br>
        <button onclick="pgpSign()">Sign (cleartext)</button>
        <hr>
        <textarea id="pgpVerifyMsg" placeholder="Signed message (cleartext armored)"></textarea><br>
        <textarea id="pgpVerifyPub" placeholder="Signer public key (ASCII-armored)"></textarea><br>
        <button onclick="pgpVerify()">Verify</button>
      `;
    },
    
    qr: () => {
      container.innerHTML = `
        <p><b>Create QR</b></p>
        <textarea id="qrText" placeholder="Text to encode..."></textarea><br>
        <button onclick="makeQR()">Generate QR</button>
        <div id="qrOut" style="margin-top:8px;"></div>
        <hr>
        <p><b>Decode QR</b></p>
        <input type="file" id="qrImage" accept="image/*"><br>
        <button onclick="readQR()">Decode from Image</button>
      `;
    }
  };

  select.addEventListener("change", () => tools[select.value]());
  tools[select.value](); // Load default
  
    // Show/hide PBKDF2 password + salt fields dynamically
  container.addEventListener("change", function(e) {
    if (e.target.id === "usePassword") {
      const section = document.getElementById("pbkdf2Inputs");
      const keyFile = document.getElementById("keyFile");
      
      if (section) section.style.display = e.target.checked ? "block" : "none";
      if (keyFile) keyFile.disabled = e.target.checked;
    }
  });
  
  // toggle deterministic password fields
  container.addEventListener("change", (e) => {
    if (e.target.id === "pwDeterministic") {
      const box = document.getElementById("pwDeterministicFields");
      if (box) box.style.display = e.target.checked ? "block" : "none";
    }
  });
  
  container.addEventListener("change", (e) => {
    if (e.target.id === "fcUsePassword") {
      document.getElementById("fcPassword").style.display = e.target.checked ? "block" : "none";
    }
    if (e.target.id === "fcUsePasswordDec") {
      const on = e.target.checked;
      document.getElementById("fcPasswordDec").style.display = on ? "block" : "none";
      document.getElementById("fcKeyFile").style.display = on ? "none" : "block";
    }
  });
  
  const logo = document.getElementById("monsterLogo");

  const wrapper = document.getElementById("logoWrapper");

  function showLogoWithAnimation() {
    wrapper.classList.add("loaded");
    logo.style.animation = "swivel 1s ease-in-out";
    setTimeout(() => (logo.style.animation = ""), 900);
  }

  if (logo.complete && logo.naturalWidth > 1) {
    // Cached image
    requestAnimationFrame(() => showLogoWithAnimation());
  } else {
    // Fresh load
    logo.addEventListener("load", () => requestAnimationFrame(() => showLogoWithAnimation()));
  }

});

function showModal(title, resultText) {
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalResultText").textContent = resultText;
  document.getElementById("resultModal").style.display = "block";
}

async function hmacSign() {
  const msg = document.getElementById("hmacMsg").value;
  const keyStr = document.getElementById("hmacKey").value.trim();
  const algo = document.getElementById("hmacAlgo").value;
  const keyHex = document.getElementById("hmacKeyHex").checked;

  if (!keyStr) { alert("Enter a secret key."); return; }

  const keyBytes = keyHex ? hexToBytes(keyStr) : new TextEncoder().encode(keyStr);
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: algo }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(msg));
  const hex = bytesToHex(new Uint8Array(sig));
  const b64u = base64urlEncode(new Uint8Array(sig));
  showModal("HMAC", `Hex:\n${hex}\n\nBase64url:\n${b64u}`);
}

async function hmacVerify() {
  const msg = document.getElementById("hmacMsg").value;
  const keyStr = document.getElementById("hmacKey").value.trim();
  const algo = document.getElementById("hmacAlgo").value;
  const keyHex = document.getElementById("hmacKeyHex").checked;
  const sigStr = document.getElementById("hmacSig").value.trim();
  const sigHex = document.getElementById("hmacSigHex").checked;

  if (!keyStr || !sigStr) { alert("Enter secret and signature."); return; }

  const keyBytes = keyHex ? hexToBytes(keyStr) : new TextEncoder().encode(keyStr);
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: algo }, false, ["sign", "verify"]
  );
  const sigBytes = sigHex ? hexToBytes(sigStr) : base64urlDecode(sigStr);
  const ok = await crypto.subtle.verify("HMAC", cryptoKey, sigBytes, new TextEncoder().encode(msg));
  showModal("HMAC Verify", ok ? "✅ Signature matches" : "❌ Signature does NOT match");
}

function decodeJWT() {
  try {
    const jwt = document.getElementById("jwtInput").value.trim();
    const [h, p, s] = jwt.split(".");
    if (!h || !p) throw new Error("Malformed JWT");
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(h)));
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(p)));
    showModal("JWT Decoded", `Header:\n${JSON.stringify(header, null, 2)}\n\nPayload:\n${JSON.stringify(payload, null, 2)}\n\nSignature:\n${s || "(none)"}`);
  } catch (e) {
    alert("Failed to decode JWT"); console.error(e);
  }
}

async function verifyJWT() {
  try {
    const jwt = document.getElementById("jwtInput").value.trim();
    const secretStr = document.getElementById("jwtSecret").value.trim();
    const secretHex = document.getElementById("jwtSecretHex").checked;
    const [h, p, s] = jwt.split(".");
    if (!h || !p || !s) throw new Error("Malformed JWT");
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(h)));

    const alg = header.alg;
    const algoMap = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" };
    if (!algoMap[alg]) { showModal("JWT Verify", `Unsupported alg for HMAC: ${alg}`); return; }

    const keyBytes = secretHex ? hexToBytes(secretStr) : new TextEncoder().encode(secretStr);
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: algoMap[alg] }, false, ["sign", "verify"]);

    const data = new TextEncoder().encode(`${h}.${p}`);
    const sig = base64urlDecode(s);
    const ok = await crypto.subtle.verify("HMAC", key, sig, data);
    showModal("JWT Verify", ok ? "✅ HS* signature is VALID" : "❌ Invalid signature");
  } catch (e) {
    alert("Verification failed"); console.error(e);
  }
}

async function encryptFileAESGCM() {
  const f = document.getElementById("fcFile")?.files?.[0];
  if (!f) { alert("Choose a file."); return; }
  const usePw = document.getElementById("fcUsePassword").checked;
  const pw = document.getElementById("fcPassword").value;
  if (usePw && !pw) { alert("Enter password."); return; }

  const data = new Uint8Array(await f.arrayBuffer());
  const iv = crypto.getRandomValues(new Uint8Array(12));

  let key, salt, keyRaw = null;

  if (usePw) {
    salt = crypto.getRandomValues(new Uint8Array(16));
    const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), { name: "PBKDF2" }, false, ["deriveKey"]);
    key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
      baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    );
  } else {
    key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    keyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  }

  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data));

  let out;
  let name = f.name + ".enc";
  if (usePw) {
    out = new Uint8Array(16 + 12 + ct.length);
    out.set(salt, 0); out.set(iv, 16); out.set(ct, 28);
  } else {
    out = new Uint8Array(12 + ct.length);
    out.set(iv, 0); out.set(ct, 12);
    download("key.bin", keyRaw);
  }
  download(name, out);
  showModal("File Encrypted", `File: ${f.name}\nMode: ${usePw ? "Password (PBKDF2-SHA256, 200k iters)" : "Raw key (key.bin downloaded)"}\nIV: ${bytesToHex(iv)}`);
}

async function decryptFileAESGCM() {
  const f = document.getElementById("fcEncFile")?.files?.[0];
  if (!f) { alert("Choose encrypted file."); return; }
  const usePw = document.getElementById("fcUsePasswordDec").checked;
  const data = new Uint8Array(await f.arrayBuffer());
  let key, iv, offset;

  try {
    if (usePw) {
      const pw = document.getElementById("fcPasswordDec").value;
      if (!pw) { alert("Enter password."); return; }
      const salt = data.slice(0, 16);
      iv = data.slice(16, 28);
      const ct = data.slice(28);
      const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), { name: "PBKDF2" }, false, ["deriveKey"]);
      key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
        baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
      );
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
      download(stripEncExt(f.name), pt);
      showModal("File Decrypted", `OK (password mode)\nIV: ${bytesToHex(iv)}`);
    } else {
      iv = data.slice(0, 12);
      const ct = data.slice(12);
      const keyFile = document.getElementById("fcKeyFile")?.files?.[0];
      if (!keyFile) { alert("Select key.bin"); return; }
      const keyRaw = await keyFile.arrayBuffer();
      key = await crypto.subtle.importKey("raw", keyRaw, { name: "AES-GCM" }, false, ["decrypt"]);
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
      download(stripEncExt(f.name), pt);
      showModal("File Decrypted", `OK (raw key mode)\nIV: ${bytesToHex(iv)}`);
    }
  } catch (e) {
    alert("Decryption failed."); console.error(e);
  }
}

function stripEncExt(name) {
  return name.endsWith(".enc") ? name.slice(0, -4) : ("decrypted_" + name);
}


async function generatePassword() {
  const len = Math.max(8, Math.min(128, parseInt(document.getElementById("pwLength").value || "32", 10)));
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}<>?";
  const det = document.getElementById("pwDeterministic")?.checked;

  if (!det) {
    // existing random mode
    const array = new Uint32Array(len);
    crypto.getRandomValues(array);
    const pw = Array.from(array, x => charset[x % charset.length]).join("");
    showModal(`Generated Password (${len} chars)`, pw);
    return;
  }

  // deterministic (seeded) mode
  const seed = (document.getElementById("pwSeed")?.value || "").trim();
  const site = (document.getElementById("pwSite")?.value || "").trim();
  const counter = Math.max(1, parseInt(document.getElementById("pwCounter")?.value || "1", 10));

  if (!seed || !site) {
    alert("Seed phrase and Site tag are required for deterministic mode.");
    return;
  }

  const pw = await deriveDeterministicPassword({
    seed,
    site,
    counter,
    length: len,
    charset,
    iterations: 200000, // tune if you want slower/faster
    version: "v1"
  });

  showModal(`Deterministic Password (${len} chars)`, pw);
}

async function deriveDeterministicPassword({ seed, site, counter, length, charset, iterations = 200000, version = "v1" }) {
  const enc = new TextEncoder();

  // Namespaced salt so it’s stable & unambiguous across sites and future versions
  const salt = enc.encode(`CryptologyMonster|${version}|${site}|${counter}`);

  // Import seed as PBKDF2 key
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(seed),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  // We need enough entropy to fill 'length' characters with unbiased sampling.
  // Request 4× the bytes we think we need; if it’s still not enough due to rejection,
  // we’ll re-derive with counter+1 and append (deterministic, because inputs are fixed).
  let bytes = await pbkdf2Bits(baseKey, salt, iterations, length * 4);

  // Unbiased map bytes → charset via rejection sampling
  let out = mapBytesToCharset(bytes, charset, length);

  // If we somehow didn’t collect enough characters, extend deterministically
  let bump = counter;
  while (out.length < length) {
    bump += 1;
    const extraSalt = enc.encode(`CryptologyMonster|${version}|${site}|${bump}`);
    const more = await pbkdf2Bits(baseKey, extraSalt, iterations, length * 2);
    bytes = concatUint8(bytes, more);
    out = mapBytesToCharset(bytes, charset, length);
  }

  return out;
}

async function pbkdf2Bits(baseKey, salt, iterations, outBytes) {
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    baseKey,
    outBytes * 8
  );
  return new Uint8Array(bits);
}

function mapBytesToCharset(bytes, charset, targetLen) {
  const n = charset.length;
  const max = 256 - (256 % n); // rejection threshold to avoid modulo bias
  let out = "";
  for (let i = 0; i < bytes.length && out.length < targetLen; i++) {
    const b = bytes[i];
    if (b < max) {
      out += charset[b % n];
    }
  }
  return out;
}

function concatUint8(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// Lazy-load openpgp.js once (UMD build exposes window.openpgp)
// Pin a version you trust; 5.x recommended.
let __openpgpPromise;
function loadOpenPGP() {
  if (window.openpgp) return Promise.resolve(window.openpgp);
  if (__openpgpPromise) return __openpgpPromise;
  __openpgpPromise = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://unpkg.com/openpgp@5.11.1/dist/openpgp.min.js";
    s.async = true;
    s.onload = () => resolve(window.openpgp);
    s.onerror = () => reject(new Error("Failed to load openpgp.js"));
    document.head.appendChild(s);
  });
  return __openpgpPromise;
}

async function pgpEncrypt() {
  try {
    const openpgp = await loadOpenPGP();
    const text = document.getElementById("pgpPlain").value;
    const pubArmored = document.getElementById("pgpPub").value;
    const pub = await openpgp.readKey({ armoredKey: pubArmored });
    const msg = await openpgp.createMessage({ text });
    const cipher = await openpgp.encrypt({ message: msg, encryptionKeys: pub });
    showModal("PGP Encrypt", cipher);
  } catch (e) { alert("Encrypt failed"); console.error(e); }
}

async function pgpDecrypt() {
  try {
    const openpgp = await loadOpenPGP();
    const armored = document.getElementById("pgpCipher").value;
    const privArmored = document.getElementById("pgpPriv").value;
    const pass = document.getElementById("pgpPrivPass").value;
    const priv = await openpgp.readPrivateKey({ armoredKey: privArmored });
    const unlocked = pass ? await openpgp.decryptKey({ privateKey: priv, passphrase: pass }) : priv;
    const msg = await openpgp.readMessage({ armoredMessage: armored });
    const { data } = await openpgp.decrypt({ message: msg, decryptionKeys: unlocked });
    showModal("PGP Decrypt", data);
  } catch (e) { alert("Decrypt failed"); console.error(e); }
}

async function pgpSign() {
  try {
    const openpgp = await loadOpenPGP();
    const text = document.getElementById("pgpSignMsg").value;
    const privArmored = document.getElementById("pgpSignPriv").value;
    const pass = document.getElementById("pgpSignPass").value;

    const priv = await openpgp.readPrivateKey({ armoredKey: privArmored });
    const unlocked = pass ? await openpgp.decryptKey({ privateKey: priv, passphrase: pass }) : priv;

    const msg = await openpgp.createCleartextMessage({ text }); // <-- cleartext
    const signed = await openpgp.sign({ message: msg, signingKeys: unlocked }); // armored cleartext
    showModal("PGP Signed (cleartext)", signed);
  } catch (e) { alert("Sign failed"); console.error(e); }
}

async function pgpVerify() {
  try {
    const openpgp = await loadOpenPGP();
    const signed = document.getElementById("pgpVerifyMsg").value;
    const pubArmored = document.getElementById("pgpVerifyPub").value;
    const pub = await openpgp.readKey({ armoredKey: pubArmored });
    const msg = await openpgp.readCleartextMessage({ cleartextMessage: signed });
    const res = await openpgp.verify({ message: msg, verificationKeys: pub });
    const ok = await res.signatures[0].verified;
    showModal("PGP Verify", ok ? "✅ Signature VALID" : "❌ Signature INVALID");
  } catch (e) { alert("Verify failed"); console.error(e); }
}

async function generatePGP() {
  const name = document.getElementById("pgpName").value.trim();
  const email = document.getElementById("pgpEmail").value.trim();
  const comment = document.getElementById("pgpComment").value.trim();
  const usePass = document.getElementById("pgpUsePass").checked;
  const passphrase = document.getElementById("pgpPass").value;
  const algo = document.getElementById("pgpAlgo").value;
  const expiryDaysRaw = document.getElementById("pgpExpiryDays").value.trim();

  if (!name || !email) {
    alert("Name and Email are required for the PGP user ID.");
    return;
  }
  if (usePass && !passphrase) {
    alert("Enter a passphrase or uncheck the passphrase box.");
    return;
  }

  const openpgp = await loadOpenPGP();

  // Build user IDs
  const userIDs = [{ name, email, ...(comment ? { comment } : {}) }];

  // Expiry handling (seconds since creation); 0/empty = no expiry
  let keyExpirationTime = undefined;
  if (expiryDaysRaw) {
    const days = parseInt(expiryDaysRaw, 10);
    if (!Number.isNaN(days) && days > 0) keyExpirationTime = days * 24 * 60 * 60;
  }

  // Map algo selection
  let genOpts;
  if (algo.startsWith("rsa")) {
    const bits = parseInt(algo.split("-")[1], 10);
    genOpts = {
      type: "rsa",
      rsaBits: bits,
      userIDs,
      passphrase: usePass ? passphrase : undefined,
      format: "armored",
      keyExpirationTime
    };
  } else {
    // ed25519 path
    genOpts = {
      type: "ecc",
      curve: "ed25519", // primary signing/auth key
      userIDs,
      passphrase: usePass ? passphrase : undefined,
      format: "armored",
      keyExpirationTime,
      // add an encryption subkey so the key can encrypt, too
      subkeys: [{ curve: "curve25519" }] // X25519 (a.k.a. Curve25519) for ECDH
    };
  }

  // Generate
  let privateKey, publicKey, revocationCertificate;
  try {
    ({ privateKey, publicKey, revocationCertificate } = await openpgp.generateKey(genOpts));
  } catch (e) {
    alert("PGP key generation failed. See console for details.");
    console.error("Error generating keypair:", e);
    return;
  }

  // Fingerprint (derived from public key)
  const keyObj = await openpgp.readKey({ armoredKey: publicKey });
  const fp = keyObj.getFingerprint().toUpperCase().match(/.{1,4}/g).join(" ");

  // Downloads
  download("pgp_public.asc", publicKey);
  download("pgp_private.asc", privateKey);
  if (revocationCertificate) {
    download("pgp_revocation.asc", revocationCertificate);
  }

  // Info modal
  const algoLabel = algo === "ed25519" ? "Ed25519" : `RSA ${genOpts.rsaBits}`;
  const created = new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  const expiryText = keyExpirationTime ? `${Math.round(keyExpirationTime / 86400)} days` : "No expiry";
  showModal(
    "PGP Key Generated",
    `User ID: ${name} <${email}>${comment ? ` (${comment})` : ""}\n` +
    `Algorithm: ${algoLabel}\n` +
    `Created: ${created}\n` +
    `Expires: ${expiryText}\n` +
    `Fingerprint:\n${fp}\n\n` +
    `Files downloaded:\n- pgp_public.asc\n- pgp_private.asc\n${revocationCertificate ? "- pgp_revocation.asc\n" : ""}`
  );
}

let __qrcodePromise, __jsqrPromise;
function loadQRCodeLib() {
  if (window.QRCode) return Promise.resolve();
  if (__qrcodePromise) return __qrcodePromise;
  __qrcodePromise = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://unpkg.com/qrcodejs@1.0.0/qrcode.min.js";
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("Failed to load qrcodejs"));
    document.head.appendChild(s);
  });
  return __qrcodePromise;
}
function loadJsQR() {
  if (window.jsQR) return Promise.resolve();
  if (__jsqrPromise) return __jsqrPromise;
  __jsqrPromise = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://unpkg.com/jsqr@1.4.0/dist/jsQR.js";
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("Failed to load jsQR"));
    document.head.appendChild(s);
  });
  return __jsqrPromise;
}

async function makeQR() {
  await loadQRCodeLib();
  const text = document.getElementById("qrText").value.trim();
  if (!text) { alert("Enter text to encode."); return; }

  // Generate QR off-DOM
  const holder = document.createElement("div");
  new QRCode(holder, { text, width: 256, height: 256, correctLevel: QRCode.CorrectLevel.M });

  let canvas = holder.querySelector("canvas");
  if (!canvas) {
    const img = holder.querySelector("img");
    if (!img) { alert("Failed to create QR."); return; }
    canvas = document.createElement("canvas");
    canvas.width = img.width || 256;
    canvas.height = img.height || 256;
    canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height);
  }

  const blob = await new Promise(res => canvas.toBlob(res, "image/png"));

  // Open modal
  showModal("QR Code", "");
  const box = document.getElementById("modalResultText");
  box.textContent = "";

  // Layout
  const qrWrap = document.createElement("div");
  qrWrap.style.display = "flex";
  qrWrap.style.flexDirection = "column";
  qrWrap.style.alignItems = "center";
  qrWrap.style.gap = "8px";

  // Show QR
  const shownCanvas = document.createElement("canvas");
  shownCanvas.width = canvas.width;
  shownCanvas.height = canvas.height;
  shownCanvas.getContext("2d").drawImage(canvas, 0, 0);

  // Buttons
  const buttons = document.createElement("div");
  buttons.style.display = "flex";
  buttons.style.gap = "8px";

  const downloadBtn = document.createElement("button");
  downloadBtn.textContent = "Download PNG";
  downloadBtn.onclick = async () => {
    download("qrcode.png", new Uint8Array(await blob.arrayBuffer()));
  };

  const copyBtn = document.createElement("button");
  copyBtn.textContent = "Copy to Clipboard";
  copyBtn.onclick = async () => {
    try {
      await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
      copyBtn.textContent = "Copied ✔️";
      setTimeout(() => (copyBtn.textContent = "Copy to Clipboard"), 1500);
    } catch (e) {
      alert("Clipboard image copy not supported in this browser/context.");
      console.error(e);
    }
  };

  buttons.appendChild(downloadBtn);
  buttons.appendChild(copyBtn);

  qrWrap.appendChild(shownCanvas);
  qrWrap.appendChild(buttons);
  box.appendChild(qrWrap);
}

async function readQR() {
  await loadJsQR();
  const f = document.getElementById("qrImage")?.files?.[0];
  if (!f) { alert("Choose an image containing a QR"); return; }
  const img = new Image();
  img.onload = () => {
    const c = document.createElement("canvas");
    c.width = img.width; c.height = img.height;
    const ctx = c.getContext("2d");
    ctx.drawImage(img, 0, 0);
    const imgData = ctx.getImageData(0, 0, c.width, c.height);
    const res = jsQR(imgData.data, c.width, c.height);
    showModal("QR Decode", res ? res.data : "No QR code found.");
  };
  img.onerror = () => alert("Failed to load image");
  img.src = URL.createObjectURL(f);
}

function bytesToHex(u8) { return [...u8].map(b => b.toString(16).padStart(2,"0")).join(""); }
function hexToBytes(hex) {
  const s = hex.replace(/^0x/,"").replace(/\s+/g,"");
  if (s.length % 2) throw new Error("Invalid hex length");
  const out = new Uint8Array(s.length/2);
  for (let i=0;i<out.length;i++) out[i]=parseInt(s.substr(i*2,2),16);
  return out;
}
function base64urlEncode(u8) {
  let s = btoa(String.fromCharCode(...u8));
  return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function base64urlDecode(str) {
  let s = str.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}

function calculateEntropy() {
  const text = document.getElementById("entropyInput").value;
  const freq = {};
  for (let char of text) freq[char] = (freq[char] || 0) + 1;
  const len = text.length;
  const entropy = -Object.values(freq).reduce((acc, f) => {
    const p = f / len;
    return acc + p * Math.log2(p);
  }, 0);
  showModal("Shannon Entropy", `Entropy: ${entropy.toFixed(4)} bits/char`);
}

async function hashFile() {
  const fileInput = document.getElementById("hashFile");
  const algo = document.getElementById("hashAlgo").value;
  const file = fileInput?.files?.[0];

  if (!file) {
    alert("Choose a file to hash.");
    return;
  }

  // Read raw bytes (no decoding, no line-ending changes)
  const buffer = await file.arrayBuffer();

  // WebCrypto digest over the raw file bytes
  const hashBuffer = await crypto.subtle.digest(algo, buffer);
  const hashHex = [...new Uint8Array(hashBuffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  // Show in your modal with filename + size for auditability
  showModal(
    `${algo} File Hash`,
    `${file.name} (${file.size} bytes)\n${hashHex}`
  );
}

function compareStrings() {
  const str1 = document.getElementById("cmpStr1").value;
  const str2 = document.getElementById("cmpStr2").value;

  // Basic strict comparison
  const match = str1 === str2;

  let message;
  if (match) {
    message = "✅ Strings match exactly.";
  } else {
    message = "❌ Strings do NOT match.";
    // Optional debug detail:
    if (str1.length !== str2.length) {
      message += `\nLength differs: ${str1.length} vs ${str2.length}`;
    }
  }

  showModal("String Comparison", message);
}

async function encryptText() {
  const plaintext = document.getElementById("plainText")?.value?.trim();
  const usePassword = document.getElementById("usePassword")?.checked;
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  let key, keyExport;

  if (!plaintext) {
    alert("Please enter text to encrypt.");
    return;
  }

  if (usePassword) {
    const password = document.getElementById("passwordInput")?.value?.trim();
    if (!password) {
      alert("Please enter a password.");
      return;
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      enc.encode(plaintext)
    );

    const ctBytes = new Uint8Array(ciphertext);
    const output = new Uint8Array(salt.length + iv.length + ctBytes.length);
    output.set(salt, 0);
    output.set(iv, salt.length);
    output.set(ctBytes, salt.length + iv.length);

    download("encrypted.bin", output);

    // Modal output of parameters
    showModal("Encryption Info", 
      `Password: ${password}
      Salt: ${Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')}
      IV: ${Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('')}
      Iterations: 100000
      Hash: SHA-256`);
    
  } else {
    key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );

    keyExport = await crypto.subtle.exportKey("raw", key);

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      enc.encode(plaintext)
    );

    const ctBytes = new Uint8Array(ciphertext);
    const output = new Uint8Array(iv.length + ctBytes.length);
    output.set(iv, 0);
    output.set(ctBytes, iv.length);

    download("encrypted.bin", output);
    download("key.bin", new Uint8Array(keyExport));
  }
}

async function decryptFile() {
  const encFile = document.getElementById("encryptedFile")?.files[0];
  const keyFile = document.getElementById("keyFile")?.files[0];
  const usePassword = document.getElementById("usePassword")?.checked;

  if (!encFile) {
    alert("Please select the encrypted.bin file.");
    return;
  }

  const encryptedBuffer = await encFile.arrayBuffer();
  const dec = new TextDecoder();

  try {
    if (usePassword) {
      const password = document.getElementById("passwordInput")?.value?.trim();
      if (!password) {
        alert("Password is required for decryption.");
        return;
      }

      const salt = new Uint8Array(encryptedBuffer.slice(0, 16));
      const iv = new Uint8Array(encryptedBuffer.slice(16, 28));
      const ciphertext = encryptedBuffer.slice(28);

      const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );

      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
      );

      document.getElementById("decryptedText").value = dec.decode(decrypted);
    } else {
      if (!keyFile) {
        alert("Key file is required for decryption.");
        return;
      }

      const keyBuffer = await keyFile.arrayBuffer();
      const iv = new Uint8Array(encryptedBuffer.slice(0, 12));
      const ciphertext = encryptedBuffer.slice(12);

      const key = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
      );

      document.getElementById("decryptedText").value = dec.decode(decrypted);
    }
  } catch (err) {
    alert("Decryption failed.");
    console.error(err);
  }
}

function checkStrength() {
  const pw = document.getElementById("pwInput").value;
  let score = 0;
  if (pw.length > 8) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  showModal("Password Strength Score", `Score: ${score}/4`);
}

function b64Encode() {
  const input = document.getElementById("b64Input").value;
  const result = btoa(input);
  showModal("Base64 Encoded", result);
}

function b64Decode() {
  const input = document.getElementById("b64Input").value;
  try {
    const result = atob(input);
    showModal("Base64 Decoded", result);
  } catch {
    showModal("Base64 Decoded", "Invalid Base64!");
  }
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function b32Encode() {
  const input = document.getElementById("b32Input").value;
  let buffer = 0, bits = 0, output = "";
  for (let i = 0; i < input.length; i++) {
    buffer = (buffer << 8) | input.charCodeAt(i);
    bits += 8;
    while (bits >= 5) {
      output += base32Alphabet[(buffer >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += base32Alphabet[(buffer << (5 - bits)) & 31];
  showModal("Base32 Encoded", output);
}

function b32Decode() {
  const input = document.getElementById("b32Input").value.toUpperCase().replace(/=+$/, "");
  let buffer = 0, bits = 0, output = "";
  for (let i = 0; i < input.length; i++) {
    const val = base32Alphabet.indexOf(input[i]);
    if (val === -1) continue;
    buffer = (buffer << 5) | val;
    bits += 5;
    if (bits >= 8) {
      output += String.fromCharCode((buffer >> (bits - 8)) & 0xFF);
      bits -= 8;
    }
  }
  showModal("Base32 Decoded", output);
}

async function hashText() {
  const text = document.getElementById("hashInput").value;
  const algo = document.getElementById("hashAlgo").value;
  const buffer = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest(algo, buffer);
  const hashHex = [...new Uint8Array(hashBuffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  showModal(`${algo} Hash`, hashHex);
}

async function generateRSA() {
  const bits = parseInt(document.getElementById("rsaBits").value);
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const privKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const pubKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);

  download("rsa_private.pem", pemFormat(privKey, "PRIVATE KEY"));
  download("rsa_public.pem", pemFormat(pubKey, "PUBLIC KEY"));
}

async function generateEd25519() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "Ed25519",
    },
    true,
    ["sign", "verify"]
  );

  const privKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const pubKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);

  download("ed25519_private.pem", pemFormat(privKey, "PRIVATE KEY"));
  download("ed25519_public.pem", pemFormat(pubKey, "PUBLIC KEY"));
}

function pemFormat(buf, label) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  const lines = base64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function download(filename, data) {
  const blob = new Blob([data], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function purgeLocalData() {
  const cookies = document.cookie.split("; ");
  for (const cookie of cookies) {
    const eqPos = cookie.indexOf("=");
    const name = eqPos > -1 ? cookie.substring(0, eqPos) : cookie;
    document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;";
  }

  localStorage.clear();
  sessionStorage.clear();

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText("").catch(() => {});
  }

  document.querySelectorAll("input, textarea, code, p").forEach(el => {
    if (el.id === "signature" || el.id === "notice") return;
    if (el.tagName === "INPUT" || el.tagName === "TEXTAREA") el.value = "";
    if (el.tagName === "CODE" || el.tagName === "P") el.textContent = "";
  });

  document.getElementById("toolSelect").selectedIndex = 0;
  document.getElementById("toolSelect").dispatchEvent(new Event("change"));

  alert("Site data including cookies, clipboard, and form fields wiped.");
}

document.querySelector(".close").onclick = function () {
  const modalBox = document.getElementById("modalContent");
  modalBox.style.left = "";
  modalBox.style.top = "";
  modalBox.style.position = "";
  document.getElementById("resultModal").style.display = "none";
};

window.onclick = function (event) {
  if (event.target === document.getElementById("resultModal")) {
    const modalBox = document.getElementById("modalContent");
    modalBox.style.left = "";
    modalBox.style.top = "";
    modalBox.style.position = "";
    document.getElementById("resultModal").style.display = "none";
  }
};

document.addEventListener("keydown", function (event) {
  if (event.key === "Escape") {
    const modal = document.getElementById("resultModal");
    const box = document.getElementById("modalContent");
    if (modal.style.display === "block") {
      box.style.left = "";
      box.style.top = "";
      box.style.position = "";
      modal.style.display = "none";
    }
  }
});

function copyModalResult() {
  const text = document.getElementById("modalResultText").textContent;
  const copyBtn = document.getElementById("copyBtn");
  
  navigator.clipboard.writeText(text).then(() => {
    copyBtn.textContent = "Copied ✔️";
    setTimeout(() => {
      copyBtn.textContent = "Copy to Clipboard";
    }, 2000); // Reset after 2 seconds
  });
}

makeModalDraggable("modalContent");

function makeModalDraggable(modalId) {
  const modal = document.getElementById(modalId);
  let offsetX = 0, offsetY = 0, isDragging = false;

  const startDrag = (x, y) => {
    isDragging = true;
    offsetX = x - modal.offsetLeft;
    offsetY = y - modal.offsetTop;
  };

  const drag = (x, y) => {
    if (!isDragging) return;
    modal.style.position = "absolute";
    modal.style.left = `${x - offsetX}px`;
    modal.style.top = `${y - offsetY}px`;
  };

  const stopDrag = () => {
    isDragging = false;
  };

  // Mouse support
  modal.addEventListener("mousedown", e => startDrag(e.clientX, e.clientY));
  document.addEventListener("mousemove", e => drag(e.clientX, e.clientY));
  document.addEventListener("mouseup", stopDrag);

  // Touch support
  modal.addEventListener("touchstart", e => {
    const t = e.touches[0];
    startDrag(t.clientX, t.clientY);
  });
  document.addEventListener("touchmove", e => {
    if (!isDragging) return;
    const t = e.touches[0];
    drag(t.clientX, t.clientY);
    e.preventDefault(); // Prevent scroll while dragging
  }, { passive: false });
  document.addEventListener("touchend", stopDrag);
}
