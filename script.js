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
        <label><b>Password length: </b><input type="number" id="pwLength" min="8" max="128" value="32"></label>
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
        <button onclick="hashText()">Generate Hash</button>`;
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

function generatePassword() {
  const len = parseInt(document.getElementById("pwLength").value);
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}<>?";
  const array = new Uint32Array(len);
  window.crypto.getRandomValues(array);
  const password = Array.from(array, x => charset[x % charset.length]).join('');
  showModal(`Generated Password (${len} chars)`, password);
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
