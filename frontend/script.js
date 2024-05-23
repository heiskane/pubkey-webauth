window.__PUBKEY_WEBAUTH__ = {};
window.__PUBKEY_WEBAUTH__.backend_url = "http://localhost:8001";
window.__PUBKEY_WEBAUTH__.priv_key = null;

document.getElementById("private_key").addEventListener("change", function () {
  let fr = new FileReader();
  fr.onload = async function () {
    window.__PUBKEY_WEBAUTH__.priv_key = await window.crypto.subtle.importKey(
      "pkcs8",
      readPemBytes(fr.result),
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"],
    );
  };

  fr.readAsText(this.files[0]);
});

document.getElementById("public_key").addEventListener("change", function () {
  let fr = new FileReader();
  fr.onload = async function () {
    window.__PUBKEY_WEBAUTH__.public_key_raw = fr.result;
  };

  fr.readAsText(this.files[0]);
});

document
  .getElementById("auth-form")
  .addEventListener("submit", async function (evt) {
    evt.preventDefault();

    if (window.__PUBKEY_WEBAUTH__.priv_key === null) {
      alert("private key missing");
      return;
    }

    let challenge = await requestAuthChallenge(
      evt.target.elements.username.value,
    );

    if (challenge === null) {
      return;
    }

    let decrypted_challenge = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      window.__PUBKEY_WEBAUTH__.priv_key,
      challenge,
    );

    await solveAuthChallenge(
      evt.target.elements.username.value,
      decrypted_challenge,
    );
  });

document
  .getElementById("user-register-form")
  .addEventListener("submit", async function (evt) {
    evt.preventDefault();

    await registerUser(
      evt.target.elements.username.value,
      window.__PUBKEY_WEBAUTH__.public_key_raw,
    );
  });

/**
 * Get the bytes from a PEM formatted private key
 * @param {string} pem
 * @returns {ArrayBuffer}
 */
function readPemBytes(pem) {
  let pemContents = pem.split("\n").slice(1, -2).join("");
  let decoded_key = atob(pemContents);
  return str2ab(decoded_key);
}

/**
 * Convert a string into an ArrayBuffer
 * from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
 * @param {string} str
 * @returns {ArrayBuffer}
 */
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

/**
 * Convert ArrayBuffer to string
 * @param {ArrayBuffer} buf
 * @returns {string}
 */
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

/**
 * @param {string} username
 * @returns {Promise<ArrayBuffer | null>}
 */
async function requestAuthChallenge(username) {
  return await fetch(
    `${window.__PUBKEY_WEBAUTH__.backend_url}/auth/${username}/challenge`,
  )
    .then((resp) => {
      if (!resp.ok) {
        console.log("challenge request failed", resp);
        throw new Error("failed to fetch challenge");
      }
      return resp;
    })
    .then((resp) => {
      return resp.json();
    })
    .then((data) => {
      return str2ab(atob(data));
    })
    .catch((err) => {
      console.log(err);
      return null;
    });
}

/**
 * @param {string} user_id
 * @param {ArrayBuffer} decrypted_challenge
 * @returns {Promise<void>}
 */
async function solveAuthChallenge(user_id, decrypted_challenge) {
  await fetch(`${window.__PUBKEY_WEBAUTH__.backend_url}/auth/${user_id}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      decrypted_challenge: btoa(ab2str(decrypted_challenge)),
    }),
  })
    .then((resp) => {
      return resp.json();
    })
    .then((data) => {
      console.log("auth result: ", data);
    });
}

/**
 * @param {string} username
 * @param {string} pubkey
 * @returns {Promise<void>}
 */
async function registerUser(username, pubkey) {
  return await fetch(
    `${window.__PUBKEY_WEBAUTH__.backend_url}/users/register`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username: username, pubkey: pubkey }),
    },
  )
    .then((resp) => {
      return resp.json();
    })
    .then((data) => {
      console.log("userRegister resp:", data);
    });
}
