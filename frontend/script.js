window.__PUBKEY_WEBAUTH__ = {};
window.__PUBKEY_WEBAUTH__.backend_url = "http://localhost:5000";
window.__PUBKEY_WEBAUTH__.priv_key = null;

document.getElementById("inputfile").addEventListener("change", function () {
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

document
  .getElementById("do-auth-button")
  .addEventListener("click", async function () {
    if (window.__PUBKEY_WEBAUTH__.priv_key === null) {
      alert("private key missing");
      return;
    }

    // TODO: use username or something instead of uuid
    let challenge = await requestAuthChallenge(
      "018e4b5d-9d6b-7288-bbbe-0c81e76a6a11",
    );
    let decrypted_challenge = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      window.__PUBKEY_WEBAUTH__.priv_key,
      challenge,
    );

    await solveAuthChallenge(
      "018e4b5d-9d6b-7288-bbbe-0c81e76a6a11",
      decrypted_challenge,
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
 * @param {string} user_id
 * @returns {Promise<ArrayBuffer>}
 */
async function requestAuthChallenge(user_id) {
  return await fetch(
    `${window.__PUBKEY_WEBAUTH__.backend_url}/auth/${user_id}/challenge`,
  )
    .then((resp) => {
      return resp.json();
    })
    .then((data) => {
      return str2ab(atob(data));
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
