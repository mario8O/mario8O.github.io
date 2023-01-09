let generatedVaultKeys = {};

// step 1
function generateVaultKeys() {
    let years = ["2021", "2022", "2023", "2024", "2025", "2026", "2027", "2028", "2029", "2030", "2031"];
    years.forEach(function (y) {
        generatedVaultKeys[y] = {};
        window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 4096,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: { name: "SHA-256" },
            },
            true,
            ["encrypt", "decrypt"]
        ).then(function (keyPair) {
            window.crypto.subtle.exportKey("jwk", keyPair.publicKey).then(function (publicKey) {
                generatedVaultKeys[y].publicKey = publicKey;
            });
            window.crypto.subtle.exportKey("jwk", keyPair.privateKey).then(function (privateKey) {
                generatedVaultKeys[y].privateKey = privateKey;
            });
        });
    });
}

// step 2
function printVaultKeys() {
    console.log(JSON.stringify(generatedVaultKeys));
}