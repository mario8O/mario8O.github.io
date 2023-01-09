const VAULT_CYPHER_TYPE = {
    AES_256: 1,
    RSA_4096: 2
};

class VaultUtil {
    fromUtf8(str) {
        const strUtf8 = unescape(encodeURIComponent(str));
        const bytes = new Uint8Array(strUtf8.length);
        for (let i = 0; i < strUtf8.length; i++) {
            bytes[i] = strUtf8.charCodeAt(i);
        }
        return bytes.buffer;
    }

    toUtf8(buf) {
        const bytes = new Uint8Array(buf);
        const encodedString = String.fromCharCode.apply(null, bytes);
        return decodeURIComponent(escape(encodedString));
    }

    toB64(buf) {
        if (!buf) return;
        let binary = '';
        const bytes = new Uint8Array(buf);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    fromB64(base64) {
        if (!base64) return;
        try {
            const binary_string = window.atob(base64);
            const len = binary_string.length;
            let bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
        } catch (err) {
            console.log(err.message);
            alert("Check your message part: " + base64);
            return new Uint8Array(1);
        }
    }

    toHex(dec) {
        return Number(dec).toString(16).toUpperCase();
    }

    invertHex(hex) {
        return (Number("0x" + hex) ^ 0xFFFFFF).toString(16).toUpperCase();
    }
}
let vaultUtil = new VaultUtil();


class VaultChecksum {
    crcTable = this.makeCRCTable();

    makeCRCTable() {
        let c;
        let crcTable = [];
        for (let n = 0; n < 256; n++) {
            c = n;
            for (let k = 0; k < 8; k++) {
                c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
            }
            crcTable[n] = c;
        }
        return crcTable;
    }

    crc32(str) {
        let crc = 0 ^ (-1);
        for (let i = 0; i < str.length; i++) {
            crc = (crc >>> 8) ^ this.crcTable[(crc ^ str.charCodeAt(i)) & 0xFF];
        }
        return (crc ^ (-1)) >>> 0;
    }
}
let vaultChecksum = new VaultChecksum();

class VaultCypher {
    constructor(str) {
        if (!str) return;
        let obj = JSON.parse(str);
        if (typeof obj == "number") {
            throw "Could not parse to cypher object";
        }
        this.type = parseInt(obj.type);
        this.time = obj.time;
        this.key = vaultUtil.fromB64(obj.key);
        this.salt = vaultUtil.fromB64(obj.salt);
        this.iv = vaultUtil.fromB64(obj.iv);
        this.data = vaultUtil.fromB64(obj.data);
    }

    isValid() {
        if (this.type == VAULT_CYPHER_TYPE.AES_256 && this.salt && this.iv && this.data) {
            return true;
        }
        if (this.type == VAULT_CYPHER_TYPE.RSA_4096 && this.time && this.key && this.iv && this.data) {
            return true;
        }
        return false;
    }

    stringify() {
        let obj = {};
        obj.type = this.type;
        obj.time = this.time;
        obj.key = vaultUtil.toB64(this.key);
        obj.salt = vaultUtil.toB64(this.salt);
        obj.iv = vaultUtil.toB64(this.iv);
        obj.data = vaultUtil.toB64(this.data);
        return JSON.stringify(obj);
    }
}

/**
 * Web Crypto API
 */
class VaultCrypto {
    isCypher(str) {
        if (!str) return false;
        try {
            return new VaultCypher(str).isValid();
        } catch (err) {
            console.log(err.message);
            return false;
        }
    }

    async aesImportAndDeriveKey(password, salt) {
        console.log("aesImportAndDeriveKey");
        let key = await window.crypto.subtle.importKey(
            "raw",
            vaultUtil.fromUtf8(password),
            {
                name: "PBKDF2"
            },
            false,
            ["deriveKey"]
        );
        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 1000000,
                hash: { name: "SHA-256" }
            },
            key,
            {
                name: "AES-CBC",
                length: 256
            },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async aesGenerateAndExportKey() {
        console.log("aesGenerateAndExportKey");
        let key = await window.crypto.subtle.generateKey(
            {
                name: "AES-CBC",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
        return window.crypto.subtle.exportKey(
            "jwk",
            key
        );
    }

    async aesImportKey(key) {
        console.log("aesImportKey");
        return window.crypto.subtle.importKey(
            "jwk",
            key,
            {
                name: "AES-CBC"
            },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async aesEncrypt(key, iv, str) {
        console.log("aesEncrypt");
        return await window.crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv
            },
            key,
            vaultUtil.fromUtf8(str)
        );
    }

    async aesDecrypt(key, iv, data) {
        console.log("aesDecrypt");
        return await window.crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: iv
            },
            key,
            data
        );
    }

    async rsaImportPublicKey(publicKey) {
        console.log("rsaImportPublicKey");
        return await window.crypto.subtle.importKey(
            "jwk",
            publicKey,
            {
                name: "RSA-OAEP",
                hash: { name: "SHA-256" }
            },
            false,
            ["encrypt"]
        );
    }

    async rsaImportPrivateKey(privateKey) {
        console.log("rsaImportPrivateKey");
        return await window.crypto.subtle.importKey(
            "jwk",
            privateKey,
            {
                name: "RSA-OAEP",
                hash: { name: "SHA-256" }
            },
            false,
            ["decrypt"]
        );
    }

    async rsaEncrypt(publicKey, str) {
        console.log("rsaEncrypt");
        return await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            publicKey,
            vaultUtil.fromUtf8(str)
        );
    }

    async rsaDecrypt(privateKey, data) {
        console.log("rsaDecrypt");
        return await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            privateKey,
            data
        );
    }

    async aesEncryptFlow(password, message) {
        console.log("aesEncryptFlow");
        let cypher = new VaultCypher();
        cypher.type = VAULT_CYPHER_TYPE.AES_256;
        cypher.salt = window.crypto.getRandomValues(new Uint8Array(16));
        cypher.iv = window.crypto.getRandomValues(new Uint8Array(16));
        let key = await this.aesImportAndDeriveKey(password, cypher.salt);
        cypher.data = await this.aesEncrypt(key, cypher.iv, message);
        return cypher.stringify();
    }

    async aesDecryptFlow(password, cypher) {
        console.log("aesDecryptFlow");
        let key = await this.aesImportAndDeriveKey(password, cypher.salt);
        return vaultUtil.toUtf8(await this.aesDecrypt(key, cypher.iv, cypher.data));
    }

    async rsaEncryptFlow(publicKey, message, time) {
        console.log("rsaEncryptFlow");
        let cypher = new VaultCypher();
        cypher.type = VAULT_CYPHER_TYPE.RSA_4096;
        cypher.time = time;
        let aesKey = await this.aesGenerateAndExportKey();
        let importedPublicKey = await this.rsaImportPublicKey(publicKey);
        cypher.key = await this.rsaEncrypt(importedPublicKey, JSON.stringify(aesKey));
        let importedAesKey = await this.aesImportKey(aesKey);
        cypher.iv = window.crypto.getRandomValues(new Uint8Array(16));
        cypher.data = await this.aesEncrypt(importedAesKey, cypher.iv, message);
        return cypher.stringify();
    }

    async rsaDecryptFlow(privateKey, cypher) {
        console.log("rsaDecryptFlow");
        let importedPrivateKey = await this.rsaImportPrivateKey(privateKey);
        let aesKey = JSON.parse(vaultUtil.toUtf8(await this.rsaDecrypt(importedPrivateKey, cypher.key)));
        let importedAesKey = await this.aesImportKey(aesKey);
        return vaultUtil.toUtf8(await this.aesDecrypt(importedAesKey, cypher.iv, cypher.data));
    }

    async autoCryptFlow(password, message, time) {
        console.log("autoCryptFlow");
        let cypher = {};
        try {
            cypher = new VaultCypher(message);
        } catch (err) {
            console.log(err.message);
            if (time) {
                const publicKey = vaultKeys[time].publicKey
                return await this.rsaEncryptFlow(publicKey, message, time);
            } else {
                return await this.aesEncryptFlow(password, message);
            }
        }
        if (cypher.type == VAULT_CYPHER_TYPE.AES_256) {
            return await this.aesDecryptFlow(password, cypher);
        } else if (cypher.type == VAULT_CYPHER_TYPE.RSA_4096) {
            const privateKey = vaultKeys[cypher.time].privateKey;
            if (!privateKey) {
                alert("Message cannot be unlocked before year " + cypher.time);
                return message;
            }
            return await this.rsaDecryptFlow(privateKey, cypher);
        }
        return message;
    }
}
let vaultCrypto = new VaultCrypto();

class VaultMainController {
    applyTimeLock = false;

    constructor(printView, mainView, timelockCheckbox, yearSelect, passwordField, checksumElement, checksumColorElement, lockButton, copyButton, printButton, clearButton, messageField, messageSizeElement) {
        this.printView = printView;
        this.mainView = mainView;
        this.timelockCheckbox = timelockCheckbox;
        this.yearSelect = yearSelect;
        this.passwordField = passwordField;
        this.checksumElement = checksumElement;
        this.checksumColorElement = checksumColorElement;
        this.lockButton = lockButton;
        this.copyButton = copyButton;
        this.printButton = printButton;
        this.clearButton = clearButton;
        this.messageField = messageField;
        this.messageSizeElement = messageSizeElement;
    }

    updateVisibility() {
        this.timelockCheckbox.checked = this.applyTimeLock;
        this.yearSelect.disabled = !this.applyTimeLock;
        this.passwordField.disabled = this.applyTimeLock;
        this.lockButton.disabled = (!this.applyTimeLock && !this.passwordField.value && !vaultCrypto.isCypher(this.messageField.value)) || !this.messageField.value;
        this.copyButton.disabled = !vaultCrypto.isCypher(this.messageField.value);
        this.printButton.disabled = !vaultCrypto.isCypher(this.messageField.value);
        this.clearButton.disabled = !this.messageField.value;
    }

    toggleApplyTimeLock() {
        this.applyTimeLock = !this.applyTimeLock;
        this.updateVisibility();
    }

    toggleShowPassword() {
        if (this.passwordField.type === "password") {
            this.passwordField.type = "text";
        } else {
            this.passwordField.type = "password";
        }
    }

    checksum(str) {
        let checksum;
        try {
            checksum = vaultUtil.toHex(vaultChecksum.crc32(str));
        } catch (err) {
            console.log(err.message);
            checksum = vaultUtil.toHex(0);
        }
        return checksum;
    }

    calcPasswordChecksum() {
        let passwordChecksum = this.checksum(this.passwordField.value);
        this.checksumElement.textContent = passwordChecksum.substr(-4);
        let colorHex = passwordChecksum.substr(-6).padStart(6, "0");
        this.checksumColorElement.style.backgroundColor = "#" + colorHex;
        this.checksumColorElement.style.color = "#" + vaultUtil.invertHex(colorHex);
        this.updateVisibility();
    }

    countMessage() {
        this.messageSizeElement.textContent = this.messageField.value.length;
        this.updateVisibility();
    }

    setAndCountMessage(str) {
        this.messageField.value = str;
        this.countMessage();
    }

    appendAndCountMessage(str) {
        this.setAndCountMessage(this.messageField.value + str);
    }

    async cryptMessage() {
        const password = this.passwordField.value;
        let message = this.messageField.value;
        if (!message) return;
        let time;
        if (this.applyTimeLock) {
            time = this.yearSelect.value;
        }
        let cryptResult = await vaultCrypto.autoCryptFlow(password, message, time);
        this.setAndCountMessage(cryptResult);
    }

    copyMessage() {
        if (this.messageField.value === "") return;
        this.messageField.select();
        this.messageField.setSelectionRange(0, 99999);
        document.execCommand("copy");
    }

    printMessage() {
        this.printView.textContent = this.messageField.value;
        this.mainView.textContent = "";
    }
}

class VaultKeyboardController {
    capsLock = false;

    constructor(vaultMainController, capsLockButton) {
        this.vaultMainController = vaultMainController;
        this.capsLockButton = capsLockButton;
    }

    press(key) {
        if (key === "^") {
            this.capsLock = !this.capsLock;
            if (this.capsLock) {
                this.capsLockButton.style.cssText = "background-color: #70d3d4";
            } else {
                this.capsLockButton.style.cssText = "";
            }
            return;
        }
        if (this.capsLock) {
            key = key.toUpperCase();
        }
        this.vaultMainController.appendAndCountMessage(key);
    }
}