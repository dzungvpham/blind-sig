const bigInt = require("big-integer");
const crypto = require("crypto");

/**
 * Generates RSA key pair using crypto.generateKeyPairSync.
 * Note that this should not be used in browser environment since generateKeyPairSync is not available.
 * Use the Web Crypto API instead.
 * @param {crypto.RSAKeyPairOptions} options - RSA key generation options (default: { modulusLength: 2048 }).
 * @returns {crypto.KeyObject} - Object containing public and private keys.
 */
async function genKeys(options = { modulusLength: 2048 }) {
    return crypto.generateKeyPairSync("rsa", options);
}

/**
 * Converts a base64-encoded string to a big integer.
 * @param {string} str - Base64-encoded string.
 * @returns {BigInt} - BigInt representation of the input string.
 */
function base64ToBigInt(str) {
    return bigInt(Buffer.from(str, "base64").toString("hex"), 16);
}

/**
 * Converts a big integer to a base64-encoded string.
 * @param {BigInt} n - BigInt to be converted.
 * @returns {string} - Base64-encoded representation of the input BigInt.
 */
function bigIntToBase64(n) {
    return Buffer.from(bigInt(n).toString(16), "hex").toString("base64");
}

/**
 * Hashes a message and returns as a BigInt using SHA-256.
 * @param {string} message - Input message to be hashed.
 * @returns {BigInt} - BigInt representing the hash of the input message.
 */
function messageToHashInt(message) {
    const m = crypto.createHash("sha256").update(message).digest("hex");
    return bigInt(m, 16);
}

/**
 * Checks if two BigInt are coprime.
 * @param {BigInt} a - First BigInt.
 * @param {BigInt} b - Second BigInt.
 * @returns {boolean} - True if a and b are coprime, false otherwise.
 */
function isCoprime(a, b) {
    return bigInt.gcd(bigInt(a), bigInt(b)).equals(bigInt.one);
}

/**
 * Blinds a message using RSA blind signature scheme.
 * @param {string} message - Input message to be blinded.
 * @param {BigInt} e - Public exponent.
 * @param {BigInt} n - Modulus.
 * @returns {Object} - Object containing blinded message and random value.
 * @throws {string} - Throws an error if the message hash is not coprime with the modulus.
 */
function blind(message, e, n) {
    e = bigInt(e);
    n = bigInt(n);
    const m = messageToHashInt(message);
    if (!isCoprime(m, n)) {
        throw "Invalid input: Message hash is not co-prime with modulus.";
    }

    let r;
    do {
        r = bigInt(crypto.randomBytes(256).toString("hex"), 16).mod(n);
    } while (!isCoprime(r, n));

    const blinded = m.multiply(r.modPow(e, n)).mod(n);
    return { blinded, r };
}

/**
 * Signs a blinded message using RSA blind signature scheme.
 * @param {BigInt} blinded - Blinded message.
 * @param {BigInt} d - Private exponent.
 * @param {BigInt} n - Modulus.
 * @returns {BigInt} - Signed blinded message.
 */
function sign(blinded, d, n) {
    return blinded.modPow(bigInt(d), bigInt(n));
}

/**
 * Unblinds a signed message using RSA blind signature scheme.
 * @param {BigInt} signed - Signed message.
 * @param {BigInt} r - Blinding factor.
 * @param {BigInt} n - Modulus.
 * @returns {BigInt} - Unblinded message.
 */
function unblind(signed, r, n) {
    r = bigInt(r);
    n = bigInt(n);
    return signed.multiply(r.modInv(n)).mod(n);
}

/**
 * Verifies a message against its unblinded signature using RSA blind signature scheme.
 * @param {string} msg - Original message.
 * @param {BigInt} unblinded - Unblinded message.
 * @param {BigInt} e - Public exponent.
 * @param {BigInt} n - Modulus.
 * @returns {boolean} - True if the signature is valid, false otherwise.
 */
function verify(msg, unblinded, e, n) {
    unblinded = bigInt(unblinded);
    e = bigInt(e);
    n = bigInt(n);
    return messageToHashInt(msg).equals(unblinded.modPow(e, n));
}

/**
 * Unblinds a signed message and verifies it against the original message using RSA blind signature scheme.
 * @param {string} msg - Original message.
 * @param {BigInt} signed - Signed message.
 * @param {BigInt} r - Blinding factor.
 * @param {BigInt} e - Public exponent.
 * @param {BigInt} n - Modulus.
 * @returns {BigInt} - Unblinded message if the signature is valid.
 * @throws {string} - Throws an error if the signature is invalid.
 */
function unblindVerify(msg, signed, r, e, n) {
    signed = bigInt(signed);
    r = bigInt(r);
    e = bigInt(e);
    n = bigInt(n);
    const unblinded = unblind(signed, r, n);
    if (!verify(msg, unblinded, e, n)) {
        throw "Invalid signature.";
    }
    return unblinded;
}

module.exports = {
    genKeys,
    base64ToBigInt,
    bigIntToBase64,
    messageToHashInt,
    blind,
    sign,
    unblind,
    verify,
    unblindVerify,
};
