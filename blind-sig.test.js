const blindSig = require("./blind-sig.js");

function testData() {
    const keyPairs = blindSig.genKeys({
        modulusLength: 2048,
        publicKeyEncoding: { format: "jwk" },
        privateKeyEncoding: { format: "jwk" },
    });

    const e = blindSig.base64ToBigInt(keyPairs.publicKey.e);
    const n = blindSig.base64ToBigInt(keyPairs.publicKey.n);
    const d = blindSig.base64ToBigInt(keyPairs.privateKey.d);
    const message = "Hello world!";

    return { message, e, d, n };
}

test("Valid blinding and signing", () => {
    const { message, e, d, n } = testData();
    const { blinded, r } = blindSig.blind(message, e, n);
    const signature = blindSig.sign(blinded, d, n);
    expect(() =>
        blindSig.unblindVerify(message, signature, r, e, n)
    ).not.toThrow();
});

test("Valid blinding and signing 2", () => {
    const { message, e, d, n } = testData();
    const { blinded, r } = blindSig.blind(message, e, n);
    const signature = blindSig.sign(blinded, d, n);
    const unblinded = blindSig.unblind(signature, r, n);
    expect(unblinded).toEqual(blindSig.messageToHashInt(message).modPow(d, n));
});

test("Valid blinding but invalid signing", () => {
    const { message, e, d, n } = testData();
    const { blinded, r } = blindSig.blind(message, e, n);
    const signature = blindSig.sign(blinded, e, n);
    expect(() => blindSig.unblindVerify(message, signature, r, e, n)).toThrow();
});

test("Invalid blinding but valid signing", () => {
    const { message, e, d, n } = testData();
    const invalidE = BigInt("0x1");
    const { blinded, r } = blindSig.blind(message, invalidE, n);
    const signature = blindSig.sign(blinded, d, n);
    expect(() =>
        blindSig.unblindVerify(message, signature, r, invalidE, n)
    ).toThrow();
});
