# Chaum's Blind Signature Implementation in JavaScript

This repo contains the code for a non-production JavaScript implementation of Chaum's Blind Signature scheme.
It uses the `crypto` library and the `big-integer` library in NodeJS, but it can work in browsers as well (with the exception of the `genKeys` function).
It is inspired by an older [blind-signatures JS library ](https://github.com/kevinejohn/blind-signatures).
We emphasize that our code is not meant for production use, so use it at your own discretion (e.g. BigInt in JavaScript is not resistant to [timing attacks](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography)).

Installation: Clone the repo, then run `npm install` inside the repo.

Example usage:

```javascript
    const blindSig = require("./blind-sig.js");
    const keyPairs = blindSig.genKeys({
        modulusLength: 2048,
        publicKeyEncoding: { format: "jwk" },
        privateKeyEncoding: { format: "jwk" },
    });
    const e = blindSig.base64ToBigInt(keyPairs.publicKey.e);
    const n = blindSig.base64ToBigInt(keyPairs.publicKey.n);
    const d = blindSig.base64ToBigInt(keyPairs.privateKey.d);
    const message = "Hello world!";
    const { blinded, r } = blindSig.blind(message, e, n);
    const signature = blindSig.sign(blinded, d, n);
    const unblinded = blindSig.unblindVerify(message, signature, r, e, n);
```

We also provide a browserified package with `blind-sig.min.js` (bundled and minified with the command `browserify -r ./blind-sig.js:blind-sig -o | uglifyjs -o blind-sig.min.js`, you need to install `browserify` and `uglifyjs`). It can be easily imported into your website as follows (check out the `demo.html`):

```html
<script src="./blind-sig.min.js"></script>
<script>
    const blindSig = require("blind-sig");
</script>
```

Note: Don't use the `genKeys` function in browser environment, it's only supported in NodeJS. Use Web Crypto API instead to generate keys (see `demo.html`)