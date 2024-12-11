# sib-crypto

JavaScript library of crypto standards.

## Node.js (Install)

Requirements:

- Node.js
- npm (Node.js package manager)

```bash
npm install sib-crypto
```

### Usage

ES6 import for typical API call signing use case:

```javascript
import * as sibCrypto from 'sib-crypto';

...
const md5 = sibCrypto.md5(message);
const aesEncrypt = sibCrypto.aesEncrypt(message, key, iv);
const aesDecrypt = sibCrypto.aesDecrypt(ciphertext, key, iv);
```

Modular include:

```javascript
var { md5, aesEncrypt, aesDecrypt } = require("sib-crypto");
...
console.log(md5, aesEncrypt, aesDecrypt);
```

## API

### Random key

```javascript
import { generateKey } from 'sib-crypto';

// 类型
type KeyOutputType = 'hex' | 'base64' | 'buffer';

interface KeyOptions {
    length?: number;
    type?: KeyOutputType;
    iv?: boolean;
}

// 示例用法
const defaultKey = generateKey(); // 默认密钥 (32字节，Hex 格式)
const base64Key = generateKey({ length: 16, type: 'base64' }); // Base64 格式密钥
const bufferIv = generateKey({ iv: true, type: 'buffer' }); // Buffer 格式 IV (16字节)


console.log('默认密钥 (Hex):', defaultKey);
console.log('Base64 格式密钥:', base64Key);
console.log('Buffer 格式 IV:', bufferIv);
```

### md5 Encryption

```javascript
import { md5 } from 'sib-crypto';
const md5text = md5('hello world!');
console.log(md5text); // fc3ff98e8c6a0d3087d515c0473f8677
```

### AES Encryption

```javascript
var { aesEncrypt, aesDecrypt } = require('sib-crypto'); // aes-256-cbc

const message = 'hello world!';
const key = '1234567890abcdef1234567890abcdef'; // 32字节（256位）密钥
const iv = 'abcdef9876543210'; // 16字节初始化向量

const ciphertext = aesEncrypt(message, key, iv);
console.log(ciphertext); // 060f1fd74ae75a534d3e284619060188

const originalText = aesDecrypt(ciphertext, key, iv);
console.log(originalText); // hello world!
```

### RSA Encryption

```javascript
/**
 * 可以使用 SSL工具 生成密钥对
 * https://www.ssleye.com/ssltool/pass_double.html
 * 密钥算法: RSA
 * 密钥强度: 4096
 * KEY密码： admin123
 */
import { rsaEncrypt, rsaDecrypt, decryptPrivateKey } from 'sib-crypto';

// 公钥
const publicKey = `
-----BEGIN PUBLIC KEY-----
    ...
-----END PUBLIC KEY-----`;

// 私钥 此处的私钥通过KEY密码加密了， 使用私钥解密时，需要先解密私钥，再用私钥去解密数据
const privateKey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
    ...
-----END ENCRYPTED PRIVATE KEY-----`;

// 需要加密的数据
const message = 'hello world!';

// 使用公钥加密
const encryptText = rsaEncrypt(message, publicKey);
console.log(encryptText); // xxxxx

// 先解密私钥
const key: KeyObject = decryptPrivateKey(privateKey, 'admin123'); // KeyObject 类型
// 使用解密后的私钥解密 密文
const decryptText = rsaDecrypt(encryptText, key);
console.log(decryptText); // hello world!
```
