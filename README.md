# **R-Secure-Token**  
🔐 A **secure alternative to JWT**, using **AES-256-GCM encryption** and **Ed25519 digital signatures** for authentication and authorization.

R-Secure-Token provides a **high-security** approach for token generation and verification, ensuring **tamper-proof** and **encrypted** payloads.

---

## **🌟 Features**  
✅ **AES-256-GCM Encryption** – Strong encryption for payload security.  
✅ **Ed25519 Signatures** – Prevents forgery and tampering.  
✅ **Replay Attack Prevention** – Unique nonce per token.  
✅ **JWT Alternative** – Secure and stateless authentication.  
✅ **High Performance** – Optimized for speed and security.  

---

## **📦 Installation**  
Install via NPM:  
```sh
npm install r-secure-token
```
or with Yarn:  
```sh
yarn add r-secure-token
```

---

## **🚀 Usage**  

### **1️⃣ Generating a Secure Token**  
```typescript
import { RSecureToken } from 'r-secure-token';

(async () => {
  const tokenService = new RSecureToken();
  const payload = { data: { userId: 123 }, exp: Date.now() + 60000 }; // 1-minute expiry
  const tokenData = await tokenService.generateToken(payload);

  console.log('Token:', tokenData.token);
  console.log('Signature:', tokenData.signature);
})();
```

### **2️⃣ Verifying & Decrypting a Secure Token**  
```typescript
import { RSecureToken } from 'r-secure-token';

(async () => {
  const tokenService = new RSecureToken();
  const { token, signature } = /* Token received from user */;
  
  const verifiedPayload = await tokenService.verifyToken(token, signature);

  if (verifiedPayload) {
    console.log('Valid Token:', verifiedPayload);
  } else {
    console.log('Invalid or Expired Token!');
  }
})();
```

---

## **🔬 How It Works**
### **1. Token Generation**
- Encrypts the payload using **AES-256-GCM**.
- Generates a secure **nonce** for each token.
- Signs the encrypted token using **Ed25519**.

### **2. Token Verification**
- Checks the **Ed25519 signature** for authenticity.
- Decrypts the token using **AES-256-GCM**.
- Validates token expiration.

---

## **🔐 Security Advantages Over JWT**
| Feature              | JWT (JSON Web Tokens)         | R-Secure-Token |
|----------------------|----------------------------|----------------------|
| **Encryption**       | ❌ No built-in encryption  | ✅ AES-256-GCM |
| **Signature Type**   | RSA / HMAC / ECDSA         | ✅ Ed25519 |
| **Tamper Protection**| ✅ Yes                     | ✅ Yes |
| **Readable Payload** | ❌ Exposed (Base64-encoded JSON) | ✅ Encrypted |
| **Replay Attack Resistance** | ❌ None | ✅ Unique nonce per token |
| **Verification Type** | Requires shared secret (HMAC) or public-private keypair | ✅ Uses asymmetric cryptography |

---

## **📄 API Reference**  
### **new RSecureToken(secretKey?: Buffer)**  
Creates a new instance of `RSecureToken`. If no secret key is provided, a random one is generated.  

### **generateToken(payload: TokenPayload): Promise<SecureToken>**  
Creates a secure, signed token.  
#### Parameters:  
- `payload` (object) – The data to include in the token, including an `exp` (expiration timestamp).  

#### Returns:  
```ts
{
  token: string;     // Encrypted token
  signature: string; // Ed25519 signature
}
```

### **verifyToken(token: string, signature: string): Promise<TokenPayload | null>**  
Verifies and decrypts the token if valid.  
#### Parameters:  
- `token` (string) – The encrypted token.  
- `signature` (string) – The digital signature for verification.  

#### Returns:  
- **Valid:** Returns the decrypted payload object.  
- **Invalid:** Returns `null`.  

Example Response:
```ts
{
  data: { userId: 123 },
  exp: 1700000000000
}
```

---

## **⚠️ Best Practices**
🔹 **Store Secret Keys Securely:** Never hardcode them in your source code. Use environment variables or a secure key management system.  
🔹 **Rotate Keys Periodically:** Regularly update encryption and signing keys to minimize security risks.  
🔹 **Use Short-Lived Tokens:** Prevent token abuse by setting short expiration times (`exp`).  
🔹 **Avoid Token Storage in Local Storage:** Instead, store tokens in **HTTP-only cookies** or secure storage solutions.  

---

## **📜 License**  
This project is licensed under the **MIT License**.  

---

## **📞 Support & Contributions**
👨‍💻 **Contributions are welcome!** Feel free to submit pull requests or report issues on [GitHub](https://github.com/raj9686/r-secure-token).  
📧 **Need Help?** Open an issue or contact us!  
