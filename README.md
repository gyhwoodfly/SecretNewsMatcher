# SecretNewsMatcher

**Confidential interest-based news matching using Zama FHEVM**

SecretNewsMatcher is a confidential Ethereum smart-contract system built using **Zama’s FHEVM**, enabling users to privately express their interests and check whether a news article matches those interests — without ever revealing any personal preference on-chain.

This repository contains:

```
/contracts       → FHEVM smart contract (Solidity)
/scripts         → Deployment scripts
/test            → Hardhat tests
/frontend        → Placeholder folder for integrating Relayer SDK (optional)
```

---

# ✨ Overview

SecretNewsMatcher enables:

### 📰 Publishers

Publish news articles with a **public topicMask (uint32)**.

### 🔐 Users

Store their encrypted interest bitmask (`euint32`) using **FHEVM Gateway** and **ZK attestation**.

### 🧮 Confidential Matching

For each article, the contract computes:

```
(hasMatch = (interestMask & topicMask) != 0)
```

This happens entirely in encrypted form (`ebool`), ensuring:

* ❌ The contract **never sees user interests**
* ❌ The network **never sees user interests**
* ❌ No one can infer interests from computed results

Users later decrypt results through the **Relayer SDK → userDecrypt()**.

---

# 🔒 Core Features

| Feature                          | Description                                              |
| -------------------------------- | -------------------------------------------------------- |
| **Private interests**            | User interest bitmask stored as `euint32`                |
| **Encrypted matching**           | FHE logical operations compute encrypted match (`ebool`) |
| **Access control**               | FHEVM ACL (allow, allowThis, allowTransient)             |
| **Selective result sharing**     | Users can grant access or make results public            |
| **Publisher-managed articles**   | Publishers control their articles and topic masks        |
| **ZK-attested encrypted inputs** | Uses Gateway attestation via `externalEuint32`           |

---

# 🛠 Tech Stack

* **Zama FHEVM Solidity library**
  `@fhevm/solidity/lib/FHE.sol`

* **ZamaEthereumConfig**
  `@fhevm/solidity/config/ZamaConfig.sol`

* **Relayer SDK** (frontend)
  `@zama-fhe/relayer-sdk`

* **Hardhat** for development, testing, deployment

---

# 📁 Repository Structure (Updated)

```
SecretNewsMatcher/
│
├── contracts/
│   └── SecretNewsMatcher.sol     → Main confidential contract
│
├── scripts/
│   └── deploy.js                 → Deployment script
│
├── test/
│   └── SecretNewsMatcher.test.js → Unit tests
│
└── README.md                     → (You’re reading the upgraded version)
```

---

# 🔧 Smart Contract Design

### Encrypted User Profile

```solidity
struct InterestProfile {
    euint32 mask;
    bool set;
}
```

### Article Metadata

```solidity
struct Article {
    address publisher;
    uint32 topicMask;
    string uri;
    bool exists;
}
```

### Encrypted Match Result

```solidity
struct MatchCheck {
    address user;
    uint64 ts;
    ebool hasMatch;
    bool set;
}
```

---

# 🔍 Confidential Matching Logic

The FHE computation is performed using encrypted operations:

```solidity
euint32 interestMask = p.mask;
euint32 topicMaskEnc = FHE.asEuint32(a.topicMask);

euint32 intersection = FHE.and(interestMask, topicMaskEnc);
ebool hasMatch = FHE.ne(intersection, FHE.asEuint32(0));
```

The boolean result is stored encrypted and can be decrypted only by:

* the user (via userDecrypt)
* explicitly allowed addresses
* publicly (if the user calls makeMatchPublic)

---

# 🧰 Key Functions

### Publish an article

```solidity
publishArticle(string uri, uint32 topicMask)
```

### Set encrypted interests

```solidity
setEncryptedInterest(externalEuint32 encMask, bytes attestation)
```

### Compute encrypted match result

```solidity
computeMatch(uint256 articleId)
```

### Retrieve encrypted handle

```solidity
matchHandle(address user, uint256 articleId)
```

### Grant decryption access

```solidity
grantMatchAccess(address user, uint256 articleId, address to)
```

### Make result public

```solidity
makeMatchPublic(articleId)
```

---

# 🧱 Frontend Integration (Relayer SDK)

Example: Encrypt interests, upload to contract, compute match, decrypt result.

```ts
import { createInstance, SepoliaConfig } from "@zama-fhe/relayer-sdk";

const sdk = await createInstance(SepoliaConfig);

// 1. Prepare encrypted input
const enc = await sdk.createEncryptedInput({
  interestMask: 0b101001
});

// 2. Send encrypted profile to contract
await contract.setEncryptedInterest(enc.external, enc.attestation);

// 3. Ask contract to compute encrypted match
await contract.computeMatch(articleId);

// 4. Get FHE handle
const handle = await contract.matchHandle(userAddress, articleId);

// 5. User decrypts privately
const matchResult = await sdk.userDecrypt({
  handle,
  contractAddress: contract.target,
});

console.log("Match:", matchResult); // true or false
```

---

# 🧭 Data Flow Diagram

```
       Publisher                         User
           │                               │
           ▼                               ▼
  publishArticle()                 createEncryptedInput()
           │                               │
           ▼                               ▼
 ┌──────────────────┐             setEncryptedInterest()
 │ SecretNewsMatcher │                      │
 └──────────────────┘                      ▼
           │                       encrypted interests stored
           │                               │
computeMatch(articleId)                    │
           │                               │
           ▼                               │
   encrypted ebool result                  │
           │                               │
           ▼                               │
matchHandle(user, article) → encrypted handle
           │                               │
           ▼                               ▼
      userDecrypt(handle)  →  plaintext true/false only to the user
```

---

# 🚀 Deployment

### Install dependencies

```
npm install
```

### Compile contracts

```
npx hardhat compile
```

### Run tests

```
npx hardhat test
```

### Deploy to Sepolia

```
npx hardhat run scripts/deploy.js --network sepolia
```

---

# 🔐 Security Notes

* Encrypted values (`euint32`, `ebool`) are never decrypted on-chain.
* Contract never performs FHE inside `view/pure` functions.
* Only approved addresses can access handles (`FHE.allow`).
* To publish match results, user must explicitly call:

  ```solidity
  makeMatchPublic(articleId)
  ```

# 📜 License

MIT License

---

# 📞 Contact

* Zama FHEVM Docs → [https://docs.zama.ai](https://docs.zama.ai)
* Relayer SDK → [https://docs.zama.ai/protocol/relayer-sdk-guides/](https://docs.zama.ai/protocol/relayer-sdk-guides/)
* Repository owner → [https://github.com/gyhwoodfly](https://github.com/gyhwoodfly)

