// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* Zama FHEVM */
import { FHE, ebool, euint32, externalEuint32 } from "@fhevm/solidity/lib/FHE.sol";
import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title SecretNewsMatcher — confidential interest-based news filtering
/// @notice
/// - Publishers register news with a public topic bitmask.
/// - Users register an encrypted interest bitmask (euint32).
/// - For any article, user can ask the contract to compute an encrypted flag:
///     hasMatch = ((interestMask & article.topicMask) != 0)
///   without revealing their interests.
/// - Frontend decrypts `hasMatch` off-chain via Relayer SDK (userDecrypt).
contract SecretNewsMatcher is ZamaEthereumConfig {
    using FHE for *;

    /* ─────────────────────────────────────
       Data model
       ───────────────────────────────────── */

    /// @dev Public description of a news article.
    struct Article {
        address publisher;   // who published the article
        uint32 topicMask;    // public bitmask of topics/categories
        string uri;          // e.g. IPFS / HTTPS URL with content/metadata
        bool   exists;
    }

    /// @dev Per-user encrypted profile: interest bitmask stored as euint32.
    struct InterestProfile {
        euint32 mask;        // encrypted bitmask of interests
        bool    set;         // profile is configured
    }

    /// @dev Result of a single "match" check: does this user care about this article?
    struct MatchCheck {
        address user;
        uint64  ts;
        ebool   hasMatch;    // true if (interestMask & topicMask) != 0
        bool    set;
    }

    /* ─────────────────────────────────────
       Storage
       ───────────────────────────────────── */

    uint256 public nextArticleId;

    // articleId => Article
    mapping(uint256 => Article) public articles;

    // user => encrypted interest profile
    mapping(address => InterestProfile) private profiles;

    // user => articleId => MatchCheck
    mapping(address => mapping(uint256 => MatchCheck)) public matchChecks;

    /* ─────────────────────────────────────
       Events
       ───────────────────────────────────── */

    event ArticlePublished(
        uint256 indexed articleId,
        address indexed publisher,
        uint32 topicMask,
        string uri
    );

    event ArticleUpdated(
        uint256 indexed articleId,
        uint32 topicMask,
        string uri
    );

    event InterestSet(address indexed user);

    event MatchComputed(
        address indexed user,
        uint256 indexed articleId,
        bytes32 resultHandle
    );

    event MatchAccessGranted(
        address indexed user,
        uint256 indexed articleId,
        address indexed to
    );

    event MatchMadePublic(
        address indexed user,
        uint256 indexed articleId
    );

    /* ─────────────────────────────────────
       Articles: public metadata & tags
       ───────────────────────────────────── */

    /// @notice Publish a new article with a public topic bitmask.
    /// @param uri Pointer to the article metadata/content (e.g. IPFS/HTTPS).
    /// @param topicMask Bitmask of topics (up to 32 flags).
    function publishArticle(
        string calldata uri,
        uint32 topicMask
    ) external returns (uint256 articleId) {
        articleId = nextArticleId++;
        articles[articleId] = Article({
            publisher: msg.sender,
            topicMask: topicMask,
            uri: uri,
            exists: true
        });

        emit ArticlePublished(articleId, msg.sender, topicMask, uri);
    }

    /// @notice Update article metadata and/or topic mask.
    /// @dev Only the original publisher can update.
    function updateArticle(
        uint256 articleId,
        string calldata uri,
        uint32 topicMask
    ) external {
        Article storage a = articles[articleId];
        require(a.exists, "article not found");
        require(a.publisher == msg.sender, "not publisher");

        a.topicMask = topicMask;
        a.uri = uri;

        emit ArticleUpdated(articleId, topicMask, uri);
    }

    /* ─────────────────────────────────────
       User encrypted interests
       ───────────────────────────────────── */

    /// @notice Set or update encrypted interest bitmask for msg.sender.
    /// @param encMask external encrypted bitmask (packed via Gateway).
    /// @param attestation ZK attestation from coprocessors (Gateway signatures).
    ///
    /// Frontend:
    /// - packs interest bitmask into externalEuint32 via Gateway
    /// - passes (encMask, attestation) into this function
    function setEncryptedInterest(
        externalEuint32 encMask,
        bytes calldata attestation
    ) external {
        // 1) Import external encrypted mask (type-checked & attested).
        euint32 mask = FHE.fromExternal(encMask, attestation);

        // 2) Persist in storage.
        profiles[msg.sender].mask = mask;
        profiles[msg.sender].set = true;

        // 3) ACL: contract + user must be able to use this ciphertext later.
        FHE.allowThis(mask);
        FHE.allow(mask, msg.sender);

        emit InterestSet(msg.sender);
    }

    /// @notice (Optional, for testing only) set interest mask in plaintext.
    /// @dev DO NOT USE in production: it reveals user interests to the contract.
    function setInterestPlain(uint32 plainMask) external {
        euint32 mask = FHE.asEuint32(plainMask);
        profiles[msg.sender].mask = mask;
        profiles[msg.sender].set = true;

        FHE.allowThis(mask);
        FHE.allow(mask, msg.sender);

        emit InterestSet(msg.sender);
    }

    /// @notice Check whether a profile is configured for a given user.
    function hasProfile(address user) external view returns (bool) {
        return profiles[user].set;
    }

    /* ─────────────────────────────────────
       Confidential matching: interests vs article topics
       ───────────────────────────────────── */

    /// @notice
    /// Compute encrypted match flag for (msg.sender, articleId):
    ///   hasMatch = ((interestMask & article.topicMask) != 0)
    ///
    /// @dev
    /// - Uses FHE.and + FHE.ne, no plaintext interests onchain.
    /// - Stores result in `matchChecks[msg.sender][articleId]`.
    /// - Grants access to the user and the contract itself.
    ///
    /// Frontend flow:
    /// 1) user tx => computeMatch(articleId)
    /// 2) read handle via matchHandle(msg.sender, articleId)
    /// 3) call userDecrypt(handle, ...) with Relayer SDK
    function computeMatch(uint256 articleId) external returns (bytes32 handle) {
        Article storage a = articles[articleId];
        require(a.exists, "article not found");

        InterestProfile storage p = profiles[msg.sender];
        require(p.set, "profile not set");

        // interestMask is encrypted (euint32)
        euint32 interestMask = p.mask;

        // public topicMask -> encrypted literal
        euint32 topicMaskEnc = FHE.asEuint32(a.topicMask);

        // intersection = interestMask & topicMask
        euint32 intersection = FHE.and(interestMask, topicMaskEnc);

        // hasMatch = (intersection != 0)
        ebool hasMatch = FHE.ne(intersection, FHE.asEuint32(0));

        // store result
        MatchCheck storage c = matchChecks[msg.sender][articleId];
        c.user = msg.sender;
        c.ts = uint64(block.timestamp);
        c.hasMatch = hasMatch;
        c.set = true;

        // ACL: contract + user can use / decrypt this flag
        FHE.allowThis(c.hasMatch);
        FHE.allow(c.hasMatch, msg.sender);

        handle = FHE.toBytes32(c.hasMatch);
        emit MatchComputed(msg.sender, articleId, handle);
    }

    /// @notice Get the FHE handle (bytes32) for a previously computed match.
    /// @dev Can be used by frontend with userDecrypt(...) for private decryption.
    function matchHandle(
        address user,
        uint256 articleId
    ) external view returns (bytes32) {
        MatchCheck storage c = matchChecks[user][articleId];
        require(c.set, "no match computed");
        return FHE.toBytes32(c.hasMatch);
    }

    /// @notice Grant another address the right to decrypt/use a match result.
    /// @dev
    /// - Can be called either by the user or the article publisher.
    /// - Typical use: let some backend / analytics contract see the result.
    function grantMatchAccess(
        address user,
        uint256 articleId,
        address to
    ) external {
        require(to != address(0), "bad addr");
        MatchCheck storage c = matchChecks[user][articleId];
        require(c.set, "no match");

        Article storage a = articles[articleId];
        require(
            msg.sender == user || msg.sender == a.publisher,
            "not allowed"
        );

        FHE.allow(c.hasMatch, to);
        emit MatchAccessGranted(user, articleId, to);
    }

    /// @notice Make a specific match result publicly decryptable by anyone.
    /// @dev Only the user themself can make their match result public.
    function makeMatchPublic(
        uint256 articleId
    ) external {
        MatchCheck storage c = matchChecks[msg.sender][articleId];
        require(c.set, "no match");
        FHE.makePubliclyDecryptable(c.hasMatch);
        emit MatchMadePublic(msg.sender, articleId);
    }
}
