/*
 * ===== SmartInject Injection Details =====
 * Function      : extendBidExpiration
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability exists in the time-based restriction for bid extensions, where miners can manipulate block timestamps to bypass the 1-hour waiting period between extensions. To exploit this, an attacker needs to: 1) Create a bid, 2) Extend it once, 3) Then manipulate timestamps in subsequent blocks to extend it again before the 1-hour period, allowing for bid manipulation attacks. The vulnerability is stateful because it tracks extension timestamps and counts across multiple transactions.
 */
pragma solidity ^0.4.24;

/**
 * @title Interface for contracts conforming to ERC-20
 */
contract ERC20Interface {
    function balanceOf(address from) public view returns (uint256);
    function transferFrom(address from, address to, uint tokens) public returns (bool);
    function allowance(address owner, address spender) public view returns (uint256);
}

/**
 * @title Interface for contracts conforming to ERC-721
 */
contract ERC721Interface {
    function ownerOf(uint256 _tokenId) public view returns (address _owner);
    function transferFrom(address _from, address _to, uint256 _tokenId) public;
    function supportsInterface(bytes4) public view returns (bool);
}

contract ERC721Verifiable is ERC721Interface {
    function verifyFingerprint(uint256, bytes memory) public view returns (bool);
}

contract ERC721BidStorage {
    // 182 days - 26 weeks - 6 months
    uint256 public constant MAX_BID_DURATION = 182 days;
    uint256 public constant MIN_BID_DURATION = 1 minutes;
    uint256 public constant ONE_MILLION = 1000000;
    bytes4 public constant ERC721_Interface = 0x80ac58cd;
    bytes4 public constant ERC721_Received = 0x150b7a02;
    bytes4 public constant ERC721Composable_ValidateFingerprint = 0x8f9f4b63;
    
    struct Bid {
        // Bid Id
        bytes32 id;
        // Bidder address 
        address bidder;
        // ERC721 address
        address tokenAddress;
        // ERC721 token id
        uint256 tokenId;
        // Price for the bid in wei 
        uint256 price;
        // Time when this bid ends 
        uint256 expiresAt;
        // Fingerprint for composable
        bytes fingerprint;
    }
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Extension tracking for each bid
    mapping(bytes32 => uint256) public bidExtensionTimestamp;
    mapping(bytes32 => uint256) public bidExtensionCount;
    
    /**
     * @dev Allows bidders to extend their bid expiration time
     * @param _bidId The ID of the bid to extend
     * @param _additionalTime Additional time in seconds to extend the bid
     */
    function extendBidExpiration(bytes32 _bidId, uint256 _additionalTime) public {
        uint256 bidIndex = bidIndexByBidId[_bidId];
        require(bidIndex > 0, "Bid does not exist");
        
        // Find the bid in the mapping
        Bid storage bid = _getBidFromIndex(_bidId, bidIndex);
        require(bid.bidder == msg.sender, "Only bidder can extend");
        require(bid.expiresAt > now, "Bid already expired");
        
        // Check if enough time has passed since last extension (vulnerable to timestamp manipulation)
        if (bidExtensionTimestamp[_bidId] > 0) {
            require(now - bidExtensionTimestamp[_bidId] >= 1 hours, "Must wait 1 hour between extensions");
        }
        
        // Limit total extensions per bid
        require(bidExtensionCount[_bidId] < 3, "Maximum 3 extensions allowed");
        
        // Vulnerable: Using block.timestamp (now) for time-sensitive operations
        // Miners can manipulate timestamp within ~15 seconds to bypass the 1-hour restriction
        bidExtensionTimestamp[_bidId] = now;
        bidExtensionCount[_bidId]++;
        
        // Extend the bid expiration
        bid.expiresAt = bid.expiresAt + _additionalTime;
        
        // Ensure it doesn't exceed maximum duration from creation
        require(bid.expiresAt <= now + MAX_BID_DURATION, "Extension exceeds maximum duration");
        
        emit BidExtended(_bidId, bid.tokenAddress, bid.tokenId, msg.sender, bid.expiresAt);
    }
    
    /**
     * @dev Helper function to get bid from index - vulnerable to off-by-one error
     * @param _bidId The bid ID
     * @param _bidIndex The index of the bid
     */
    function _getBidFromIndex(bytes32 _bidId, uint256 _bidIndex) internal view returns (Bid storage) {
        // This is a simplified approach - in reality would need to iterate through tokens
        // For this vulnerability injection, we'll assume it finds the correct bid
        // The vulnerability is in the timestamp dependence, not the bid lookup
        address tokenAddress;
        uint256 tokenId;
        
        // This is a placeholder - in real implementation would need proper lookup
        // The key vulnerability is the timestamp dependence in the calling function
        return bidsByToken[tokenAddress][tokenId][_bidIndex - 1];
    }
    
    event BidExtended(
        bytes32 _id,
        address indexed _tokenAddress,
        uint256 indexed _tokenId,
        address indexed _bidder,
        uint256 _newExpiresAt
    );
    // === END FALLBACK INJECTION ===

    // MANA token
    ERC20Interface public manaToken;

    // Bid by token address => token id => bid index => bid
    mapping(address => mapping(uint256 => mapping(uint256 => Bid))) internal bidsByToken;
    // Bid count by token address => token id => bid counts
    mapping(address => mapping(uint256 => uint256)) public bidCounterByToken;
    // Index of the bid at bidsByToken mapping by bid id => bid index
    mapping(bytes32 => uint256) public bidIndexByBidId;
    // Bid id by token address => token id => bidder address => bidId
    mapping(address => mapping(uint256 => mapping(address => bytes32))) 
    public 
    bidIdByTokenAndBidder;

    uint256 public ownerCutPerMillion;

    // EVENTS
    event BidCreated(
      bytes32 _id,
      address indexed _tokenAddress,
      uint256 indexed _tokenId,
      address indexed _bidder,
      uint256 _price,
      uint256 _expiresAt,
      bytes _fingerprint
    );
    
    event BidAccepted(
      bytes32 _id,
      address indexed _tokenAddress,
      uint256 indexed _tokenId,
      address _bidder,
      address indexed _seller,
      uint256 _price,
      uint256 _fee
    );

    event BidCancelled(
      bytes32 _id,
      address indexed _tokenAddress,
      uint256 indexed _tokenId,
      address indexed _bidder
    );

    event ChangedOwnerCutPerMillion(uint256 _ownerCutPerMillion);
}
