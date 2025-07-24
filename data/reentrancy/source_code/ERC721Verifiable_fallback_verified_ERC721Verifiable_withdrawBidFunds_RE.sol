/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawBidFunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This introduces a multi-transaction reentrancy vulnerability where an attacker must first call requestWithdrawal() to set up the state, then call withdrawBidFunds() which contains the vulnerable external call before state updates. The vulnerability requires two separate transactions and maintains state between them through the withdrawalRequested and withdrawalAmount mappings. An attacker can exploit this by calling withdrawBidFunds() recursively before the state is cleared, potentially draining funds multiple times.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Mapping to track withdrawal requests (multi-transaction state)
    mapping(bytes32 => bool) public withdrawalRequested;
    mapping(bytes32 => uint256) public withdrawalAmount;
    
    /**
     * @dev Initiates withdrawal request for a cancelled/expired bid
     * @param _bidId The bid ID to withdraw funds for
     */
    function requestWithdrawal(bytes32 _bidId) public {
        uint256 bidIndex = bidIndexByBidId[_bidId];
        
        // Find the bid across all tokens (simplified lookup)
        //Bid memory bid;
        //bool found = false;
        
        // This creates a stateful condition - withdrawal must be requested first
        require(!withdrawalRequested[_bidId], "Withdrawal already requested");
        
        // Mark withdrawal as requested (state change)
        withdrawalRequested[_bidId] = true;
        withdrawalAmount[_bidId] = 100 ether; // Simplified amount for demo
        
        emit WithdrawalRequested(_bidId, msg.sender, withdrawalAmount[_bidId]);
    }
    
    /**
     * @dev Withdraws funds for a previously requested withdrawal
     * @param _bidId The bid ID to complete withdrawal for
     */
    function withdrawBidFunds(bytes32 _bidId) public {
        // Check if withdrawal was requested (stateful check)
        require(withdrawalRequested[_bidId], "Withdrawal not requested");
        require(withdrawalAmount[_bidId] > 0, "No funds to withdraw");
        
        uint256 amount = withdrawalAmount[_bidId];
        
        // VULNERABILITY: External call before state update
        // This creates a reentrancy vulnerability across multiple transactions
        if (msg.sender.call.value(amount)()) {
            // State updates after external call (vulnerable pattern)
            withdrawalRequested[_bidId] = false;
            withdrawalAmount[_bidId] = 0;
            
            emit WithdrawalCompleted(_bidId, msg.sender, amount);
        }
    }
    
    event WithdrawalRequested(bytes32 indexed _bidId, address indexed _bidder, uint256 _amount);
    event WithdrawalCompleted(bytes32 indexed _bidId, address indexed _bidder, uint256 _amount);
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