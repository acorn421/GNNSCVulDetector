/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawBidFunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This creates a stateful, multi-transaction reentrancy vulnerability where an attacker can: 1) Cancel multiple bids to accumulate funds in pendingWithdrawals, 2) Call withdrawBidFunds which makes an external call to manaToken.transferFrom before updating the state, 3) During the external call, reenter withdrawBidFunds to drain more funds than they should be able to. The vulnerability requires multiple transactions to set up (canceling bids) and then exploiting the reentrancy in the withdrawal function. The state persists between transactions in the pendingWithdrawals mapping.
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
    // Mapping to track withdrawal requests
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;
    
    /**
     * @dev Allows bidders to withdraw their failed bid funds
     * @param _amount Amount to withdraw
     */
    function withdrawBidFunds(uint256 _amount) public {
        require(pendingWithdrawals[msg.sender] >= _amount, "Insufficient funds");
        require(!withdrawalInProgress[msg.sender], "Withdrawal already in progress");
        
        withdrawalInProgress[msg.sender] = true;
        
        // External call before state update - vulnerable to reentrancy
        require(manaToken.transferFrom(address(this), msg.sender, _amount), "Transfer failed");
        
        // State update after external call - reentrancy vulnerability
        pendingWithdrawals[msg.sender] -= _amount;
        withdrawalInProgress[msg.sender] = false;
    }
    
    /**
     * @dev Internal function to add funds to pending withdrawals
     * @param _bidder Address of the bidder
     * @param _amount Amount to add to pending withdrawals
     */
    function _addPendingWithdrawal(address _bidder, uint256 _amount) internal {
        pendingWithdrawals[_bidder] += _amount;
    }
    
    /**
     * @dev Function to cancel a bid and add funds to pending withdrawals
     * @param _tokenAddress ERC721 token address
     * @param _tokenId Token ID
     */
    function cancelBidAndWithdraw(address _tokenAddress, uint256 _tokenId) public {
        bytes32 bidId = bidIdByTokenAndBidder[_tokenAddress][_tokenId][msg.sender];
        require(bidId != 0, "No bid found");
        
        uint256 bidIndex = bidIndexByBidId[bidId];
        Bid storage bid = bidsByToken[_tokenAddress][_tokenId][bidIndex];
        
        require(bid.bidder == msg.sender, "Not the bidder");
        require(bid.expiresAt > now, "Bid already expired");
        
        uint256 bidAmount = bid.price;
        
        // Clear the bid
        delete bidsByToken[_tokenAddress][_tokenId][bidIndex];
        delete bidIdByTokenAndBidder[_tokenAddress][_tokenId][msg.sender];
        delete bidIndexByBidId[bidId];
        
        // Add to pending withdrawals - this creates the multi-transaction vulnerability
        _addPendingWithdrawal(msg.sender, bidAmount);
        
        emit BidCancelled(bidId, _tokenAddress, _tokenId, msg.sender);
    }
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