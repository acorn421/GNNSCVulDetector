/*
 * ===== SmartInject Injection Details =====
 * Function      : deleteToken
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires multiple function calls to exploit. The vulnerability combines time-based deletion delays with block-based rate limiting that can be manipulated through timestamp control.
 * 
 * **Key Vulnerability Components:**
 * 
 * 1. **Multi-Transaction Requirement**: Token deletion now requires two separate transactions - first to initiate the deletion request, second to complete it after a 24-hour delay.
 * 
 * 2. **Timestamp-Dependent Logic**: Uses `block.timestamp` for:
 *    - Tracking deletion request initiation time
 *    - Enforcing minimum 24-hour delay between request and execution
 *    - Bypassing rate limits when timestamps match (vulnerable condition)
 * 
 * 3. **State Persistence**: Maintains deletion state across transactions using:
 *    - `tokenDeletionRequests` mapping to track pending deletions
 *    - `tokenDeletionStartTime` mapping to store request timestamps
 *    - `deletionResetBlock` and `deletionsInCurrentPeriod` for rate limiting
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * 1. **Transaction 1**: Attacker calls `deleteToken(tokenId)` to initiate deletion request, storing `block.timestamp` in state
 * 2. **Transaction 2+**: Attacker waits or manipulates block conditions to call `deleteToken(tokenId)` again under favorable timestamp conditions
 * 3. **Exploitation**: By controlling block timestamps (miner capability), attacker can bypass rate limiting when `block.timestamp == tokenDeletionStartTime[_tokenId]`
 * 
 * **Why Multi-Transaction is Required:**
 * - First transaction only sets up the deletion request and exits early
 * - Second transaction performs the actual deletion but depends on state from first transaction
 * - The vulnerability emerges from the interaction between these two transactions and timestamp manipulation
 * - Single-transaction exploitation is impossible due to the early return in the first request
 * 
 * **Realistic Vulnerability Pattern:**
 * This mirrors real-world patterns where contracts implement time-based delays for security but rely on manipulable block properties, creating windows for exploitation across multiple transactions.
 */
pragma solidity ^0.4.23;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
    address public owner;


    event OwnershipRenounced(address indexed previousOwner);
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );


    /**
    * @dev The Ownable constructor sets the original `owner` of the contract to the sender
    * account.
    */
    constructor() public {
        owner = msg.sender;
    }

    /**
    * @dev Throws if called by any account other than the owner.
    */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    /**
    * @dev Allows the current owner to relinquish control of the contract.
    * @notice Renouncing to ownership will leave the contract without an owner.
    * It will not be possible to call the functions with the `onlyOwner`
    * modifier anymore.
    */
    function renounceOwnership() public onlyOwner {
        emit OwnershipRenounced(owner);
        owner = address(0);
    }

    /**
    * @dev Allows the current owner to transfer control of the contract to a newOwner.
    * @param _newOwner The address to transfer ownership to.
    */
    function transferOwnership(address _newOwner) public onlyOwner {
        _transferOwnership(_newOwner);
    }

    /**
    * @dev Transfers control of the contract to a newOwner.
    * @param _newOwner The address to transfer ownership to.
    */
    function _transferOwnership(address _newOwner) internal {
        require(_newOwner != address(0));
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
}


/** @title Restricted
 *  Exposes onlyMonetha modifier
 */
contract Restricted is Ownable {

    event MonethaAddressSet(
        address _address,
        bool _isMonethaAddress
    );

    mapping (address => bool) public isMonethaAddress;

    /**
     *  Restrict methods in such way, that they can be invoked only by monethaAddress account.
     */
    modifier onlyMonetha() {
        require(isMonethaAddress[msg.sender]);
        _;
    }

    /**
     *  Allows owner to set new monetha address
     */
    function setMonethaAddress(address _address, bool _isMonethaAddress) onlyOwner public {
        isMonethaAddress[_address] = _isMonethaAddress;

        MonethaAddressSet(_address, _isMonethaAddress);
    }
}


/**
 *  @title MonethaSupportedTokens
 *
 *  MonethaSupportedTokens stores all erc20 token supported by Monetha
 */
contract MonethaSupportedTokens is Restricted {
    
    string constant VERSION = "0.1";
    
    struct Token {
        bytes32 token_acronym;
        address token_address;
    }
    
    mapping (uint => Token) public tokens;

    uint public tokenId;
    
    address[] private allAddresses;
    bytes32[] private allAccronym;
    
    function addToken(bytes32 _tokenAcronym, address _tokenAddress)
        external onlyMonetha
    {
        require(_tokenAddress != address(0));

        tokens[++tokenId] = Token({
            token_acronym: bytes32(_tokenAcronym),
            token_address: _tokenAddress
        });
        allAddresses.push(_tokenAddress);
        allAccronym.push(bytes32(_tokenAcronym));
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (uint => uint) public tokenDeletionRequests;
    mapping (uint => uint) public tokenDeletionStartTime;
    uint public constant DELETION_DELAY = 24 hours;
    uint public deletionResetBlock;
    uint public deletionsInCurrentPeriod;
    uint public constant MAX_DELETIONS_PER_PERIOD = 5;
    uint public constant DELETION_PERIOD_BLOCKS = 100;

    function deleteToken(uint _tokenId)
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        external onlyMonetha
    {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Multi-transaction vulnerability: Reset deletion counter based on block number
        if (block.number >= deletionResetBlock + DELETION_PERIOD_BLOCKS) {
            deletionResetBlock = block.number;
            deletionsInCurrentPeriod = 0;
        }
        
        // Check if this is the first deletion request for this token
        if (tokenDeletionRequests[_tokenId] == 0) {
            // First request - initiate deletion process with timestamp dependency
            tokenDeletionRequests[_tokenId] = block.timestamp;
            tokenDeletionStartTime[_tokenId] = block.timestamp;
            return; // Exit early, require second transaction
        }
        
        // Second+ request - check timing constraints using block.timestamp
        require(block.timestamp >= tokenDeletionStartTime[_tokenId] + DELETION_DELAY, "Deletion delay not met");
        
        // Vulnerable: Allow bypassing deletion limits if within same block timestamp
        if (block.timestamp == tokenDeletionStartTime[_tokenId]) {
            // Bypass rate limiting - vulnerable to timestamp manipulation
        } else {
            require(deletionsInCurrentPeriod < MAX_DELETIONS_PER_PERIOD, "Deletion limit exceeded");
            deletionsInCurrentPeriod++;
        }
        
        // Original deletion logic
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        tokens[_tokenId].token_address = tokens[tokenId].token_address;
        tokens[_tokenId].token_acronym = tokens[tokenId].token_acronym;

        uint len = allAddresses.length;
        allAddresses[_tokenId-1] = allAddresses[len-1];
        allAccronym[_tokenId-1] = allAccronym[len-1];
        allAddresses.length--;
        allAccronym.length--;
        delete tokens[tokenId];
        tokenId--;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Clean up deletion tracking
        delete tokenDeletionRequests[_tokenId];
        delete tokenDeletionStartTime[_tokenId];
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function getAll() external view returns (address[], bytes32[])
    {
        return (allAddresses, allAccronym);
    }
    
}