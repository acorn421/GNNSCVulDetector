/*
 * ===== SmartInject Injection Details =====
 * Function      : addToken
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that creates timing-based exploitation opportunities:
 * 
 * **Specific Changes Made:**
 * 1. **Time-based Registration Windows**: Added logic that only allows token registration during first 15 minutes of each hour using `block.timestamp % 3600`
 * 2. **Timestamp Storage**: Embedded registration timestamp in the upper 32 bits of the token_acronym field for persistent storage
 * 3. **Sequential Timing Validation**: Added requirement for minimum 1-minute gap between consecutive token registrations
 * 4. **Priority Boost System**: Tokens registered within first 5 minutes of hour get tokenId incremented by 2 instead of 1
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker (or colluding miner) registers first token during valid time window, establishing baseline timestamp
 * 2. **Transaction 2**: Attacker attempts to register second token but manipulates block.timestamp to either:
 *    - Skip the 1-minute waiting period by advancing timestamp
 *    - Gain priority boost by setting timestamp within first 5 minutes of hour
 *    - Bypass the 15-minute window restriction entirely
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * - The vulnerability requires at least 2 transactions because the timing validation depends on the timestamp stored from the previous token registration
 * - Single transaction exploitation is impossible because the timing check compares current `block.timestamp` with the stored timestamp from the previous token
 * - State persistence is crucial as the timestamp from previous registration is stored in the `tokens` mapping and used for validation in subsequent calls
 * - The exploit becomes more effective with multiple sequential registrations as attackers can manipulate the timing sequence across several transactions
 * 
 * **Exploitation Impact:**
 * - Miners can manipulate block timestamps to register tokens outside intended time windows
 * - Priority manipulation allows certain tokens to receive higher IDs than intended
 * - Sequential timing requirements can be bypassed, allowing rapid token registration spam
 * - The timestamp encoding in token_acronym creates data integrity issues when combined with timing manipulation
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based token registration window: only allow registration during first 15 minutes of each hour
        uint256 timeWindow = block.timestamp % 3600; // Get minutes within current hour
        require(timeWindow < 900, "Token registration only allowed in first 15 minutes of each hour");
        
        // Store registration timestamp for priority ordering
        uint256 registrationTime = block.timestamp;
        
        // If this is not the first token, check timing dependency
        if (tokenId > 0) {
            // Get the last token's registration time from the stored timestamp
            uint256 lastTokenTime = uint256(tokens[tokenId].token_acronym) >> 224; // Extract timestamp from previous token
            
            // Enforce minimum 1 minute gap between registrations to prevent spam
            require(registrationTime >= lastTokenTime + 60, "Must wait at least 1 minute between token registrations");
            
            // Priority boost: if registered within 5 minutes of hour start, increment tokenId by 2 instead of 1
            if (timeWindow < 300) {
                tokenId += 2;
            } else {
                tokenId++;
            }
        } else {
            tokenId++;
        }
        
        // Encode timestamp in the upper 32 bits of token_acronym for future validation
        bytes32 timestampedAcronym = bytes32((uint256(_tokenAcronym) & 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) | (registrationTime << 224));
        
        tokens[tokenId] = Token({
            token_acronym: timestampedAcronym,
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            token_address: _tokenAddress
        });
        allAddresses.push(_tokenAddress);
        allAccronym.push(bytes32(_tokenAcronym));
    }
    
    function deleteToken(uint _tokenId)
        external onlyMonetha
    {
        
        tokens[_tokenId].token_address = tokens[tokenId].token_address;
        tokens[_tokenId].token_acronym = tokens[tokenId].token_acronym;

        uint len = allAddresses.length;
        allAddresses[_tokenId-1] = allAddresses[len-1];
        allAccronym[_tokenId-1] = allAccronym[len-1];
        allAddresses.length--;
        allAccronym.length--;
        delete tokens[tokenId];
        tokenId--;
    }
    
    function getAll() external view returns (address[], bytes32[])
    {
        return (allAddresses, allAccronym);
    }
    
}