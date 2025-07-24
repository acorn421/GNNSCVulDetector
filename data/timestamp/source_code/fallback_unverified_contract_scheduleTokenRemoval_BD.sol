/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTokenRemoval
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
 * This vulnerability introduces timestamp dependence in a multi-transaction token removal system. The scheduleTokenRemoval function uses block.timestamp to set a future removal time, and executeScheduledRemoval relies on block.timestamp to enforce the delay. Miners can manipulate timestamps within a 15-second window, allowing them to potentially execute scheduled removals earlier than intended. The vulnerability is stateful because it requires: 1) First transaction to schedule removal with a timestamp, 2) State persistence of the scheduled time, 3) Second transaction to execute removal based on timestamp comparison. This creates a multi-transaction attack surface where malicious miners can manipulate the timing of token removals.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(uint => uint) public tokenRemovalSchedule;
    
    /**
     * @dev Schedules a token for removal after a delay period
     * @param _tokenId The ID of the token to schedule for removal
     * @param _delayHours Hours to wait before token can be removed
     */
    function scheduleTokenRemoval(uint _tokenId, uint _delayHours) external onlyMonetha {
        require(tokens[_tokenId].token_address != address(0));
        require(_delayHours > 0);
        
        // Vulnerable: Using block.timestamp for time-dependent logic
        uint removalTime = block.timestamp + (_delayHours * 1 hours);
        tokenRemovalSchedule[_tokenId] = removalTime;
    }
    
    /**
     * @dev Executes the scheduled removal of a token
     * @param _tokenId The ID of the token to remove
     */
    function executeScheduledRemoval(uint _tokenId) external onlyMonetha {
        require(tokenRemovalSchedule[_tokenId] != 0);
        
        // Vulnerable: Relying on block.timestamp for access control
        require(block.timestamp >= tokenRemovalSchedule[_tokenId]);
        
        // Remove the token
        tokens[_tokenId].token_address = tokens[tokenId].token_address;
        tokens[_tokenId].token_acronym = tokens[tokenId].token_acronym;

        uint len = allAddresses.length;
        allAddresses[_tokenId-1] = allAddresses[len-1];
        allAccronym[_tokenId-1] = allAccronym[len-1];
        allAddresses.length--;
        allAccronym.length--;
        delete tokens[tokenId];
        tokenId--;
        
        // Clear the schedule
        delete tokenRemovalSchedule[_tokenId];
    }
    // === END FALLBACK INJECTION ===

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
