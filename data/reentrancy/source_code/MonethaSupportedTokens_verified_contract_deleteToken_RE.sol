/*
 * ===== SmartInject Injection Details =====
 * Function      : deleteToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token contract before state cleanup operations. This violates the Checks-Effects-Interactions (CEI) pattern and creates a window for reentrancy attacks.
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. **Added External Call**: Introduced `tokenAddress.call(abi.encodeWithSignature("onTokenDeleted(uint256)", _tokenId))` to notify the token contract about pending deletion
 * 2. **Timing Violation**: Placed this external call BEFORE the state cleanup operations, violating the CEI pattern
 * 3. **State Window**: Created a time window where the token still exists in the contract's state during the external call
 * 
 * **MULTI-TRANSACTION EXPLOITATION PATTERN:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker deploys a malicious token contract with an `onTokenDeleted` function
 * - Attacker (if they have Monetha permissions) or convinces admin to add this token to the registry via `addToken`
 * 
 * **Transaction 2 (Exploitation Trigger):**
 * - Admin calls `deleteToken` on the malicious token
 * - During the external call to `onTokenDeleted`, the malicious token contract can reenter the MonethaSupportedTokens contract
 * - At this point, the token still exists in all data structures (tokens mapping, allAddresses, allAccronym arrays)
 * 
 * **Transaction 3 (Reentrant Exploitation):**
 * - The malicious token's `onTokenDeleted` function calls back into MonethaSupportedTokens
 * - It can call `getAll()` to retrieve token information that should be deleted
 * - It can potentially call other functions that depend on the token's existence
 * - The token exists in an inconsistent state where it's "being deleted" but still present
 * 
 * **Transaction 4 (State Corruption):**
 * - After reentrancy, the original deletion continues
 * - State becomes corrupted due to the interference during deletion
 * - Array indices may be misaligned, tokenId counter may be incorrect
 * 
 * **WHY MULTI-TRANSACTION DEPENDENCY IS REQUIRED:**
 * 1. **State Accumulation**: The vulnerability depends on tokens being added to the registry in prior transactions
 * 2. **Permission Dependencies**: Requires Monetha permissions to be granted in earlier transactions
 * 3. **Malicious Contract Deployment**: Attacker must deploy and register malicious token contracts beforehand
 * 4. **Timing Window**: The vulnerability only exists during the specific window when external call is made but state hasn't been cleaned up yet
 * 5. **Persistent State Effects**: The corruption persists across transactions, affecting future operations
 * 
 * This creates a realistic, stateful vulnerability that mirrors real-world reentrancy patterns where external calls during state transitions create exploitation opportunities that accumulate over multiple transactions.
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
    
    function deleteToken(uint _tokenId)
        external onlyMonetha
    {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store token address before deletion for notification
        address tokenAddress = tokens[_tokenId].token_address;
        
        // VULNERABILITY: External call before state cleanup - allows reentrancy
        // This notifies the token contract about pending deletion
        if (tokenAddress != address(0)) {
            // Low-level call to avoid compilation issues with interface
            tokenAddress.call(abi.encodeWithSignature("onTokenDeleted(uint256)", _tokenId));
        }
        
        // Original state modifications - now happen AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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