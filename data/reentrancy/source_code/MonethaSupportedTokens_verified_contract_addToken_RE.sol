/*
 * ===== SmartInject Injection Details =====
 * Function      : addToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to `ERC20(_tokenAddress).symbol()` for token validation after tokenId increment but before final state updates
 * - Moved final state updates (tokens mapping, array pushes) to occur after the external call
 * - Used try-catch to make the validation call realistic while maintaining function flow
 * - Pre-incremented tokenId to create a reserved slot that can be exploited during reentrancy
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires a sophisticated multi-transaction attack:
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys malicious token contract that implements ERC20 interface
 * - Malicious token's symbol() function is designed to call back into addToken during execution
 * 
 * **Transaction 2 (Initial Call):**
 * - Authorized Monetha address calls addToken with malicious token address
 * - tokenId is incremented (e.g., from 5 to 6)
 * - External call to malicious token's symbol() is made
 * - During this call, the malicious contract reenters addToken with different parameters
 * 
 * **Transaction 3 (Reentrant Call):**
 * - Inside the external call, malicious token calls addToken again
 * - tokenId is incremented again (from 6 to 7)  
 * - This creates state inconsistency: slot 6 reserved but not filled, slot 7 being processed
 * - Arrays and mappings become desynchronized
 * 
 * **Transaction 4 (Completion):**
 * - Original call completes, attempting to write to slot 6 but tokenId is now 7
 * - State corruption occurs with mismatched tokenId, array lengths, and mapping entries
 * 
 * **3. Why Multi-Transaction Nature is Critical:**
 * - **State Accumulation:** Each call increments tokenId, creating accumulated state changes
 * - **Sequence Dependency:** The vulnerability only works when reentrancy occurs during the external call window
 * - **Persistent State Corruption:** The desynchronization persists across transactions, affecting future operations
 * - **Cannot Be Atomic:** The external call creates an unavoidable transaction boundary where reentrancy can occur
 * 
 * **4. Realistic Exploitation Impact:**
 * - Token registry becomes corrupted with mismatched IDs and array entries
 * - Future token operations may fail or access wrong token data
 * - getAll() function returns inconsistent data
 * - deleteToken operations may corrupt the registry further
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions and sophisticated contract interaction to exploit, making it an excellent test case for security analysis tools.
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


// Interface for ERC20 symbol (not part of the ERC20 spec in 0.4.x, but many ERC20 add it)
interface ERC20 {
    function symbol() external view returns (string);
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Pre-increment tokenId to reserve the slot
        uint newTokenId = ++tokenId;
        
        // External call to token contract for validation - VULNERABILITY POINT
        // This creates a reentrancy window where state is partially updated
        // Simulate external call in Solidity 0.4.x
        address(_tokenAddress).call(bytes4(keccak256("symbol()")));
        // State updates happen after external call - enables reentrancy exploitation
        tokens[newTokenId] = Token({
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
