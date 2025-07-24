/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through the following mechanisms:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: Introduced `pendingOwner` and `pendingOwners` mapping to track ownership transfer state across transactions
 * 2. **External Call Before State Update**: Added a callback to the new owner contract using `newOwner.call()` before updating the `owner` state variable
 * 3. **Multi-Step Process**: Created a pending ownership mechanism that persists state between transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Legitimate owner calls `transferOwnership(attackerContract)` 
 * 2. **During TX 1**: The external call to `attackerContract.onOwnershipTransferred()` triggers
 * 3. **Reentrancy Attack**: The attacker's contract can reenter `transferOwnership` or other `onlyOwner` functions while:
 *    - The original owner is still set in storage
 *    - But the pending ownership state indicates transfer is in progress
 *    - The attacker can exploit this intermediate state across multiple calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to have a contract deployed that implements the callback
 * - The attacker needs to first become a pending owner through legitimate means
 * - During the callback, they can make additional calls to exploit the inconsistent state
 * - The state persistence (`pendingOwners` mapping) allows the vulnerability to span multiple transactions
 * - The attacker could potentially call other `onlyOwner` functions during reentrancy or manipulate the pending state
 * 
 * **Realistic Integration:**
 * - Owner notification callbacks are common in ownership transfer patterns
 * - The pending ownership mechanism appears as a safety feature
 * - The external call pattern mimics real-world implementations like OpenZeppelin's two-step ownership transfer
 */
pragma solidity ^0.4.18;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public pendingOwners;
    address public pendingOwner;

    function transferOwnership(address newOwner) onlyOwner public {
        require(newOwner != address(0));
        
        // Mark as pending owner for multi-step process
        pendingOwner = newOwner;
        pendingOwners[newOwner] = true;
        
        // External call to notify new owner before state finalization
        // Replacing 'newOwner.code.length > 0' (not available in 0.4.18)
        if (isContract(newOwner)) {
            // This external call creates reentrancy opportunity
            (bool success,) = newOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", owner));
            require(success, "Ownership notification failed");
        }
        
        // State update happens after external call - vulnerable pattern
        owner = newOwner;
        
        // Clean up pending state
        pendingOwners[newOwner] = false;
        pendingOwner = address(0);
    }

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract SoundTribeToken is owned{
    // Public variables
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // Balances array
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    //ERC20 events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Sound Tribe Token"; 
        symbol = "STS9";
        decimals = 18;
    }

    /**
     * ERC20 balance function
     */
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balanceOf[_owner];
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
        // Failsafe logic that should never be false
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender the address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender the address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

}

contract AdvSoundTribeToken is owned, SoundTribeToken {
    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply
    ) SoundTribeToken(initialSupply) public {}

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);               // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Create `mintedAmount` tokens and send it to `target`
    /// @param target Address to receive the tokens
    /// @param mintedAmount the amount of tokens it will receive
    function mintToken(address target, uint256 mintedAmount) onlyOwner public {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, this, mintedAmount);
        Transfer(this, target, mintedAmount);
    }
}
