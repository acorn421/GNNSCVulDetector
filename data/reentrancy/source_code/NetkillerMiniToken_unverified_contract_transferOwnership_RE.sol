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
 * **Changes Made:**
 * 1. Added an external call to notify the new owner via `onOwnershipTransferred(address)` callback
 * 2. The external call is made BEFORE the state update (`owner = newOwner`)
 * 3. Used low-level `.call()` to invoke the callback, which allows reentrancy
 * 4. Added a require statement to ensure the callback succeeds
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onOwnershipTransferred(address)` function
 * - Current owner calls `transferOwnership(maliciousContract)`
 * - During the external call, malicious contract's `onOwnershipTransferred` is triggered
 * - Since `owner` hasn't been updated yet, the malicious contract can call `transferOwnership` again
 * - The malicious contract can transfer ownership to another attacker-controlled address
 * 
 * **Transaction 2 (Exploitation):**
 * - The attacker now has control through the secondary address set in Transaction 1
 * - The attacker can call any `onlyOwner` functions to drain tokens, mint tokens, or perform other privileged operations
 * - The original owner believes they transferred ownership to the malicious contract, but control actually went to the attacker's secondary address
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability relies on the intermediate state where the external call is made but `owner` hasn't been updated yet
 * 2. **Persistent State Changes**: The ownership change persists between transactions, enabling future exploitation
 * 3. **Sequence Dependency**: The exploit requires a specific sequence: initial transfer call → reentrancy during callback → secondary ownership transfer → subsequent privileged operations
 * 4. **Cross-Transaction Impact**: The compromised ownership state from Transaction 1 enables unlimited exploitation in all future transactions
 * 
 * This creates a realistic, stateful vulnerability where the attacker gains persistent control over the contract through a multi-step reentrancy attack.
 */
pragma solidity ^0.4.24;

/******************************************/
/*       Netkiller Mini TOKEN             */
/******************************************/
/* Author netkiller <netkiller@msn.com>   */
/* Home http://www.netkiller.cn           */
/* Version 2018-05-31 Fixed transfer bool */
/******************************************/

contract NetkillerMiniToken {
    address public owner;
    // Public variables of the token
    string public name;
    string public symbol;
    uint public decimals;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint decimalUnits
    ) public {
        owner = msg.sender;
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol; 
        decimals = decimalUnits;
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial token
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify the new owner before state update (vulnerable to reentrancy)
            if (extcodesize(newOwner) > 0) {
                (bool success,) = newOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", msg.sender));
                require(success, "Ownership notification failed");
            }
            // State update happens after external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            owner = newOwner;
        }
    }
 
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);               // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        emit Transfer(_from, _to, _value);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public returns (bool success){
        _transfer(msg.sender, _to, _value);
        return true;
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
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // Inline assembly function for extcodesize to check if an address is a contract
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
