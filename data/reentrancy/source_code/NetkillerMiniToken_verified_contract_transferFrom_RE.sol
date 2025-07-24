/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient notification hook (onTokenReceived) before updating the allowance state. This creates a Check-Effects-Interactions (CEI) pattern violation where the allowance state remains unchanged during the external call, enabling multi-transaction exploitation scenarios.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `ITokenReceiver(_to).onTokenReceived(_from, _value)` for contract recipients
 * 2. Moved the allowance update (`allowance[_from][msg.sender] -= _value`) to AFTER the external call
 * 3. This creates a window where the allowance state is inconsistent with the actual token transfer
 * 
 * **Multi-Transaction Exploitation Pathway:**
 * 1. **Transaction 1**: Attacker obtains allowance approval from victim
 * 2. **Transaction 2**: Attacker calls transferFrom, which triggers the external call to their malicious contract
 * 3. **During External Call**: Malicious contract can call transferFrom again since allowance hasn't been updated yet
 * 4. **Transaction 3+**: Reentrant calls can drain additional tokens before allowance is properly decremented
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first obtain allowance permissions in a separate transaction
 * - The reentrancy exploitation requires the external call to be made to a contract the attacker controls
 * - The stateful nature means the allowance persists between transactions, enabling gradual exploitation
 * - Cannot be exploited atomically - requires building up allowance state and then exploiting it across multiple calls
 * 
 * This vulnerability is realistic as token recipient notifications are common in modern token standards, and the subtle ordering of state updates makes it a genuine security flaw that could appear in production code.
 */
pragma solidity ^0.4.24;

/******************************************/
/*       Netkiller Mini TOKEN             */
/******************************************/
/* Author netkiller <netkiller@msn.com>   */
/* Home http://www.netkiller.cn           */
/* Version 2018-05-31 Fixed transfer bool */
/******************************************/

interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value) external;
}

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer tokens first
        _transfer(_from, _to, _value);
        
        // Notify recipient if it's a contract - external call before state update
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }
        
        // Update allowance AFTER external call (CEI pattern violation)
        allowance[_from][msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Helper function for determining if _to is a contract in Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
