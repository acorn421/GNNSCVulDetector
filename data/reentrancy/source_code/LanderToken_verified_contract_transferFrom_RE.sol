/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract AFTER balance updates but BEFORE allowance updates. The vulnerability exploits the window where balances are updated but allowances haven't been decremented yet.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker approves themselves a large allowance from a victim account they control or have compromised
 * 2. **Transaction 2 (Initial Transfer)**: Attacker calls transferFrom() with their malicious contract as _to
 * 3. **During Transaction 2**: The onTokenReceived callback is triggered, allowing the attacker to call transferFrom() again while the original allowance hasn't been decremented yet
 * 4. **Transaction 3+ (Continued Exploitation)**: The attacker can continue the reentrancy chain, draining funds beyond the original allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires initial allowance setup in a separate transaction
 * - The reentrancy creates a chain of calls that accumulate state changes across the call stack
 * - Each reentrant call operates on the updated balance state but unchanged allowance state
 * - The exploit builds up across multiple nested calls, with each call transferring more tokens than should be allowed
 * 
 * **State Persistence Exploitation:**
 * - The allowance state persists between the initial external call and the reentrant calls
 * - Balance updates from earlier calls in the chain affect subsequent calls
 * - The vulnerability exploits the inconsistent state where balances are updated but allowances lag behind
 * 
 * This creates a realistic vulnerability pattern seen in tokens that implement recipient notifications without proper reentrancy protection.
 */
/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/

pragma solidity ^0.4.18;

contract ITokenRecipient {
    function onTokenReceived(address _from, uint256 _value, bytes data) public;
}

contract EIP20Interface {
    /// total amount of tokens
    uint256 public totalSupply;

    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    uint256 constant internal MAX_UINT256 = 2**256 - 1;
    // solhint-disable-next-line no-simple-event-func-name  
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) public view returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool success);

    /// @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient if it's a contract (ERC777-style hook)
        if (isContract(_to)) {
            // Note: Using blank bytes for data
            ITokenRecipient(_to).onTokenReceived(_from, _value, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }

    /// @notice `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of tokens to be approved for transfer
    /// @return Whether the approval was successful or not
    function approve(address _spender, uint256 _value) public returns (bool success);

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}

contract LanderToken is EIP20Interface {
    address owner = msg.sender;

    // MAX_UINT256, balances, allowed, and totalSupply already defined in base
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX
    uint price;
    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               // Give the creator all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
    /* function() public payable{
        if (price >=0 ether){
        uint toMint = 1000;
       
        totalSupply -= toMint;
        if (totalSupply>=6000000){
        balances[msg.sender] += toMint;
        Transfer(0,msg.sender, toMint);
        }
        if (totalSupply<6000000){
        throw;
        }
        }
       
       owner.transfer(msg.value);

     }
       */
       
}
