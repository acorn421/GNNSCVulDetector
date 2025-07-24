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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating the sender's balance and allowance. This creates a window where the same allowance can be exploited multiple times across different transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker gets approval for X tokens from victim
 * 2. **Transaction 2 (Initial transferFrom)**: Attacker calls transferFrom(victim, attackerContract, X)
 *    - Function checks allowance (X available) ✓
 *    - Updates recipient balance (attackerContract gets X tokens)
 *    - Makes external call to attackerContract.onTokenReceived()
 *    - **VULNERABILITY**: In the callback, attackerContract can call transferFrom again
 *    - During callback: allowed[victim][attacker] still shows X (not yet decremented)
 *    - During callback: balances[victim] still shows original amount (not yet decremented)
 *    - Attacker can drain more tokens than originally approved
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires persistent state (allowance) that was set in previous transactions
 * - The exploit leverages the fact that allowance persists across transactions
 * - A single transaction without prior allowance setup would fail the initial require check
 * - The attack pattern requires: Setup Transaction → Exploit Transaction(s) with nested calls
 * 
 * **State Dependencies:**
 * - Requires pre-existing allowance from previous approve() transaction
 * - Exploits the gap between external call and state updates within the same transaction
 * - The vulnerability compounds across multiple nested calls enabled by the persistent allowance state
 */
pragma solidity ^0.4.18;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ConoToken  {

    using SafeMath for uint256;
    
    uint256 public _totalSupply;
    
    uint256 public constant AMOUNT = 1000000000;    // initial amount of token
    
    string public constant symbol = "CONO";
    string public constant name = "Cono Coins";
    uint8 public constant decimals = 18; 
    string public version = '1.0';  

    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    address _contractCreator;
    
    function ConoToken(address owner) public {
        _contractCreator = owner;
        _totalSupply = AMOUNT * 1000000000000000000;
        balances[_contractCreator] = _totalSupply;
    }
     

    /// @return total amount of tokens
    function totalSupply() constant public returns (uint256) {
        return _totalSupply;
    }

    /// @param who The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address who) constant public returns (uint256){
        return balances[who];
    }

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool success) {
        
        require(_to != 0x00);
        //Default assumes totalSupply can't be over max (2^256 - 1).
        //If your token leaves out totalSupply and can issue more tokens as time goes on, you need to check if it doesn't wrap.
        //Replace the if with this one instead.
        //if (balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
        require(balances[msg.sender] >= _value && _value > 0 );
        require(balances[_to] + _value >= balances[_to]); // Check for overflows

        if (balances[msg.sender] >= _value && _value > 0) {
            //balances[msg.sender] -= _value;
            balances[msg.sender] = balances[msg.sender].sub(_value);
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);  // Log the Transaction
            return true;
        } else { return false; }
    }
        

    /// @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
         //same as above. Replace this line with the following if you want to protect against wrapping uints.
        //if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
        require(
            allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0
        );
        require(balances[_to] + _value >= balances[_to]); // Check for overflows
        
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract about the transfer (vulnerable external call)
            if (isContract(_to)) {
                // Call recipient contract before updating sender's balance and allowance
                _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
                // Continue regardless of call success to maintain backward compatibility
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    /// @notice `msg.sender` approves `_addr` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of wei to be approved for transfer
    /// @return Whether the approval was successful or not
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value); // Log the Transaction
        return true;
    }

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 
}
