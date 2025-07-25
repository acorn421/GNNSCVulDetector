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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: Initial approval - User approves a large allowance to an attacker contract
 * **Transaction 2**: Malicious transferFrom call - Attacker calls transferFrom, triggering the callback to a malicious recipient contract
 * **Transaction 3+**: Reentrancy exploitation - The malicious recipient contract re-enters transferFrom during the callback, exploiting the fact that allowances and balances haven't been updated yet
 * 
 * The vulnerability is stateful because:
 * 1. It depends on persistent allowance state from previous approve() transactions
 * 2. The allowance remains high during the callback, allowing multiple nested transfers
 * 3. Each nested call can transfer tokens before the allowance is decremented
 * 4. The accumulated effect across multiple reentrant calls drains more tokens than intended
 * 
 * This creates a realistic CEI (Checks-Effects-Interactions) pattern violation where external calls occur before critical state updates, enabling multi-transaction exploitation through the persistent allowance mechanism.
 */
pragma solidity ^0.4.18;

// author: KK Coin team

contract ERC20Standard {
    // Storage declarations added for balances and allowed
    mapping(address => uint256) internal balances;
    mapping(address => mapping(address => uint256)) internal allowed;

    // Get the total token supply
    function totalSupply() public constant returns (uint256 _totalSupply);
 
    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) public constant returns (uint256 balance);
 
    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _value) public returns (bool success);
    
    // transfer _value amount of token approved by address _from
    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient before state changes - creates reentrancy opportunity
            if (_isContract(_to)) {
                // Call recipient's onTokenReceived function if it exists
                _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _amount));
                // Continue regardless of callback success to maintain functionality
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function _isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    // approve an address with _value amount of tokens
    function approve(address _spender, uint256 _value) public returns (bool success);

    // get remaining token approved by _owner to _spender
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining);
  
    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
 
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract KKToken is ERC20Standard {
    string public constant symbol = "KK";
    string public constant name = "KKCOIN";
    uint256 public constant decimals = 8;

    uint256 public _totalSupply = 10 ** 18; // equal to 10^10 KK

    // Owner of this contract
    address public owner;

    // Balances KK for each account
    // (Now inherited and declared as internal in the parent)

    // Owner of account approves the transfer of an amount to another account
    // (Now inherited and declared as internal in the parent)

    /// @dev Constructor
    function KKToken() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
        Transfer(0x0, owner, _totalSupply);
    }

    /// @return Total supply
    function totalSupply() public constant returns (uint256) {
        return _totalSupply;
    }

    /// @return Account balance
    function balanceOf(address _addr) public constant returns (uint256) {
        return balances[_addr];
    }

    /// @return Transfer status
    function transfer(address _to, uint256 _amount) public returns (bool) {
        if ( (balances[msg.sender] >= _amount) &&
             (_amount >= 0) && 
             (balances[_to] + _amount > balances[_to]) ) {  

            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Send _value amount of tokens from address _from to address _to
    // these standardized APIs for approval:
    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    // get allowance
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
