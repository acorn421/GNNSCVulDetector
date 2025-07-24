/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback after balance updates. This allows malicious contracts to re-enter the transfer function during the callback, potentially draining tokens across multiple transaction sequences. The vulnerability requires accumulated state changes and multiple function calls to be exploitable, as the attacker needs to: 1) Deploy a malicious contract that implements tokenReceived(), 2) Trigger initial transfer to the malicious contract, 3) Use the callback to perform recursive transfers, and 4) Exploit the persistent state corruption across subsequent transactions. The balance state modifications persist between transactions, making this a true multi-transaction vulnerability where the effects compound over time.
 */
pragma solidity ^0.4.18;

// author: KK Coin team

contract ERC20Standard {
    // Balances for each account (added; needed for transfer logic)
    mapping(address => uint256) internal balances;
    
    // Get the total token supply
    function totalSupply() public constant returns (uint256 _totalSupply);
 
    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) public constant returns (uint256 balance);
 
    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _amount) public returns (bool) {
        if ( (balances[msg.sender] >= _amount) &&
             (_amount >= 0) && 
             (balances[_to] + _amount > balances[_to]) ) {  

            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient if it's a contract (potential reentrancy point)
            uint size;
            assembly {
                size := extcodesize(_to)
            }
            if (size > 0) {
                bool success = _to.call(abi.encodeWithSignature("tokenReceived(address,uint256)", msg.sender, _amount));
                // Continue regardless of callback success for compatibility
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
    
    // transfer _value amount of token approved by address _from
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

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

    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) private allowed;

    /// @dev Constructor
    constructor() public {
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