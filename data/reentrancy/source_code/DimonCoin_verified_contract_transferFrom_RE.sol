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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Fixed Logic Bugs**: Corrected the comparison operators in the original code (>= instead of <=, < instead of >) to make the function work properly first.
 * 
 * 2. **Added External Call Hook**: Introduced a recipient notification mechanism that calls `ITokenReceiver(_to).onTokenTransfer()` if the recipient is a contract address.
 * 
 * 3. **Moved Critical State Update**: The allowance update `allowed[_from][msg.sender] -= _value` was moved to AFTER the external call, creating a reentrancy window where the allowance hasn't been decremented yet.
 * 
 * 4. **Created Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: Attacker sets up allowance via `approve()` call
 *    - **Transaction 2**: Attacker calls `transferFrom()` with malicious recipient contract
 *    - **Reentrant Calls**: The recipient contract can call back into `transferFrom()` multiple times before the allowance is decremented, draining funds beyond the approved amount
 * 
 * The vulnerability is stateful because:
 * - It requires pre-existing allowance state from a previous transaction
 * - The reentrancy window exists due to persistent state inconsistency
 * - Multiple calls can exploit the same allowance before it's properly decremented
 * - Each reentrant call can transfer the full allowance amount since the decrement happens after the external call
 * 
 * This creates a realistic advanced token feature (recipient notifications) that introduces a subtle but critical reentrancy vulnerability requiring multiple transactions to exploit.
 */
pragma solidity ^0.4.16;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

// Minimal interface declaration for recipient contract to fix ITokenReceiver error
interface ITokenReceiver {
    function onTokenTransfer(address _from, uint256 _value, bytes data) external;
}

contract DimonCoin {
    
    address owner = msg.sender;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
    uint256 public totalSupply = 100000000 * 10**8;

    function name() constant returns (string) { return "DimonCoin"; }
    function symbol() constant returns (string) { return "FUD"; }
    function decimals() constant returns (uint8) { return 8; }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function DimonCoin() public {
        owner = msg.sender;
        balances[msg.sender] = totalSupply;
    }

    modifier onlyOwner { 
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }

    function getEthBalance(address _addr) constant returns(uint) {
        return _addr.balance;
    }

    function distributeFUD(address[] addresses, uint256 _value, uint256 _ethbal) onlyOwner {
         for (uint i = 0; i < addresses.length; i++) {
             if (getEthBalance(addresses[i]) < _ethbal) {
                 continue;
             }
             balances[owner] -= _value;
             balances[addresses[i]] += _value;
             Transfer(owner, addresses[i], _value);
         }
    }
    
    function balanceOf(address _owner) constant returns (uint256) {
         return balances[_owner];
    }

    // mitigates the ERC20 short address attack
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length >= size + 4);
        _;
    }
    
    function transfer(address _to, uint256 _value) onlyPayloadSize(2 * 32) returns (bool success) {

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) onlyPayloadSize(2 * 32) returns (bool success) {

        if (_value == 0) { return false; }
        
        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        bool sufficientFunds = fromBalance >= _value;
        bool sufficientAllowance = allowance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            Transfer(_from, _to, _value);
            
            // Notify recipient contract if it's a contract address
            uint length;
            assembly { length := extcodesize(_to) }
            if (length > 0) {
                ITokenReceiver(_to).onTokenTransfer(_from, _value, msg.data);
            }
            
            // State modification moved after external call - creates reentrancy window
            allowed[_from][msg.sender] -= _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        
        allowed[msg.sender][_spender] = _value;
        
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }


    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        require(msg.sender == owner);
        ForeignToken token = ForeignToken(_tokenContract);
        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

}