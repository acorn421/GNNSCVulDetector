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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance. The vulnerability is stateful because:
 * 
 * 1. **State Persistence**: The allowance mapping (allowed[_from][msg.sender]) persists between transactions and is only updated after the external call
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls transferFrom, balance updates occur, external call is made to malicious contract
 *    - Transaction 2: Malicious contract can call transferFrom again with the same allowance since it hasn't been decremented yet
 *    - The persistent allowance state enables multiple withdrawals across separate transactions
 * 
 * 3. **Exploitation Scenario**:
 *    - Setup: User approves attacker contract for 100 tokens
 *    - Transaction 1: Attacker calls transferFrom(user, attackerContract, 100), balances update, external call triggers
 *    - In the callback: Attacker cannot immediately re-enter due to gas limits and transaction boundaries
 *    - Transaction 2: Attacker calls transferFrom again with the same 100 token allowance (not yet decremented)
 *    - Result: Attacker drains more tokens than approved across multiple transactions
 * 
 * 4. **Why Multi-Transaction**: The vulnerability requires multiple transactions because the allowance state persists between calls, and the external call creates a window where the allowance hasn't been properly decremented, enabling repeated exploitation across transaction boundaries.
 */
pragma solidity ^0.4.15;

contract SolidusToken {

    address owner = msg.sender;

    bool public purchasingAllowed = true;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;
    uint256 public totalSupply = 0;
    uint256 public totalBalancingTokens = 0;
    uint256 public tokenMultiplier = 600;

    function name() constant returns (string) { return "Solidus"; }
    function symbol() constant returns (string) { return "SOL"; }
    function decimals() constant returns (uint8) { return 18; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        require(_to != 0x0);                               
        require(balances[msg.sender] >= _value);           
        require(balances[_to] + _value > balances[_to]); 
        balances[msg.sender] -= _value;                     
        balances[_to] += _value;                            
        emit Transfer(msg.sender, _to, _value);                  
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require(_to != 0x0);                                
        require(balances[_from] >= _value);                 
        require(balances[_to] + _value > balances[_to]);  
        require(_value <= allowed[_from][msg.sender]);    
        balances[_from] -= _value;                        
        balances[_to] += _value;                          
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Multi-transaction vulnerability: External call before allowance update
        // This enables stateful reentrancy across multiple transactions
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        if (_value != 0 && allowed[msg.sender][_spender] != 0) {return false;}
        
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function enablePurchasing() {
        require(msg.sender == owner);
        purchasingAllowed = true;
    }

    function disablePurchasing() {
        require(msg.sender == owner);
        purchasingAllowed = false;
    }

    function getStats() constant returns (uint256, uint256, uint256, uint256, bool) {
        return (totalContribution, totalSupply, totalBalancingTokens, tokenMultiplier, purchasingAllowed);
    }

    function halfMultiplier() {
        require(msg.sender == owner);
        tokenMultiplier /= 2;
    }

    function burn(uint256 _value) returns (bool success) {
        require(msg.sender == owner);
        require(balances[msg.sender] > _value);
        balances[msg.sender] -= _value;
        totalBalancingTokens -= _value;
        totalSupply -= _value;  
        return true;
    }

    function() payable {
        require(purchasingAllowed);
        
        if (msg.value == 0) {return;}

        owner.transfer(msg.value);
        totalContribution += msg.value;

        uint256 tokensIssued = (msg.value * tokenMultiplier);
        
        totalSupply += tokensIssued*2;
        totalBalancingTokens += tokensIssued;

        balances[msg.sender] += tokensIssued;
        balances[owner] += tokensIssued;
        
        emit Transfer(address(this), msg.sender, tokensIssued);
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
