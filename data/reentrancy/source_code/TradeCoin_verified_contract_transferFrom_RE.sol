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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before Critical State Update**: Inserted a callback to the recipient address (`_to.call(...)`) that occurs AFTER balance updates but BEFORE the allowance is decremented. This creates a reentrancy window where the allowance hasn't been updated yet.
 * 
 * 2. **Stateful Exploitation Requirements**: 
 *    - **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`. The contract receives the callback and can immediately call `transferFrom()` again since the allowance hasn't been decremented yet.
 *    - **Transaction 2+**: The malicious contract can continue calling `transferFrom()` in a loop during the callback, draining tokens beyond the original allowance limit.
 * 
 * 3. **Multi-Transaction Nature**: The vulnerability requires multiple function calls within the same transaction context (initial call + reentrant calls), but the exploitation builds up state changes across these calls. The attacker must:
 *    - Deploy a malicious contract first (separate transaction)
 *    - Set up allowances (separate transaction)  
 *    - Execute the reentrancy attack (multiple nested calls within one transaction)
 *    - The accumulated effect drains more tokens than the allowance should permit
 * 
 * 4. **Realistic Implementation**: The callback mechanism appears legitimate - many DeFi protocols implement similar notification patterns for token recipients. The `onTokenReceived` callback is a common pattern in advanced token contracts.
 * 
 * 5. **Exploitation Scenario**:
 *    - Attacker gets approval for 100 tokens
 *    - Calls `transferFrom(victim, maliciousContract, 100)`
 *    - `maliciousContract.onTokenReceived()` is called
 *    - Inside callback, `maliciousContract` calls `transferFrom(victim, attacker, 100)` again
 *    - Since allowance wasn't decremented yet, this succeeds
 *    - Process repeats until victim's balance is drained
 *    - All within one transaction but multiple function calls exploit the stateful inconsistency
 */
pragma solidity ^0.4.18;
/*
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
    return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}


contract TradeCoin is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function TradeCoin(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public  {
        balanceOf[msg.sender] = initialSupply;              
        totalSupply = initialSupply;                        
        name = tokenName;                                   
        symbol = tokenSymbol;                               
        decimals = decimalUnits;                    
        owner = msg.sender;
    }


    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0)  revert();                               
        if (_value <= 0)  revert(); 
        if (balanceOf[msg.sender] < _value)  revert();           
        if (balanceOf[_to] + _value < balanceOf[_to])  revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                    
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                           
        emit Transfer(msg.sender, _to, _value);                  
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0)  revert();                                
        if (_value <= 0)  revert(); 
        if (balanceOf[_from] < _value)  revert();                 
        if (balanceOf[_to] + _value < balanceOf[_to])  revert();  
        if (_value > allowance[_from][msg.sender])  revert();     
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        
        // Notify recipient contract about incoming transfer (VULNERABLE: external call before allowance update)
        if (isContract(_to)) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            // Continue execution regardless of callback success
        }
        
        // Update allowance AFTER external call (VULNERABLE: reentrancy window)
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    // Helper function to check if address is a contract (since .code is not available in 0.4.x)
    function isContract(address _addr) internal view returns (bool result) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
