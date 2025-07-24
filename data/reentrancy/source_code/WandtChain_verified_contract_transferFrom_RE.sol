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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address between balance updates and allowance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls transferFrom with a malicious contract as _to address
 * 2. **During Transaction 1**: The external call to _to.call() triggers the malicious contract's onTokenReceived function
 * 3. **Reentrancy**: The malicious contract re-enters transferFrom with the same _from address while allowance hasn't been updated yet
 * 4. **Transaction 2 (via reentrancy)**: The reentrant call can use the same allowance again because it hasn't been decremented yet
 * 5. **State Accumulation**: Multiple reentrant calls can drain the _from balance beyond the original allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the timing gap between balance updates and allowance updates
 * - Each reentrant call creates a new transaction context that can manipulate the persistent allowance state
 * - The exploit requires building up state through multiple function calls, not possible in a single atomic transaction
 * - The allowance checking happens at the beginning, but the allowance update happens after the external call, creating a window for exploitation across multiple calls
 * 
 * **Stateful Nature:**
 * - The allowance state persists between transactions and can be exploited multiple times
 * - Balance changes accumulate across reentrant calls
 * - The vulnerability requires the attacker to have previously obtained allowance (separate transaction) before exploitation
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


contract WandtChain is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(
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

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        if (_to == 0x0)  revert();                                
		if (_value <= 0)  revert(); 
        if (balanceOf[_from] < _value)  revert();                 
        if (balanceOf[_to] + _value < balanceOf[_to])  revert();  
        if (_value > allowance[_from][msg.sender])  revert();     
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Call recipient contract to notify of transfer (allows reentrancy)
        // _to.code.length is not available in 0.4.18, so we simulate EOA/contract distinction using 'extcodesize'
        uint256 codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            _to.call(
                abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value)
            );
            // Continue execution even if call fails
        }
        
        // Update allowance after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

}
