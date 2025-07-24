/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient BEFORE updating balances. This creates a classic reentrancy scenario where:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokenReceived()` callback
 * 2. **Transaction 2 (Exploit)**: Victim calls `transfer()` to send tokens to the malicious contract:
 *    - Function checks victim's balance (e.g., 1000 tokens)
 *    - External call to malicious contract's `onTokenReceived()` 
 *    - Malicious contract re-enters `transfer()` function
 *    - Re-entrant call still sees original balance (1000 tokens) since state hasn't been updated yet
 *    - Attacker can drain multiple times the intended amount
 * 
 * **Why Multi-Transaction is Required:**
 * - **Transaction 1** is needed to deploy and set up the malicious contract with the callback
 * - **Transaction 2** triggers the actual exploit when victim transfers to the malicious contract
 * - The vulnerability leverages persistent state (balanceOf mapping) that exists between transactions
 * - The malicious contract's code must be deployed in a separate transaction before it can be exploited
 * 
 * **Stateful Nature:**
 * - The exploit depends on the persistent `balanceOf` state between transactions
 * - The malicious contract's deployment state from Transaction 1 enables the exploit in Transaction 2
 * - Each re-entrant call sees the same pre-update balance state, allowing accumulation of unauthorized transfers
 * 
 * This vulnerability is realistic as many token contracts implement recipient notifications, but placing the external call before state updates violates the checks-effects-interactions pattern and creates a critical security flaw.
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

    // Fixed: Changed from deprecated constructor style to 'constructor'
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient before updating balances (vulnerable to reentrancy)
        // Fixed: Use extcodesize to detect if _to is a contract in Solidity 0.4.x
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // (bool success, ) = _to.call(abi.encodeWithSignature(...)) is not available in 0.4.x, so use _to.call(...)
            // We must encode parameters by hand due to lack of abi.encodeWithSignature in 0.4.18
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,uint256)"));
            // _to.call must be used as (success) = _to.call( ... ) in 0.4.x.
            bool success = _to.call(selector, msg.sender, _value);
            require(success);
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                    
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                           
        Transfer(msg.sender, _to, _value);                  
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0)  revert();                                
		if (_value <= 0)  revert(); 
        if (balanceOf[_from] < _value)  revert();                 
        if (balanceOf[_to] + _value < balanceOf[_to])  revert();  
        if (_value > allowance[_from][msg.sender])  revert();     
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

}
