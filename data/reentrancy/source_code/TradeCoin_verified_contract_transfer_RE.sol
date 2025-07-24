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
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that notifies the recipient contract BEFORE state changes occur. The vulnerability is stateful because it relies on the accumulated balances from previous transactions, and multi-transaction because an attacker needs to:
 * 
 * 1. **Transaction 1**: Deploy a malicious contract that implements onTokenTransfer callback
 * 2. **Transaction 2**: First transfer call - during the callback, the malicious contract can call transfer again while the original sender's balance hasn't been updated yet
 * 3. **Transaction 3+**: Subsequent calls can exploit the inconsistent state accumulated across transactions
 * 
 * **Exploitation Process:**
 * - The attacker first accumulates tokens through normal transfers
 * - When transferring to their malicious contract, the callback is triggered BEFORE balance updates
 * - During the callback, the malicious contract can call transfer again, exploiting the unchanged balance state
 * - This requires multiple transactions to set up the attack state and execute the exploitation
 * - The vulnerability is stateful because it depends on the attacker's accumulated balance from previous legitimate transactions
 * 
 * The vulnerability is realistic as callback mechanisms for transfer notifications are common in modern token implementations, making this injection subtle and production-like.
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
        
        // Notify recipient before state changes (vulnerability injection)
        if (isContract(_to)) {
            bool success = _to.call(abi.encodeWithSignature("onTokenTransfer(address,uint256)", msg.sender, _value));
            if (!success) {
                // Continue with transfer even if notification fails
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                    
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                           
        Transfer(msg.sender, _to, _value);                  
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
