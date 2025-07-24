/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Vulnerability Injection: Stateful Multi-Transaction Reentrancy**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call After State Updates**: Introduced a low-level call to `_to.call()` that executes after balance updates are complete
 * 2. **Token Receipt Callback**: Added a realistic callback mechanism `onTokenReceived(address,uint256)` that recipient contracts can implement
 * 3. **Conditional Execution**: Only executes the external call if the recipient is a contract (has code)
 * 4. **Preserved Functionality**: The function continues to work normally even if the external call fails
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys a malicious contract that implements `onTokenReceived()`
 * - The malicious contract's `onTokenReceived()` function calls back to `transfer()` with different parameters
 * - Initial transfer succeeds and triggers the callback
 * 
 * **Transaction 2+ (Exploitation)**:
 * - The callback from Transaction 1 triggers additional `transfer()` calls
 * - Each callback can trigger further nested transfers before the original call completes
 * - The attacker can drain funds by calling `transfer()` multiple times in a cascade
 * - State changes accumulate across the transaction sequence
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation**: The vulnerability exploits the fact that balance updates persist between callback executions
 * 2. **Callback Chain**: Each transfer can trigger callbacks that initiate new transfers, creating a chain reaction
 * 3. **Timing Dependency**: The exploit requires the external call to happen after state updates but before the transaction completes
 * 4. **Coordination Required**: The attacker must coordinate multiple contract calls through the callback mechanism
 * 
 * **Exploitation Example:**
 * ```solidity
 * // Attacker contract
 * contract AttackerContract {
 *     WIN token;
 *     address victim;
 *     
 *     function onTokenReceived(address from, uint256 value) external {
 *         // Reentrant call - triggers another transfer
 *         if (token.balanceOf(victim) > 0) {
 *             token.transfer(address(this), token.balanceOf(victim));
 *         }
 *     }
 * }
 * ```
 * 
 * This creates a stateful, multi-transaction reentrancy where the attacker can drain funds through coordinated callback-driven transfers that accumulate state changes across multiple function executions.
 */
pragma solidity ^0.4.18;

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

contract WIN {
    
    using SafeMath for uint256;
    
    uint256 constant private MAX_UINT256 = 2**256 - 1;

    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    // event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed _from, uint256 value);

    constructor(uint256 _initialSupply, string _tokenName, uint8 _decimalUnits, string _tokenSymbol) public {
        name = _tokenName;                                   
        symbol = _tokenSymbol;
        decimals = _decimalUnits;                            
        totalSupply = _initialSupply;                        
        balanceOf[msg.sender] = _initialSupply;
        owner = msg.sender;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
            // Test validity of the address '_to':
        require(_to != 0x0);
            // Test positiveness of '_value':
        require(_value > 0);
            // Check the balance of the sender:
        require(balanceOf[msg.sender] >= _value);
            // Check for overflows:
        require(balanceOf[_to] + _value >= balanceOf[_to]); 
            // Update balances of msg.sender and _to:
        balanceOf[msg.sender] = SafeMath.sub(balanceOf[msg.sender], _value);                     
        balanceOf[_to] = SafeMath.add(balanceOf[_to], _value);                            
        emit Transfer(msg.sender, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Stateful reentrancy vulnerability: external call after state updates
        // This allows recipient contracts to call back while state is inconsistent
        uint toCodeSize;
        assembly { toCodeSize := extcodesize(_to) }
        if (toCodeSize > 0) {
            // External call to recipient contract - enables reentrancy
            bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue regardless of call success to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
            // Test validity of the address '_to':
        require(_to != 0x0);
            // Test positiveness of '_value':
        require(_value > 0);
            // Check the balance of the sender:
        require(balanceOf[msg.sender] >= _value);
            // Check for overflows:
        require(balanceOf[_to] + _value >= balanceOf[_to]); 
            // Update balances of msg.sender and _to:
            // Check allowance's sufficiency:
        require(_value <= allowance[_from][msg.sender]);
            // Update balances of _from and _to:
        balanceOf[_from] = SafeMath.sub(balanceOf[_from], _value);                           
        balanceOf[_to] = SafeMath.add(balanceOf[_to], _value);
            // Update allowance:
        require(allowance[_from][msg.sender]  < MAX_UINT256);
        allowance[_from][msg.sender] = SafeMath.sub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
            // Test positiveness of '_value':
        require(_value > 0); 
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
            // Check msg.sender's balance sufficiency:
        require(balanceOf[msg.sender] >= _value);           
            // Test positiveness of '_value':
        require(_value > 0); 
        balanceOf[msg.sender] = SafeMath.sub(balanceOf[msg.sender], _value);                    
        totalSupply = SafeMath.sub(totalSupply,_value);                              
        emit Burn(msg.sender, _value);
        return true;
    }
            
}
