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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between balance updates and allowance reduction. The vulnerability creates a critical window where:
 * 
 * 1. **State Inconsistency Window**: After balances are updated but before allowances are reduced, the contract is in an inconsistent state
 * 2. **External Call Injection**: The onTokenReceived callback allows the recipient to execute arbitrary code during this inconsistent state
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls transferFrom, triggering the callback which can call transferFrom again using the same allowance (since it hasn't been reduced yet)
 *    - Transaction 2: The nested call succeeds because the allowance check passes, but the allowance is only reduced once
 *    - Result: Double spending using a single allowance approval
 * 
 * **Multi-Transaction Nature**: The vulnerability requires:
 * - Initial setup transaction to approve allowance
 * - Multiple coordinated transferFrom calls where the callback mechanism enables reentrancy
 * - The attack leverages persistent state (allowances) that aren't properly updated during the external call window
 * 
 * **Realistic Implementation**: The callback mechanism mimics legitimate token transfer hooks found in modern token standards, making the vulnerability subtle and realistic.
 */
pragma solidity ^0.4.21;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0); 
    uint256 c = a / b;
    return c;
  }
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

contract  IYFIMM {
   
    uint256 public totalSupply;

    function balanceOf(address _owner) public view returns (uint256 balance);

    function transfer(address _to, uint256 _value) public returns (bool success);

    // Fix: Declare balances, allowed and SafeMath usage so the function can reference them
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    
    using SafeMath for uint256;

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        uint256 allowanceVar = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowanceVar >= _value);
        require(_to != address(0));
        
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Transfer notification callback to recipient - potential reentrancy point
        // "code.length" does not exist in 0.4.21, use extcodesize instead
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // Use 'call' compatible with 0.4.x
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value); 
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success);

    function allowance(address _owner, address _spender) public view returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}


contract YFIMM is IYFIMM {
    using SafeMath for uint256;

    // mapping and event already inherited from IYFIMM

    string public name;                   
    uint8 public decimals;                
    string public symbol;                 

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               
        totalSupply = _initialAmount;                       
        name = _tokenName;                                  
        decimals = _decimalUnits;                            
        symbol = _tokenSymbol;                             
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0));
        require(balances[msg.sender] >= _value);
      
        balances[msg.sender] = balances[msg.sender].sub(_value);
  
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value); 
        return true;
    }

    // Reentrancy vulnerability fixed in interface only; here, keep the implementation safe as per instructions (implementation will be shadowed by the interface in this test case)
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowanceVar = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowanceVar >= _value);
        require(_to != address(0));
      
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value); 
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_spender != address(0));
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value); 
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        require(_spender != address(0));
        return allowed[_owner][_spender];
    }
}
