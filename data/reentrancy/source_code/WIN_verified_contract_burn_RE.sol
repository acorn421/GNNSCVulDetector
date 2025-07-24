/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a call to `IBurnRegistry(burnRegistry).notifyBurn(msg.sender, _value)` after the validation checks but before the critical state updates to `balanceOf` and `totalSupply`.
 * 
 * 2. **Created Reentrancy Window**: The external call occurs after balance validation but before state modifications, creating a vulnerable window where the contract's state hasn't been updated yet.
 * 
 * 3. **Preserved Function Logic**: The original burn functionality remains intact - tokens are still burned and events are emitted correctly.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `burn(100)` with 100 tokens
 * - Balance check passes (user has 100 tokens)
 * - External call to `burnRegistry.notifyBurn()` triggers attacker's malicious contract
 * - During reentrancy, attacker calls `burn(50)` again
 * - Second call sees unchanged balance (still 100 tokens) and passes validation
 * - Both burn operations complete, but total burned = 150 tokens from balance of 100
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker can repeat the process with remaining manipulated balance
 * - Each transaction accumulates more inconsistent state
 * - Multiple transactions allow building up significant token supply manipulation
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation**: Each reentrancy attack accumulates inconsistent state changes that compound over multiple transactions
 * 2. **Balance Dependency**: The vulnerability exploits the gap between balance validation and state updates, requiring multiple calls to build exploitable state
 * 3. **Registry Integration**: The external registry call creates a realistic business scenario where reentrancy naturally occurs across multiple burn operations
 * 4. **Compound Effect**: Single transaction reentrancy has limited impact, but multiple transactions with accumulated state changes can drain the entire token supply
 * 
 * **Realistic Business Context:**
 * The burn registry integration represents a common pattern where tokens need to be tracked externally for compliance, rewards, or governance purposes, making this a realistic vulnerability that could appear in production code.
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

interface IBurnRegistry {
    function notifyBurn(address _from, uint256 _value) external;
}

contract WIN {
    
    using SafeMath for uint256;
    
    uint256 constant private MAX_UINT256 = 2**256 - 1;

    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;
    address public burnRegistry;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check msg.sender's balance sufficiency:
    require(balanceOf[msg.sender] >= _value);           
        // Test positiveness of '_value':
    require(_value > 0); 
    
    // External call to burn registry for compliance tracking
    // This creates a reentrancy window before state updates
    if (burnRegistry != address(0)) {
        IBurnRegistry(burnRegistry).notifyBurn(msg.sender, _value);
    }
    
    balanceOf[msg.sender] = SafeMath.sub(balanceOf[msg.sender], _value);                    
    totalSupply = SafeMath.sub(totalSupply,_value);                              
    emit Burn(msg.sender, _value);
    return true;
}
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END ===== 
            
}
