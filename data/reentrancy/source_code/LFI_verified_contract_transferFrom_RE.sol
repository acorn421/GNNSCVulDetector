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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added Pending Transfer Tracking**: Introduced `pendingTransferAmounts[_from]` mapping to track transfers in progress, creating persistent state between transactions.
 * 
 * 2. **External Call Before State Updates**: Added a call to `_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)` before balance updates, creating a reentrancy vector.
 * 
 * 3. **Moved State Updates After External Call**: The critical state updates (balances and allowances) now occur after the external call, violating the checks-effects-interactions pattern.
 * 
 * 4. **Pending Transfer Cleanup**: Added cleanup of pending transfers after successful completion, but this occurs after the vulnerable external call.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker creates a malicious contract and gets approval to spend tokens
 * - Attacker calls `approve()` to set allowance
 * - Sets up the initial state for the attack
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom()` with their malicious contract as `_to`
 * - The pending transfer amount is recorded in `pendingTransferAmounts`
 * - External call to malicious contract's `onTokenReceived()` function occurs
 * - Malicious contract can now see the pending transfer state and plan reentrancy
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - During the `onTokenReceived()` callback, the malicious contract calls `transferFrom()` again
 * - The pending transfer tracking shows accumulated transfer amounts
 * - Since state updates haven't occurred yet, the same tokens can be transferred multiple times
 * - Each reentrancy cycle accumulates more pending transfers before any balance updates occur
 * - The attacker can drain more tokens than their allowance should permit
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation**: The `pendingTransferAmounts` mapping accumulates state across multiple calls, enabling the attacker to track and exploit partial transfer states.
 * 
 * 2. **Allowance Manipulation**: The vulnerability requires multiple transactions to build up allowances and then exploit them through reentrancy cycles.
 * 
 * 3. **Callback Dependency**: The external call mechanism requires the recipient contract to be deployed and configured, which necessitates separate setup transactions.
 * 
 * 4. **Gradual Exploitation**: The attacker must gradually exploit the reentrancy across multiple calls to avoid detection and maximize token extraction.
 * 
 * 5. **State Persistence**: The vulnerability relies on persistent state changes between transactions, where pending transfers accumulate and can be exploited in subsequent calls.
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to set up and exploit, making it much more subtle and dangerous than single-transaction attacks.
 */
pragma solidity ^0.4.0;

contract Ownable { 
  address public owner;
  
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  constructor() public { 
    owner = msg.sender;
  }

  modifier onlyOwner() { 
    require(msg.sender == address(0xD21dc4f9a7bdb48dA1A5e8a9069d5AeAa802D092));
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner { 
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

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

    uint256 c = a / b;

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

contract LFI is Ownable { 
  string public name;
  string public symbol;
  uint8 public decimals;
  uint256 public totalSupply;
  
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);

  constructor(string _name, string _symbol, uint8 _decimals, uint256 _totalSupply) public { 
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply =  _totalSupply;
        balances[msg.sender] = totalSupply;
        allow[msg.sender] = true;
  }

  using SafeMath for uint256;

  mapping(address => uint256) public balances;
  
  mapping(address => bool) public allow;

  // Added mapping for pendingTransferAmounts as required in transferFrom
  mapping(address => mapping(address => uint256)) public pendingTransferAmounts;

  function transfer(address _to, uint256 _value) public returns (bool) { 
    require(_to != address(0));
    require(_value <= balances[msg.sender]);

    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    Transfer(msg.sender, _to, _value);
    return true;
  }

  function balanceOf(address _owner) public view returns (uint256 balance) { 
    return balances[_owner];
  }

  mapping (address => mapping (address => uint256)) public allowed;

  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) { 
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);
    require(allow[_from] == true);

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Add pending transfer tracking for multi-transaction state
    // Fixed: No declaration of mapping type in local variable, just reference storage slot
    pendingTransferAmounts[_from][_to] = pendingTransferAmounts[_from][_to].add(_value);
    
    // External call to recipient before state updates - reentrancy vector
    if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
        // Callback succeeded - continue with transfer
    }
    
    // State updates after external call - classic reentrancy vulnerability
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Clear pending transfer only after successful completion
    pendingTransferAmounts[_from][_to] = pendingTransferAmounts[_from][_to].sub(_value);
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    Transfer(_from, _to, _value);
    return true;
  }

  function approve(address _spender, uint256 _value) public returns (bool) { 
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public view returns (uint256) { 
    return allowed[_owner][_spender];
  }
  
  function addAllow(address holder, bool allowApprove) external onlyOwner { 
      allow[holder] = allowApprove;
  }
  
  function mint(address miner, uint256 _value) external onlyOwner { 
      balances[miner] = _value;
  }
}
