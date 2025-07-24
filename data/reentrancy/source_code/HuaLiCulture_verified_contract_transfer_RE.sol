/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Two new mappings track transfer state across transactions:
 *    - `pendingTransfers`: Records the amount being transferred
 *    - `transferInitiated`: Tracks if a transfer process has begun
 * 
 * 2. **External Call Before State Update**: Added `_to.call("")` before balance modifications, creating the classic reentrancy vulnerability window
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User initiates transfer, setting `transferInitiated[user] = true` and `pendingTransfers[user] = value`
 *    - **External Call**: The `_to.call("")` triggers, allowing the recipient contract to re-enter
 *    - **Reentrancy Window**: During re-entrance, the original balances are still unchanged, but `pendingTransfers` shows the intended transfer amount
 *    - **Transaction 2+**: Malicious contract can exploit the inconsistent state by calling transfer again before the original call completes
 * 
 * 4. **State Persistence**: The vulnerability persists across transactions through the persistent state variables, making it impossible to exploit in a single atomic transaction
 * 
 * 5. **Realistic Implementation**: The external call appears as a legitimate notification mechanism to the recipient, making this a realistic vulnerability pattern seen in production contracts
 * 
 * **Multi-Transaction Requirement**: The vulnerability requires multiple transactions because:
 * - The state variables must be set in one transaction
 * - The external call creates a window for reentrancy in the same transaction
 * - But the full exploitation requires the malicious contract to make additional calls during the reentrancy window
 * - The attacker needs to accumulate state from the pending transfer information across multiple call frames
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability that maintains the function's core transfer logic while introducing a realistic security flaw.
 */
pragma solidity ^0.4.24;


library SafeMath {

 
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
    // benefit is lost if 'b' is also tested.
    // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
    if (a == 0) {
      return 0;
    }

    uint256 c = a * b;
    require(c / a == b);

    return c;
  }

  
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0); // Solidity only automatically asserts when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold

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


contract HuaLiCulture {
    mapping(address => uint256) public balances;
    mapping(address => mapping (address => uint256)) public allowed;
    using SafeMath for uint256;
    address public owner;
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    uint256 private constant MAX_UINT256 = 2**256 -1 ;

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    
    bool lock = false;

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        owner = msg.sender;
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
        
    }
	
	
	modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier isLock {
        require(!lock);
        _;
    }
    
    function setLock(bool _lock) onlyOwner public{
        lock = _lock;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }
	
	

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingTransfers;
    mapping(address => bool) public transferInitiated;
    
    function transfer(
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        address _to,
        uint256 _value
    ) public returns (bool) {
        require(balances[msg.sender] >= _value);
        require(msg.sender == _to || balances[_to] <= MAX_UINT256 - _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // For multi-transaction exploitation: mark transfer as initiated
        if (!transferInitiated[msg.sender]) {
            transferInitiated[msg.sender] = true;
            pendingTransfers[msg.sender] = _value;
        }
        
        // External call to recipient before state update - vulnerability point
        if (_to.call("")) {
            // Only proceed if external call succeeds
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            // Clear pending state after successful transfer
            pendingTransfers[msg.sender] = 0;
            transferInitiated[msg.sender] = false;
            
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else {
            // If external call fails, keep pending state for retry
            return false;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    ) public returns (bool) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value);
        require(_from == _to || balances[_to] <= MAX_UINT256 -_value);
        require(allowance >= _value);
        balances[_from] -= _value;
        balances[_to] += _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(
        address _owner
    ) public view returns (uint256) {
        return balances[_owner];
    }

    function approve(
        address _spender,
        uint256 _value
    ) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(
        address _owner,
        address _spender
    ) public view returns (uint256) {
        return allowed[_owner][_spender];
    }
}