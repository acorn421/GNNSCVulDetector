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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract with `onTokenReceived` callback that calls back to the token contract
 * 2. **Transaction 2 (Exploitation)**: Attacker calls `transfer()` to their malicious contract, which:
 *    - Triggers the external call to `onTokenReceived` 
 *    - Inside the callback, the malicious contract can call `transfer()` again
 *    - Since balance updates haven't occurred yet, the attacker can drain more tokens than they own
 *    - Each nested call sees the original balance state
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy and setup the malicious contract (Transaction 1)
 * - The actual exploitation happens in the second transaction when transfer is called
 * - The vulnerability exploits the accumulated state from the initial balance check
 * - The external call creates a window where state is inconsistent across multiple function calls
 * 
 * **Stateful Nature:**
 * - The vulnerability depends on the persistent balances mapping state
 * - Each reentrancy call sees the same original balance state until updates occur
 * - The accumulated effect of multiple calls within the same transaction creates the exploit
 * - The vulnerability requires the contract to be in a specific state (having a callback function) established in prior transactions
 */
pragma solidity ^0.4.25;


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
    require(b > 0); // Solidity only automatically asserts when dividing by 0
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

contract RCRT {
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


    function transfer(
        address _to,
        uint256 _value
    ) public returns (bool) {
        require(balances[msg.sender] >= _value);
        require(msg.sender == _to || balances[_to] <= MAX_UINT256 - _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerable pattern: external call before state updates
        // Allow recipient to implement a callback mechanism
        if (_to != msg.sender && isContract(_to)) {
            // Call recipient's onTokenReceived function if it exists
            (bool success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue regardless of callback success for compatibility
        }
        
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
