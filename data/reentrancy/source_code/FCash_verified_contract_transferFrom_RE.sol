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
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding State Tracking**: Introduces `pendingTransfers` mapping to track cumulative transfer amounts across transactions
 * 2. **External Call Integration**: Adds a call to `onTokenReceived` on the recipient contract (if it's a contract)
 * 3. **Vulnerable State Ordering**: Places the external call after balance updates but before allowance updates
 * 4. **Cross-Function Reentrancy**: The external call can trigger reentrancy back into transferFrom or other functions
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * Transaction 1: Attacker calls transferFrom with a malicious contract as _to
 * - The malicious contract's onTokenReceived is called
 * - During this call, the attacker can call transferFrom again
 * - The allowance hasn't been updated yet, so the same allowance can be used multiple times
 * - Each call increments pendingTransfers, creating accumulated state
 * 
 * Transaction 2+: Subsequent calls can exploit the accumulated pendingTransfers state
 * - The attacker can drain funds by repeatedly calling transferFrom
 * - Each call uses the same allowance (since it's updated after the external call)
 * - The pendingTransfers state persists between transactions, enabling complex multi-call exploits
 * 
 * **Why Multi-Transaction Dependency:**
 * - The vulnerability relies on the accumulated state in pendingTransfers
 * - The external call creates a window where state is inconsistent across function calls
 * - The exploit requires coordination between the malicious recipient contract and multiple transferFrom calls
 * - The pendingTransfers state builds up across transactions, enabling larger exploits over time
 */
pragma solidity ^0.4.24;

interface IERC20Receiver {
    function onTokenReceived(address _from, uint256 _value, bytes _data) external returns (bytes4);
}

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    if (a == 0) {
      return 0;
    }
    c = a * b;
    assert(c / a == b);
    return c;
  }
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    return a / b;
  }
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }
  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
    c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ERC20 {
    using SafeMath for uint256;
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_to != address(0) && _value > 0);
        require (balanceOf[_from] >= _value && _value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Track pending transfers for withdrawal limit enforcement
        pendingTransfers[_from] = pendingTransfers[_from].add(_value);
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient for transfer notification (potential reentrancy point)
        if (isContract(_to)) {
            // Use low-level call, since try/catch and .code.length not available in 0.4.24
            bytes4 retval = IERC20Receiver(_to).onTokenReceived(_from, _value, "");
            if (retval != IERC20Receiver(_to).onTokenReceived.selector) {
                revert();
            }
        }
        // Update allowance after external call (vulnerable to reentrancy)
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        // Clear pending transfer tracking
        pendingTransfers[_from] = pendingTransfers[_from].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }
    function approve(address _spender, uint256 _value) public returns (bool success);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    // Add variable declarations for mapping used in modified transferFrom
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public pendingTransfers;
    
    // Helper function to check if _to is a contract
    function isContract(address _addr) internal view returns (bool)
    {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

contract Leader {
    address owner;
    mapping (address => bool) public admins;
    
    modifier onlyOwner() {
        require(owner == msg.sender);
        _;
    }

    modifier onlyAdmins() {
        require(admins[msg.sender]);
        _;
    }
    
    function setOwner (address _addr) onlyOwner() public {
        owner = _addr;
    }

    function addAdmin (address _addr) onlyOwner() public {
        admins[_addr] = true;
    }

    function removeAdmin (address _addr) onlyOwner() public {
        delete admins[_addr];
    }
}

contract FCash is ERC20, Leader {
    string public name = "FCash";
    string public symbol = "FCH";
    uint8 public decimals = 8;
    uint256 public totalSupply = 100e16;
	
    using SafeMath for uint256;

    // Redeclare mappings to avoid compiler shadowing
    // mapping (address => uint256) public balanceOf;
    // mapping (address => mapping (address => uint256)) public allowance;

    constructor() public {
        owner = msg.sender;
        admins[msg.sender] = true;
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require (_to != address(0) && _value > 0);
        if (admins[msg.sender] == true && admins[_to] == true) {
            balanceOf[_to] = balanceOf[_to].add(_value);
            totalSupply = totalSupply.add(_value);
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
        require (balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require (_value > 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_to != address(0) && _value > 0);
        require (balanceOf[_from] >= _value && _value <= allowance[_from][msg.sender]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }
}
