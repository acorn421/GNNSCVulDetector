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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between balance updates and allowance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker calls transferFrom() with a malicious recipient contract
 * 2. **State at external call**: Balances are updated but allowance is not yet decreased
 * 3. **Malicious contract callback**: The recipient contract's onTokenReceived() function executes
 * 4. **Transaction 2**: From within the callback, the malicious contract calls transferFrom() again with the same allowance (since it hasn't been updated yet)
 * 5. **State accumulation**: Multiple transfers occur using the same allowance value
 * 6. **Transaction 3**: Original call completes, finally updating the allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the window between balance updates and allowance updates
 * - The external call creates a state where balances reflect the transfer but allowance is still at its original value
 * - An attacker needs to make additional transferFrom calls during this window to exploit the inconsistent state
 * - The exploit requires coordinated timing across multiple function calls, making it impossible to exploit in a single atomic transaction
 * 
 * **Realistic Implementation:**
 * - Added TokenRecipient interface call with try/catch for backward compatibility
 * - The callback mechanism is a common pattern in modern token contracts (similar to ERC-777)
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - Maintains all original functionality while introducing the security flaw
 */
pragma solidity ^0.4.18;

interface TokenRecipient {
    function onTokenReceived(address from, address operator, uint256 amount) external;
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
    require(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ERC20 {
  using SafeMath for uint256;

  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  function allowance(address owner, address spender) public view returns (uint256 remaining);
  function approve(address spender, uint256 value) public returns (bool);

  mapping (address => uint256) public balances;
  mapping (address => mapping (address => uint256)) internal allowed;

  function transferFrom(address _from, address _to, uint256 _amount) public returns (bool) {
    require(_to != address(0));
    require(_amount <= balances[_from]);
    require(_amount <= allowed[_from][msg.sender]);

    balances[_from] = balances[_from].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // External call to recipient contract before updating allowance
    if (isContract(_to)) {
        // Call recipient's onTokenReceived function if it exists
        // Use low-level call to preserve 0.4.18 compatibility
        TokenRecipient(_to).onTokenReceived(_from, msg.sender, _amount);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
    emit Transfer(_from, _to, _amount);
    return true;
  }

  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);

  // Utility to check if an address is a contract (0.4.18 compatible)
  function isContract(address _addr) internal view returns (bool) {
      uint size;
      assembly { size := extcodesize(_addr) }
      return size > 0;
  }
}

contract NebToken is ERC20 {
  using SafeMath for uint256;

  string public name = "Nebula Network Token";
  string public symbol = "NEB";
  uint8 public decimals = 0;
  address public treasury;
  uint256 public totalSupply;

  constructor(uint256 _totalSupply) public {
    treasury = msg.sender;
    totalSupply = _totalSupply;
    balances[treasury] = totalSupply;
    emit Transfer(0x0, treasury, totalSupply);
  }

  function balanceOf(address _addr) public view returns(uint256) {
    return balances[_addr];
  }

  function transfer(address _to, uint256 _amount) public returns (bool) {
    require(_to != address(0));
    require(_amount <= balances[msg.sender]);

    balances[msg.sender] = balances[msg.sender].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
    emit Transfer(msg.sender, _to, _amount);
    return true;
  }

  function allowance(address _owner, address _spender) public view returns (uint256) {
    return allowed[_owner][_spender];
  }

  function transferFrom(address _from, address _to, uint256 _amount) public returns (bool) {
    require(_to != address(0));
    require(_amount <= balances[_from]);
    require(_amount <= allowed[_from][msg.sender]);

    balances[_from] = balances[_from].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
    emit Transfer(_from, _to, _amount);
    return true;
  }

  function approve(address _spender, uint256 _amount) public returns (bool) {
      allowed[msg.sender][_spender] = _amount;
      emit Approval(msg.sender, _spender, _amount);
      return true;
  }
}
