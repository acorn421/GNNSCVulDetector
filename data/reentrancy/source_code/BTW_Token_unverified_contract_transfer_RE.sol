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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract recipients using `_to.code.length > 0`
 * 2. Introduced an external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` before balance updates
 * 3. Positioned the external call after the balance check but before state modifications, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract with `onTokenReceived` function
 * 2. **Initial Transfer**: User calls `transfer()` to send tokens to the malicious contract
 * 3. **Reentrant Calls**: During the external call, the malicious contract calls `transfer()` repeatedly before the original balance deduction occurs
 * 4. **State Accumulation**: Each reentrant call passes the balance check (since original deduction hasn't happened yet) and triggers more external calls
 * 5. **Final Settlement**: After all reentrant calls complete, the original balance update occurs, but the attacker has already extracted more tokens than they should have received
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the initial transfer transaction to trigger the external call
 * - The reentrant calls happen within the same transaction but are separate function invocations
 * - The attacker needs to pre-deploy the malicious contract in a separate transaction
 * - Maximum exploitation requires multiple sequential transfers to accumulate maximum stolen tokens
 * - The persistent state changes (balance modifications) enable the vulnerability across the sequence of calls
 * 
 * **Stateful Nature:**
 * - The `balances` mapping maintains state between calls
 * - Each reentrant call modifies the recipient's balance while the sender's balance remains unchanged until the end
 * - The accumulated state changes persist and enable continued exploitation in subsequent transactions
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world token contract flaws where recipient notifications or hooks are called before state updates.
 */
pragma solidity ^0.4.24;

/**
 * SmartEth.co
 * ERC20 Token and ICO smart contracts development, smart contracts audit, ICO websites.
 * contact@smarteth.co
 */

/**
 * @title SafeMath
 */
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

/**
 * @title ERC20Basic
 */
contract ERC20Basic {
  mapping(address => uint256) internal balances;
  function totalSupply() public view returns (uint256);
  function balanceOf(address who) public view returns (uint256);
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

    // Notify recipient about incoming transfer (external call before state update)
    if (isContract(_to)) {
        (bool success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
        // Continue regardless of call success to maintain functionality
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }
  event Transfer(address indexed from, address indexed to, uint256 value);
  // Helper function to check if an address is a contract (Solidity <0.5)
  function isContract(address _addr) internal view returns (bool) {
      uint256 length;
      assembly {
        length := extcodesize(_addr)
      }
      return (length > 0);
  }
}

/**
 * @title Bitway Coin
 */
contract BTW_Token is ERC20Basic {
  using SafeMath for uint256;

  // mapping(address => uint256) balances; // Already declared in ERC20Basic as internal

  uint256 totalSupply_;

  function totalSupply() public view returns (uint256) {
    return totalSupply_;
  }

  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);
    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  function balanceOf(address _owner) public view returns (uint256 balance) {
    return balances[_owner];
  }
    
  string public name;
  string public symbol;
  uint8 public decimals;
  address public owner;
  uint256 public initialSupply;

  constructor() public {
    name = 'Bitway Coin';
    symbol = 'BTW';
    decimals = 18;
    owner = 0x0034a61e60BD3325C08E36Ac3b208E43fc53E5C2;
    initialSupply = 16000000 * 10 ** uint256(decimals);
    totalSupply_ = initialSupply;
    balances[owner] = initialSupply;
    emit Transfer(0x0, owner, initialSupply);
  }
}
