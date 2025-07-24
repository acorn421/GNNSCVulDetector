/*
 * ===== SmartInject Injection Details =====
 * Function      : createSwap
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by maintaining the external call to ERC20.transferFrom() before the state update. The vulnerability exploits the fact that:
 * 
 * 1. **Multi-Transaction State Dependency**: The function checks `swaps[msg.sender][_participantAddress].balance == uint256(0)` at the beginning, but this check can be bypassed through accumulated state manipulation across multiple transactions.
 * 
 * 2. **Reentrancy Window**: A malicious token contract can reenter the createSwap function during the transferFrom call, before the swap state is updated. This creates a window where the balance check passes multiple times.
 * 
 * 3. **Stateful Exploitation Pattern**:
 *    - Transaction 1: Attacker calls createSwap with malicious token contract
 *    - During transferFrom: Malicious token reenters createSwap with different parameters
 *    - The balance check still passes because state hasn't been updated yet
 *    - Transaction 2: Attacker can create overlapping swaps or manipulate existing ones
 *    - Result: Multiple swaps created with same owner/participant pair, breaking contract invariants
 * 
 * 4. **Persistent State Corruption**: The vulnerability allows creation of multiple swaps for the same owner/participant combination, which should be impossible according to the contract logic. This corrupted state persists across transactions and can be leveraged for further attacks.
 * 
 * The vulnerability is realistic because it maintains the original function flow while exploiting the natural external call pattern. The multi-transaction nature comes from the ability to accumulate corrupted state that enables subsequent exploits.
 */
pragma solidity ^0.4.23;

// ----------------------------------------------------------------------------
// Safe maths from OpenZeppelin
// ----------------------------------------------------------------------------
library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns(uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns(uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns(uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns(uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ERC20 {
    function transfer(address _to, uint256 _value) public;
    function transferFrom(address _from, address _to, uint256 _value) public returns(bool success);
}

contract EthTokenToSmthSwaps {

  using SafeMath for uint;

  address public owner;
  uint256 SafeTime = 3 hours; // atomic swap timeOut

  struct Swap {
    address token;
    bytes32 secret;
    bytes20 secretHash;
    uint256 createdAt;
    uint256 balance;
  }

  // ETH Owner => BTC Owner => Swap
  mapping(address => mapping(address => Swap)) public swaps;

  // ETH Owner => BTC Owner => secretHash => Swap
  // mapping(address => mapping(address => mapping(bytes20 => Swap))) public swaps;

  constructor () public {
    owner = msg.sender;
  }

  event CreateSwap(uint256 createdAt);

  // ETH Owner creates Swap with secretHash
  // ETH Owner make token deposit
  function createSwap(bytes20 _secretHash, address _participantAddress, uint256 _value, address _token) public {
    require(_value > 0);
    require(swaps[msg.sender][_participantAddress].balance == uint256(0));
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Vulnerability: External call before state update creates reentrancy window
    // This allows malicious token contracts to reenter during transferFrom
    require(ERC20(_token).transferFrom(msg.sender, this, _value));
    
    // State update moved after external call - creates race condition
    // Attacker can exploit the window between transferFrom and state update
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    swaps[msg.sender][_participantAddress] = Swap(
      _token,
      bytes32(0),
      _secretHash,
      now,
      _value
    );

    CreateSwap(now);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function getBalance(address _ownerAddress) public view returns (uint256) {
    return swaps[_ownerAddress][msg.sender].balance;
  }

  event Withdraw(bytes32 _secret,address addr, uint amount);

  // BTC Owner withdraw money and adds secret key to swap
  // BTC Owner receive +1 reputation
  function withdraw(bytes32 _secret, address _ownerAddress) public {
    Swap memory swap = swaps[_ownerAddress][msg.sender];

    require(swap.secretHash == ripemd160(_secret));
    require(swap.balance > uint256(0));
    require(swap.createdAt.add(SafeTime) > now);

    ERC20(swap.token).transfer(msg.sender, swap.balance);

    swaps[_ownerAddress][msg.sender].balance = 0;
    swaps[_ownerAddress][msg.sender].secret = _secret;

    Withdraw(_secret,msg.sender,swap.balance);
  }

  // ETH Owner receive secret
  function getSecret(address _participantAddress) public view returns (bytes32) {
    return swaps[msg.sender][_participantAddress].secret;
  }

  event Refund();

  // ETH Owner refund money
  // BTC Owner gets -1 reputation
  function refund(address _participantAddress) public {
    Swap memory swap = swaps[msg.sender][_participantAddress];

    require(swap.balance > uint256(0));
    require(swap.createdAt.add(SafeTime) < now);

    ERC20(swap.token).transfer(msg.sender, swap.balance);
    clean(msg.sender, _participantAddress);

    Refund();
  }

  function clean(address _ownerAddress, address _participantAddress) internal {
    delete swaps[_ownerAddress][_participantAddress];
  }
  
  //only for testnet
  function testnetWithdrawn(address tokencontract,uint val) {
      require(msg.sender == owner);
      ERC20(tokencontract).transfer(msg.sender,val);
  }
}