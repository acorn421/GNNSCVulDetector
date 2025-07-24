/*
 * ===== SmartInject Injection Details =====
 * Function      : refund
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Modification Before External Call**: Added `swaps[msg.sender][_participantAddress].balance = 0;` before the external token transfer. This creates a window where the swap state is partially modified but not fully cleaned.
 * 
 * 2. **Multi-Transaction Exploitation Vector**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls `refund()` with a malicious ERC20 token contract
 *    - **During Transfer**: The malicious token's transfer function can call other contract functions (like `createSwap()` or `withdraw()`) while the swap state is in an inconsistent state
 *    - **Transaction 2+**: The attacker can exploit the fact that while balance is set to 0, the swap struct still exists in storage until `clean()` is called
 * 
 * 3. **Stateful Vulnerability Characteristics**:
 *    - The vulnerability depends on the persistent state between the balance update and the final cleanup
 *    - An attacker can create new swaps or manipulate existing ones during the reentrancy window
 *    - The incomplete state cleanup allows for cross-function reentrancy attacks
 *    - Multiple transactions can exploit the time window between balance zeroing and struct deletion
 * 
 * 4. **Why Multiple Transactions Are Required**:
 *    - The initial call sets balance to 0, preventing simple same-function reentrancy
 *    - However, the swap struct remains in storage with corrupted state until `clean()` executes
 *    - An attacker needs separate transactions to set up the exploitation conditions and then exploit the inconsistent state
 *    - The vulnerability becomes exploitable when combined with other contract functions that don't properly validate the complete swap state
 * 
 * This creates a realistic vulnerability pattern where the contract appears to have reentrancy protection (balance is zeroed) but actually creates a more complex multi-transaction attack surface.
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
    require(ERC20(_token).transferFrom(msg.sender, this, _value));

    swaps[msg.sender][_participantAddress] = Swap(
      _token,
      bytes32(0),
      _secretHash,
      now,
      _value
    );

    CreateSwap(now);
  }

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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Mark as processing to prevent direct re-entry
    swaps[msg.sender][_participantAddress].balance = 0;
    
    // External call to potentially malicious token contract
    ERC20(swap.token).transfer(msg.sender, swap.balance);
    
    // Complete cleanup after external call
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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