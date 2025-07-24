/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by: 1) Adding a partial withdrawal mechanism that uses the secret field to track withdrawal state, 2) Introducing an external callback opportunity through swap.token.call() that executes between token transfer and balance zeroing, 3) Creating a window where the balance remains non-zero during the callback, allowing reentrant calls to exploit the same swap balance multiple times across different transactions. The vulnerability requires multiple transactions because the first transaction establishes the secret state, and subsequent reentrant transactions can exploit the non-zero balance before it gets updated.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Allow partial withdrawals - new vulnerability component
    uint256 withdrawAmount = swap.balance;
    
    // Track withdrawal attempts for this swap
    if (swaps[_ownerAddress][msg.sender].secret == bytes32(0)) {
        // First withdrawal attempt - transfer tokens before state update
        ERC20(swap.token).transfer(msg.sender, withdrawAmount);
        
        // Mark as partially processed but don't zero balance yet
        swaps[_ownerAddress][msg.sender].secret = _secret;
        
        // External callback opportunity - notify token contract of withdrawal
        if (swap.token.call(bytes4(keccak256("onWithdraw(address,uint256)")), msg.sender, withdrawAmount)) {
            // Callback executed - this creates reentrancy window
        }
        
        // State update happens after external interactions
        swaps[_ownerAddress][msg.sender].balance = 0;
    } else {
        // Subsequent withdrawal attempts on same swap
        require(swaps[_ownerAddress][msg.sender].secret == _secret, "Invalid secret for completed withdrawal");
        
        // Check if balance was somehow not zeroed (reentrancy scenario)
        if (swap.balance > 0) {
            ERC20(swap.token).transfer(msg.sender, swap.balance);
            swaps[_ownerAddress][msg.sender].balance = 0;
        }
    }

    Withdraw(_secret,msg.sender,withdrawAmount);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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