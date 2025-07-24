/*
 * ===== SmartInject Injection Details =====
 * Function      : claimUnsold
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Variables Added**: The function now relies on two state variables that must be added to the contract:
 *    - `bool public claimInProgress;` - tracks whether a claim is currently being processed
 *    - `uint public lastClaimTime;` - records when the last claim was initiated
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls `claimUnsold()`, sets `claimInProgress = true`, initiates token transfer
 *    - **During Transfer**: If the token contract is malicious, it can call back to `claimUnsold()` during the transfer
 *    - **Reentrancy Window**: The callback finds `claimInProgress = true` but the time-based bypass logic allows claiming again if 1 hour has passed
 *    - **Transaction 2**: Second call processes with `claimInProgress = false` (due to time bypass), allowing another full claim
 *    - **Result**: Multiple claims of the same token balance across transactions
 * 
 * 3. **Why Multi-Transaction is Required**:
 *    - The vulnerability requires accumulating state over time (`lastClaimTime` tracking)
 *    - The time-based bypass logic creates windows where multiple claims become possible
 *    - State cleanup happens after external calls, creating persistent vulnerability windows
 *    - The exploit needs real time passage (1 hour) or manipulation of the time-based checks across transactions
 * 
 * 4. **Realistic Integration**:
 *    - Progressive claiming appears to be a legitimate feature for large token amounts
 *    - Time-based restrictions seem reasonable for preventing abuse
 *    - The state management looks like typical access control patterns
 *    - The vulnerability is subtle and would likely pass initial code reviews
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability where the state persists between calls and enables exploitation through accumulated state changes and time-based manipulation.
 */
pragma solidity ^0.4.19;

contract owned {
  address public owner;

  function owned() public { owner = msg.sender; }

  modifier onlyOwner {
    if (msg.sender != owner) { revert(); }
    _;
  }

  function changeOwner( address newowner ) public onlyOwner {
    owner = newowner;
  }

  function closedown() public onlyOwner {
    selfdestruct( owner );
  }
}

// "extern" declare functions from token contract
interface BitEther {
  function transfer(address to, uint256 value) public;
  function balanceOf( address owner ) public constant returns (uint);
}

contract BTTPREICO is owned {

  uint public constant STARTTIME = 1515794400; // 12 JAN 2017 00:00 GMT
  uint public constant ENDTIME = 1517104800;   // 27 JAN 2017 00:00 GMT
  uint public constant BTTPERETH = 1550;       // price: approx $0.65 ea

  BitEther public tokenSC;

  // State variables for claimUnsold's progressive claiming mechanism
  bool private claimInProgress;
  uint256 private lastClaimTime;

  function BTTPREICO() public {}

  function setToken( address tok ) public onlyOwner {
    if ( tokenSC == address(0) )
      tokenSC = BitEther(tok);
  }

  function() public payable {
    if (now < STARTTIME || now > ENDTIME)
      revert();

    // (amountinwei/weipereth * bitether/eth) * ( (100 + bonuspercent)/100 )
    // = amountinwei*bitetherpereth/weipereth*(bonus+100)/100
    uint qty =
      div(mul(div(mul(msg.value, BTTPERETH),1000000000000000000),(bonus()+100)),100);

    if (qty > tokenSC.balanceOf(address(this)) || qty < 1)
      revert();

    tokenSC.transfer( msg.sender, qty );
  }

  // unsold tokens can be claimed by owner after sale ends
  function claimUnsold() public onlyOwner {
    if ( now < ENDTIME )
      revert();

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Track claim initiation for progressive claiming
    if (!claimInProgress) {
        claimInProgress = true;
        lastClaimTime = now;
    }
    
    uint256 availableTokens = tokenSC.balanceOf(address(this));
    
    // Allow progressive claiming if sufficient time has passed
    if (now >= lastClaimTime + 1 hours) {
        claimInProgress = false;
        lastClaimTime = now;
    }
    
    // External call before state cleanup - vulnerable to reentrancy
    tokenSC.transfer( owner, availableTokens );
    
    // State cleanup happens after external call
    claimInProgress = false;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  function withdraw( uint amount ) public onlyOwner returns (bool) {
    if (amount <= this.balance)
      return owner.send( amount );

    return false;
  }

  function bonus() pure private returns(uint) {
    return 0;
  }

  // ref:
  // github.com/OpenZeppelin/zeppelin-solidity/
  // blob/master/contracts/math/SafeMath.sol
  function mul(uint256 a, uint256 b) pure private returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) pure private returns (uint256) {
    uint256 c = a / b;
    return c;
  }
}
