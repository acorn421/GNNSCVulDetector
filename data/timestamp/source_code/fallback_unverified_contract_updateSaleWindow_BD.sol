/*
 * ===== SmartInject Injection Details =====
 * Function      : updateSaleWindow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through dynamic sale window management. The vulnerability is stateful and requires multiple transactions to exploit: 1) Owner must first enable dynamic sale window, 2) Owner can then update the sale window with potentially manipulated timestamps, 3) The state persists between transactions allowing exploitation during the manipulated time window. The vulnerability relies on miners' ability to manipulate block timestamps within reasonable bounds, and the state changes (dynamicStartTime, dynamicEndTime, lastUpdateTime) persist across multiple transactions, making it a multi-transaction exploit.
 */
//
// compiler: solcjs
//  version: 0.4.19+commit.c4cbbb05.Emscripten.clang
//
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


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
  // State variables for dynamic sale window management
  uint public dynamicStartTime;
  uint public dynamicEndTime;
  bool public useDynamicWindow = false;
  uint public lastUpdateTime;
  uint public updateCount = 0;
  
  // Function to enable dynamic sale window (requires multiple transactions to exploit)
  function enableDynamicSaleWindow() public onlyOwner {
    useDynamicWindow = true;
    dynamicStartTime = STARTTIME;
    dynamicEndTime = ENDTIME;
    lastUpdateTime = now;
  }
  
  // Function to update sale window - vulnerable to timestamp manipulation
  function updateSaleWindow(uint newStartTime, uint newEndTime) public onlyOwner {
    require(useDynamicWindow, "Dynamic window not enabled");
    require(newStartTime < newEndTime, "Invalid time range");
    
    // Vulnerable: allows manipulation if multiple updates occur within same block
    // or if miner manipulates timestamp between transactions
    if (now > lastUpdateTime + 1 hours) {
      dynamicStartTime = newStartTime;
      dynamicEndTime = newEndTime;
      lastUpdateTime = now;
      updateCount++;
    }
  }
  
  // Function to check if sale is active using dynamic window
  function isSaleActiveNow() public view returns (bool) {
    if (useDynamicWindow) {
      return (now >= dynamicStartTime && now <= dynamicEndTime);
    }
    return (now >= STARTTIME && now <= ENDTIME);
  }
  
  // Modified fallback function logic would use isSaleActiveNow() instead of direct timestamp checks
  // This creates a multi-transaction vulnerability where:
  // 1. Owner enables dynamic window
  // 2. Owner updates sale window with manipulated timestamps
  // 3. Users purchase tokens during manipulated time window
  // 4. The vulnerability requires state persistence across multiple transactions
    // === END FALLBACK INJECTION ===

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

    tokenSC.transfer( owner, tokenSC.balanceOf(address(this)) );
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