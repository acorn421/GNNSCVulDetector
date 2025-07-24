/*
 * ===== SmartInject Injection Details =====
 * Function      : enableExtendedSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence attack. The attack requires: 1) Owner calls enableExtendedSale() after ENDTIME, 2) Multiple calls to updateExtendedSaleTime() can extend the sale window, 3) Users can then call purchaseInExtendedSale() during the extended window. The vulnerability allows miners to manipulate timestamps across multiple transactions to extend sale periods beyond intended limits, creating unfair advantages. The state persists across transactions through extendedSaleEnabled and extendedSaleEndTime variables.
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
  uint public extendedSaleEndTime;
  bool public extendedSaleEnabled;
  
  function enableExtendedSale() public onlyOwner {
    // Allow owner to enable extended sale with timestamp dependence vulnerability
    if (now >= ENDTIME) {
      extendedSaleEnabled = true;
      // Vulnerable: relies on block.timestamp which can be manipulated by miners
      // within certain bounds over multiple transactions
      extendedSaleEndTime = now + 86400; // 24 hours extension
    }
  }
  
  function updateExtendedSaleTime() public onlyOwner {
    // Vulnerable: allows multiple timestamp-dependent state changes
    if (extendedSaleEnabled && now < extendedSaleEndTime) {
      // Each call can extend further based on manipulable timestamp
      extendedSaleEndTime = now + 43200; // 12 hours extension
    }
  }
  
  function purchaseInExtendedSale() public payable {
    // Multi-transaction vulnerability: requires enableExtendedSale() first,
    // then this function, creating stateful timestamp dependence
    if (!extendedSaleEnabled || now > extendedSaleEndTime)
      revert();
    
    // Same purchase logic but with extended timeframe
    uint qty = div(mul(div(mul(msg.value, BTTPERETH),1000000000000000000),(bonus()+100)),100);
    
    if (qty > tokenSC.balanceOf(address(this)) || qty < 1)
      revert();
      
    tokenSC.transfer(msg.sender, qty);
  }
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