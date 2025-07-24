/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawPartial
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Multi-transaction reentrancy vulnerability requiring: (1) First transaction calls requestWithdrawal() to set pending amount, (2) Second transaction calls withdrawPartial() which makes external call before clearing pending amount, allowing reentrancy. The vulnerability is stateful because it depends on the pendingWithdrawals mapping persisting between transactions.
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


    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
mapping(address => uint256) public pendingWithdrawals;
bool public withdrawalLocked;

function requestWithdrawal(uint256 amount) public onlyOwner {
    require(amount > 0, "Amount must be greater than 0");
    require(amount <= this.balance, "Insufficient contract balance");
    
    pendingWithdrawals[msg.sender] = amount;
}

function withdrawPartial() public onlyOwner {
    require(!withdrawalLocked, "Withdrawal in progress");
    require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
    
    uint256 amount = pendingWithdrawals[msg.sender];
    withdrawalLocked = true;
    
    // Vulnerable to reentrancy: external call before state update
    if (msg.sender.call.value(amount)()) {
        // State update happens after external call
        pendingWithdrawals[msg.sender] = 0;
        withdrawalLocked = false;
    } else {
        withdrawalLocked = false;
        revert("Transfer failed");
    }
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