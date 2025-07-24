/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase withdrawal system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Phase 1 (Transaction 1)**: User calls withdraw() to set up a pending withdrawal, which stores the amount in pendingWithdrawals mapping and records the request time.
 * 
 * **Phase 2 (Transaction 2+)**: User calls withdraw() again to claim the pending withdrawal. The vulnerability occurs because:
 * 1. The external call owner.send() happens BEFORE the state update (totalWithdrawn += pendingAmount)
 * 2. During the external call, a malicious owner contract can reenter the function
 * 3. The reentrancy allows manipulation of pendingWithdrawals and totalWithdrawn across multiple transactions
 * 4. The malicious owner can set up multiple overlapping pending withdrawals across transactions
 * 
 * **Multi-Transaction Exploitation**:
 * - Transaction 1: Set pendingWithdrawals[owner] = X
 * - Transaction 2: Call withdraw() to claim X, but during owner.send(), reenter to modify pendingWithdrawals for future transactions
 * - Transaction 3+: Exploit the manipulated state to withdraw more than intended
 * 
 * **State Variables Required** (assumed to be added to contract):
 * - mapping(address => uint) pendingWithdrawals
 * - mapping(address => uint) withdrawalRequestTime  
 * - uint totalWithdrawn
 * 
 * The vulnerability is realistic because it mimics real-world patterns where contracts implement withdrawal delays or two-phase operations for security, but introduce reentrancy vulnerabilities in the process.
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

  // State variables to fix undeclared identifiers
  mapping (address => uint256) public pendingWithdrawals;
  mapping (address => uint256) public withdrawalRequestTime;
  uint256 public totalWithdrawn;

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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Check if there's an existing pending withdrawal
    if (pendingWithdrawals[msg.sender] > 0) {
        uint pendingAmount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        
        // External call before state update - vulnerable to reentrancy
        if (owner.send(pendingAmount)) {
            totalWithdrawn += pendingAmount;
            return true;
        } else {
            pendingWithdrawals[msg.sender] = pendingAmount; // restore on failure
            return false;
        }
    }
    
    // Process new withdrawal request
    if (amount <= this.balance && amount > 0) {
        // Set up pending withdrawal for next transaction
        pendingWithdrawals[msg.sender] = amount;
        withdrawalRequestTime[msg.sender] = now;
        return true;
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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