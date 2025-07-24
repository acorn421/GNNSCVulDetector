/*
 * ===== SmartInject Injection Details =====
 * Function      : claimUnsold
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `claimInProgress` mapping to track ongoing claims
 *    - `partialClaimAmount` mapping to store partial claim amounts between transactions
 * 
 * 2. **Modified Control Flow**:
 *    - Set `claimInProgress[owner] = true` before external call
 *    - Added logic to use `partialClaimAmount` if set from previous transaction
 *    - Moved state cleanup (`partialClaimAmount[owner] = 0` and `claimInProgress[owner] = false`) to AFTER the external call
 * 
 * 3. **Added Helper Function**: 
 *    - `setPartialClaim()` allows setting partial claim amounts while a claim is in progress
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * 
 * **Transaction 1**: Owner calls `claimUnsold()` 
 * - Sets `claimInProgress[owner] = true`
 * - Calls `tokenSC.transfer()` with full balance
 * - If tokenSC is malicious, it can reenter and call `setPartialClaim()` to set a smaller amount
 * - Original transaction completes, resetting states
 * 
 * **Transaction 2**: Owner calls `claimUnsold()` again
 * - `claimInProgress[owner]` is set to true again
 * - Now uses the manipulated `partialClaimAmount` instead of full balance
 * - Attacker can repeat the process to drain tokens incrementally
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability requires persistent state (`partialClaimAmount`) to be set in one transaction and exploited in another
 * - Single transaction exploitation is prevented by the state reset at the end of each call
 * - The attack builds upon accumulated state changes across multiple function calls
 * - Each transaction modifies the contract's persistent state, enabling the vulnerability in subsequent calls
 * 
 * This creates a realistic stateful reentrancy where an attacker controlling the token contract can manipulate the claiming process across multiple transactions, potentially draining more tokens than intended.
 */
//
// compiler: solcjs -o ./build/contracts --optimize --abi --bin <this file>
//  version: 0.4.19+commit.c4cbbb05.Emscripten.clang
//
pragma solidity ^0.4.19;

contract owned {
  address public owner;
  function owned() public { owner = msg.sender; }
  function changeOwner( address newowner ) public onlyOwner {owner = newowner;}
  function closedown() public onlyOwner {selfdestruct(owner);}
  modifier onlyOwner {
    if (msg.sender != owner) { revert(); }
    _;
  }
}

// token should be ERC20-compliant and implement these functions
interface ERC20 {
  function transfer(address to, uint256 value) public;
  function balanceOf( address owner ) public constant returns (uint);
}

contract RTKICO is owned {

  ERC20   public tokenSC;   // token this ICO is selling
  address        treasury;  // [optional] where to direct incoming Ether
  uint    public start;     // seconds since Jan 1 1970 GMT
  uint    public duration;  // seconds
  uint    public tokpereth; // price NOTE: attention to decimals on setup

  function RTKICO( address _erc20,
                   address _treasury,
                   uint    _startSec,
                   uint    _durationSec,
                   uint    _tokpereth ) public {

    require( isContract(_erc20) );
    require( _tokpereth > 0 );

    if (_treasury != address(0))
      require( isContract(_treasury) );

    tokenSC = ERC20( _erc20 );
    treasury = _treasury;
    start = _startSec;
    duration = _durationSec;
    tokpereth = _tokpereth;
  }

  function setTreasury( address treas ) public onlyOwner { treasury = treas; }
  function setStart( uint newstart ) public onlyOwner { start = newstart; }
  function setRate( uint rate ) public onlyOwner { tokpereth = rate; }
  function setDuration( uint dur ) public onlyOwner { duration = dur; }

  function() public payable {
    if (now < start || now > (start + duration))
      revert();

    // Calculation:
    //   amountinwei * tokpereth/weipereth * (bonus+100)/100
    // = amountinwei * tokpereth/1e18 * (bonus+100)/100
    // = msg.value * tokpereth/1e20 * (bonus+100)
    uint qty =
      multiply( divide( multiply( msg.value, tokpereth ),
                        1e20 ),
                (bonus()+100) );

    if (qty > tokenSC.balanceOf(address(this)) || qty < 1)
      revert();

    tokenSC.transfer( msg.sender, qty );

    if (treasury != address(0)) treasury.transfer( msg.value );
  }

  // unsold tokens can be claimed by owner after sale ends
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public claimInProgress;
  mapping(address => uint) public partialClaimAmount;
  
  function claimUnsold() public onlyOwner {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    if ( now < (start + duration) )
      revert();

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Mark claim as in progress to allow partial claims
    claimInProgress[owner] = true;
    
    uint totalBalance = tokenSC.balanceOf(address(this));
    
    // If there's a partial claim amount from previous transaction, use it
    uint claimAmount = partialClaimAmount[owner] > 0 ? partialClaimAmount[owner] : totalBalance;
    
    // External call before state update - vulnerable to reentrancy
    tokenSC.transfer( owner, claimAmount );
    
    // State updates after external call
    partialClaimAmount[owner] = 0;
    claimInProgress[owner] = false;
  }
  
  function setPartialClaim(uint amount) public onlyOwner {
    require(claimInProgress[owner], "No claim in progress");
    require(amount <= tokenSC.balanceOf(address(this)), "Amount exceeds balance");
    partialClaimAmount[owner] = amount;
  }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function withdraw( uint amount ) public onlyOwner returns (bool) {
    require (amount <= this.balance);
    return owner.send( amount );
  }

  function bonus() internal constant returns(uint) {
    uint elapsed = now - start;

    if (elapsed < 1 weeks) return 20;
    if (elapsed < 2 weeks) return 15;
    if (elapsed < 4 weeks) return 10;
    return 0;
  }

  function isContract( address _a ) constant private returns (bool) {
    uint ecs;
    assembly { ecs := extcodesize(_a) }
    return ecs > 0;
  }

  // ref: github.com/OpenZeppelin/zeppelin-solidity/
  //      blob/master/contracts/math/SafeMath.sol
  function multiply(uint256 a, uint256 b) pure private returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function divide(uint256 a, uint256 b) pure private returns (uint256) {
    return a / b;
  }
}