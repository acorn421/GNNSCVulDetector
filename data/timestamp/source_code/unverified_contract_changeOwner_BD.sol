/*
 * ===== SmartInject Injection Details =====
 * Function      : changeOwner
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where ownership transfers require a time delay between request and execution. The vulnerability exploits block.timestamp manipulation across multiple transactions: (1) First transaction records the transfer request with current timestamp, (2) Second transaction completes the transfer after the delay period. Miners can manipulate block timestamps within the ~900 second tolerance to either accelerate or delay ownership transfers. The state persists between transactions through the ownershipTransferRequests mapping, making this a multi-transaction vulnerability that requires coordination across multiple blocks to exploit timing windows.
 */
//
// compiler: solcjs -o ./build/contracts --optimize --abi --bin <this file>
//  version: 0.4.19+commit.c4cbbb05.Emscripten.clang
//
pragma solidity ^0.4.19;

contract owned {
  address public owner;
  function owned() public { owner = msg.sender; }
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public ownershipTransferRequests;
uint public constant TRANSFER_DELAY = 1 days;

function changeOwner( address newowner ) public onlyOwner {
    // If this is the first request for this address, record the timestamp
    if (ownershipTransferRequests[newowner] == 0) {
        ownershipTransferRequests[newowner] = block.timestamp;
        return; // Exit early, ownership not transferred yet
    }
    
    // Check if sufficient time has passed since the initial request
    require(block.timestamp >= ownershipTransferRequests[newowner] + TRANSFER_DELAY, "Transfer delay not met");
    
    // Transfer ownership and clean up the request
    owner = newowner;
    ownershipTransferRequests[newowner] = 0;
}
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
  function claimUnsold() public onlyOwner {
    if ( now < (start + duration) )
      revert();

    tokenSC.transfer( owner, tokenSC.balanceOf(address(this)) );
  }

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