/*
 * ===== SmartInject Injection Details =====
 * Function      : extendSaleIfActive
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
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The contract tracks extension state across multiple transactions (extensionCount, lastExtensionTime) and relies on block.timestamp for critical timing decisions. A malicious miner can manipulate timestamps across multiple blocks to either prevent legitimate extensions or force unwanted extensions, requiring multiple transactions to exploit as the state must be built up over time.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Extension tracking state
  uint public extensionCount = 0;
  uint public maxExtensions = 3;
  uint public lastExtensionTime = 0;
  
  // Allows extending the sale duration if certain conditions are met
  function extendSaleIfActive(uint additionalDuration) public onlyOwner {
    // Check if we're currently within the active sale period
    if (now < start || now > (start + duration)) {
      revert();
    }
    
    // Check extension limits
    if (extensionCount >= maxExtensions) {
      revert();
    }
    
    // Vulnerable timestamp dependence: relies on block.timestamp for timing decisions
    // This creates a multi-transaction vulnerability where miners can manipulate
    // the timestamp to either force or prevent extensions
    
    // Check if enough time has passed since last extension (24 hours)
    if (lastExtensionTime > 0 && (now - lastExtensionTime) < 86400) {
      revert();
    }
    
    // Update state variables - this makes the vulnerability stateful
    extensionCount++;
    lastExtensionTime = now;
    duration += additionalDuration;
  }
  
  // Function to check if extension is possible (getter for state)
  function canExtendSale() public view returns (bool) {
    if (now < start || now > (start + duration)) {
      return false;
    }
    if (extensionCount >= maxExtensions) {
      return false;
    }
    if (lastExtensionTime > 0 && (now - lastExtensionTime) < 86400) {
      return false;
    }
    return true;
  }
  // === END FALLBACK INJECTION ===

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
