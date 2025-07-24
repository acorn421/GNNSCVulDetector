/*
 * ===== SmartInject Injection Details =====
 * Function      : claimUnsold
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a multi-phase claiming process that creates several timestamp dependence vulnerabilities:
 * 
 * **Specific Changes Made:**
 * 1. **State Variables Added**: claimInitBlock, claimConfirmBlock, claimAttempts, and CLAIM_WINDOW constant
 * 2. **Multi-Phase Logic**: Function now requires 3 separate transactions to complete
 * 3. **Block-Based Timing**: Uses block.number and block.timestamp for validation
 * 4. **Timestamp Calculations**: Vulnerable time calculations using block properties
 * 5. **Pseudo-Random Validation**: Uses timestamp-based seed for final validation
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * **Transaction 1 (Initialize):**
 * - Owner calls claimUnsold() to start the process
 * - Sets claimInitBlock to current block.number
 * - Function returns without transferring tokens
 * 
 * **Transaction 2 (Confirmation):**
 * - Owner calls claimUnsold() again after waiting 2+ blocks
 * - Vulnerable timestamp calculation: timeDiff = now - (claimInitBlock * 15)
 * - Miners can manipulate block.timestamp to affect time window validation
 * - If timestamp is manipulated to make timeDiff > CLAIM_WINDOW, process resets
 * 
 * **Transaction 3 (Final Claim):**
 * - Owner calls claimUnsold() a third time
 * - Vulnerable pseudo-random validation using block.blockhash() and timestamp
 * - Miners can manipulate block.timestamp to influence the validation result
 * - If validation fails, owner must restart entire process
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **State Accumulation**: Each transaction builds on previous state (block numbers, attempt count)
 * 2. **Time-Based Validation**: Requires real time passage between transactions
 * 3. **Persistent Vulnerability**: Timestamp manipulation affects the entire multi-step process
 * 4. **Cannot be Atomic**: The validation logic depends on different block properties across transactions
 * 
 * **Exploitation Vectors:**
 * - **Miner Manipulation**: Miners can adjust block.timestamp within the 15-minute tolerance to influence validation
 * - **Timestamp Drift**: Natural timestamp variations between blocks can cause unexpected failures
 * - **Replay Attacks**: Attacker could potentially influence the timing of transactions
 * - **Denial of Service**: Manipulation could force repeated restarts of the claiming process
 * 
 * This creates a realistic vulnerability where the owner must navigate a multi-step process vulnerable to timestamp manipulation at each phase.
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

  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
  uint public claimInitBlock;
  uint public claimConfirmBlock;
  uint public claimAttempts;
  uint constant CLAIM_WINDOW = 300; // 5 minutes
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
  function claimUnsold() public onlyOwner {
    if ( now < (start + duration) )
      revert();

    // Multi-phase claiming process with timestamp dependence
    if (claimAttempts == 0) {
        // Phase 1: Initialize claim with block timestamp
        claimInitBlock = block.number;
        claimAttempts = 1;
        return;
    } else if (claimAttempts == 1) {
        // Phase 2: Confirmation window - vulnerable to timestamp manipulation
        // Must wait at least 2 blocks but within 5 minutes
        if (block.number <= claimInitBlock + 1) {
            revert("Must wait at least 2 blocks");
        }

        // Using block.timestamp for time window validation - VULNERABLE
        uint timeDiff = now - (claimInitBlock * 15); // Assume 15 sec/block
        if (timeDiff > CLAIM_WINDOW) {
            // Reset if too much time passed
            claimAttempts = 0;
            claimInitBlock = 0;
            revert("Claim window expired, restart process");
        }

        claimConfirmBlock = block.number;
        claimAttempts = 2;
        return;
    } else if (claimAttempts == 2) {
        // Phase 3: Final claim - timestamp-dependent validation
        // Vulnerable calculation using block properties
        uint blockHash = uint(block.blockhash(claimConfirmBlock));
        uint timeBasedSeed = now + claimInitBlock + claimConfirmBlock;

        // Pseudo-random validation using timestamp - VULNERABLE
        if ((blockHash + timeBasedSeed) % 10 < 3) {
            revert("Timestamp validation failed, try again");
        }

        // Reset state and transfer tokens
        claimAttempts = 0;
        claimInitBlock = 0;
        claimConfirmBlock = 0;
        tokenSC.transfer( owner, tokenSC.balanceOf(address(this)) );
    }
  }
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
