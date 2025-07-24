/*
 * ===== SmartInject Injection Details =====
 * Function      : flag
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction Timestamp Dependence vulnerability into the flag function. The vulnerability introduces time-based restrictions using block.timestamp and block.number that create predictable timing windows and multi-transaction exploitation opportunities.
 * 
 * **Specific Changes Made:**
 * 1. **Added Time Window Restrictions**: Flagging trustees can only occur during the second half of each day (timeWindow >= 43200), calculated using `block.timestamp % 86400`
 * 2. **Introduced State Persistence**: Added `flagTimestamp[ix]` and `flagBlock[ix]` to track when flags were set, creating persistent state between transactions
 * 3. **Multi-Transaction Timing Requirements**: Unflagging requires waiting at least 1 hour (3600 seconds) and 240 blocks, enforced through multiple timestamp/block checks
 * 4. **Vulnerable Time Calculations**: Uses both `block.timestamp` and `block.number` as time proxies, which can be manipulated by miners
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Treasurer flags a trustee during the allowed time window (second half of day)
 * 2. **Manipulation Period**: Miner can manipulate block timestamps within the 15-second tolerance to extend or compress the perceived time
 * 3. **Transaction 2**: During a critical voting period, the treasurer attempts to unflag the trustee, but the timing restrictions can be exploited by miners to either prevent or allow the unflagging at strategically advantageous moments
 * 4. **Transaction 3**: If a proposal is being voted on, the flag state (controlled by the manipulated timing) directly affects whether the trustee can participate in the `approve()` function
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires at least 2 transactions: one to set the flag with timestamp/block recording, and another to attempt unflagging after the time constraints
 * - The persistent state (`flagTimestamp` and `flagBlock`) must be established in an earlier transaction to enable the timing-based exploitation
 * - The time-based restrictions create windows that can only be exploited across multiple blocks/transactions, not within a single atomic transaction
 * - The impact on governance (trustee voting rights) only becomes apparent when the `approve()` function is called in subsequent transactions
 * 
 * This creates a realistic governance attack where miners could collude with malicious actors to manipulate voting outcomes by controlling when trustees can be flagged/unflagged during critical proposal periods.
 */
//
// compiler: solcjs -o ./build --optimize --abi --bin <this file>
//  version: 0.4.18+commit.9cf6e910.Emscripten.clang
//
pragma solidity ^0.4.18;

// ---------------------------------------------------------------------------
// Treasury smart contract. Owner (Treasurer) is only account that can submit
// proposals, yet cannot actually spend. The Treasurer appoints Trustees to
// approve spending proposals. Funds are released automatically once a
// proposal is approved by a simple majority of trustees.
//
// Trustees can be flagged as inactive by the Treasurer. An inactive Trustee
// cannot vote. The Treasurer may set/reset flags. The Treasurer can replace
// any Trustee, though any approvals already made will stand.
// ---------------------------------------------------------------------------

contract owned
{
  address public treasurer;
  function owned() public { treasurer = msg.sender; }

  modifier onlyTreasurer {
    require( msg.sender == treasurer );
    _;
  }

  function setTreasurer( address newTreasurer ) public onlyTreasurer
  { treasurer = newTreasurer; }

  function closedown() public onlyTreasurer { selfdestruct( treasurer ); }
}

contract Treasury is owned {

  event Added( address indexed trustee );
  event Flagged( address indexed trustee, bool isRaised );
  event Replaced( address indexed older, address indexed newer );

  event Proposal( address indexed payee, uint amt, string eref );
  event Approved( address indexed approver,
                  address indexed to,
                  uint amount,
                  string eref );
  event Spent( address indexed payee, uint amt, string eref );

  struct SpendProposal {
    address   payee;
    uint      amount;
    string    eref;
    address[] approvals;
  }

  SpendProposal[] proposals;
  address[]       trustees;
  bool[]          flagged; // flagging trustee disables from voting
  uint256[]       flagTimestamp; // timestamp when flagged/unflagged
  uint256[]       flagBlock;     // block.number when flagged/unflagged

  function Treasury() public {}

  function() public payable {}

  function add( address trustee ) public onlyTreasurer
  {
    require( trustee != treasurer ); // separate Treasurer and Trustees

    for (uint ix = 0; ix < trustees.length; ix++)
      if (trustees[ix] == trustee) return;

    trustees.push(trustee);
    flagged.push(false);
    flagTimestamp.push(0);
    flagBlock.push(0);

    Added( trustee );
  }

  function flag( address trustee, bool isRaised ) public onlyTreasurer
  {
    for( uint ix = 0; ix < trustees.length; ix++ )
      if (trustees[ix] == trustee)
      {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Timestamp-based flagging logic with vulnerability
        if (isRaised) {
          // Flag can only be set during certain time windows based on block timestamp
          // This creates predictable timing that can be exploited
          uint256 timeWindow = block.timestamp % 86400; // 24-hour cycle
          require(timeWindow >= 43200, "Flagging only allowed in second half of day");
          
          flagged[ix] = isRaised;
          flagTimestamp[ix] = block.timestamp;
          flagBlock[ix] = block.number;
        } else {
          // Unflagging has additional timestamp-based restrictions
          // This creates a multi-transaction vulnerability window
          if (flagTimestamp[ix] > 0) {
            uint256 flagAge = block.timestamp - flagTimestamp[ix];
            // Flags can only be removed after a minimum time period
            // But this time period can be manipulated by miners
            require(flagAge >= 3600, "Must wait at least 1 hour before unflagging");
            
            // Additional vulnerability: use block.number as time proxy
            uint256 blockAge = block.number - flagBlock[ix];
            require(blockAge >= 240, "Must wait at least 240 blocks before unflagging");
          }
          
          flagged[ix] = isRaised;
          flagTimestamp[ix] = 0;
          flagBlock[ix] = 0;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Flagged( trustees[ix], flagged[ix] );
      }
  }

  function replace( address older, address newer ) public onlyTreasurer
  {
    for( uint ix = 0; ix < trustees.length; ix++ )
      if (trustees[ix] == older)
      {
        Replaced( trustees[ix], newer );
        trustees[ix] = newer;
        flagged[ix] = false;
        flagTimestamp[ix] = 0;
        flagBlock[ix] = 0;
      }
  }

  function proposal( address _payee, uint _wei, string _eref )
  public onlyTreasurer
  {
    bytes memory erefb = bytes(_eref);
    require(    _payee != address(0)
             && _wei > 0
             && erefb.length > 0
             && erefb.length <= 32 );

    uint ix = proposals.length++;
    proposals[ix].payee = _payee;
    proposals[ix].amount = _wei;
    proposals[ix].eref = _eref;

    Proposal( _payee, _wei, _eref );
  }

  function approve( address _payee, uint _wei, string _eref ) public
  {
    // ensure caller is a trustee in good standing
    bool senderValid = false;
    for (uint tix = 0; tix < trustees.length; tix++) {
      if (msg.sender == trustees[tix]) {
        if (flagged[tix])
          revert();

        senderValid = true;
      }
    }
    if (!senderValid) revert();

    // find the matching proposal not already actioned (amount would be 0)
    for (uint pix = 0; pix < proposals.length; pix++)
    {
      if (    proposals[pix].payee == _payee
           && proposals[pix].amount == _wei
           && strcmp(proposals[pix].eref, _eref) )
      {
        // prevent voting twice
        for (uint ap = 0; ap < proposals[pix].approvals.length; ap++)
        {
          if (msg.sender == proposals[pix].approvals[ap])
            revert();
        }

        proposals[pix].approvals.push( msg.sender );

        Approved( msg.sender,
                  proposals[pix].payee,
                  proposals[pix].amount,
                  proposals[pix].eref );

        if ( proposals[pix].approvals.length > (trustees.length / 2) )
        {
          require( this.balance >= proposals[pix].amount );

          if ( proposals[pix].payee.send(proposals[pix].amount) )
          {
            Spent( proposals[pix].payee,
                   proposals[pix].amount,
                   proposals[pix].eref );

            proposals[pix].amount = 0; // prevent double spend
          }
        }
      }
    }
  }

  function strcmp( string _a, string _b ) pure internal returns (bool)
  {
    return keccak256(_a) == keccak256(_b);
  }
}
