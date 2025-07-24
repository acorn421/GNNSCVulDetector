/*
 * ===== SmartInject Injection Details =====
 * Function      : add
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding time-based access controls that depend on block.timestamp. The vulnerability has two components:
 * 
 * 1. **Time Window Restriction**: Trustees can only be added when block.timestamp is divisible by 300 (every 5 minutes), creating predictable "safe" periods
 * 2. **Rate Limiting**: Enforces a 60-second cooldown between trustee additions using persistent state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker (treasurer) attempts to add a malicious trustee during a regular timestamp, but fails due to the modulo restriction
 * - **Transaction 2**: Attacker waits or manipulates block timestamps to hit a "safe" window (divisible by 300)
 * - **Transaction 3**: If multiple trustees need to be added, attacker must wait for the 60-second cooldown period and hit another safe window
 * 
 * **Exploitation Methods:**
 * 1. **Miner Manipulation**: If the attacker controls mining, they can manipulate block timestamps to create artificial "safe" periods
 * 2. **Predictable Timing**: The modulo 300 creates predictable windows every 5 minutes that can be exploited
 * 3. **State Persistence**: The lastAdditionTimestamp creates a persistent state that affects future transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires multiple transactions because the attacker needs to time their actions across different blocks
 * - State from previous transactions (lastAdditionTimestamp) directly affects the exploitability of future transactions
 * - Cannot be exploited in a single transaction due to the timing constraints and state dependencies between calls
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

  function Treasury() public {}

  function() public payable {}

  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) private trusteeAdditionTime;
uint private lastAdditionTimestamp;

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function add( address trustee ) public onlyTreasurer
  {
    require( trustee != treasurer ); // separate Treasurer and Trustees

    for (uint ix = 0; ix < trustees.length; ix++)
      if (trustees[ix] == trustee) return;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Time-based access control: Only allow adding trustees during "safe" periods
    // Safe periods are defined as blocks where timestamp is divisible by 300 (5 minutes)
    require(block.timestamp % 300 == 0, "Can only add trustees during safe time windows");
    
    // Rate limiting: Prevent rapid trustee additions
    require(block.timestamp >= lastAdditionTimestamp + 60, "Must wait at least 1 minute between trustee additions");
    
    // Store the addition time for this trustee
    trusteeAdditionTime[trustee] = block.timestamp;
    lastAdditionTimestamp = block.timestamp;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    trustees.push(trustee);
    flagged.push(false);

    Added( trustee );
  }

  function flag( address trustee, bool isRaised ) public onlyTreasurer
  {
    for( uint ix = 0; ix < trustees.length; ix++ )
      if (trustees[ix] == trustee)
      {
        flagged[ix] = isRaised;
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