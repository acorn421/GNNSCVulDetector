/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a preliminary external call to the payee's fallback function before the payment is sent. This creates a window where the malicious payee can re-enter the approve function while the proposal amount is still non-zero, allowing multiple withdrawals of the same proposal across different transactions. The vulnerability requires: 1) Initial trustee approval transaction to trigger the external call, 2) Malicious payee re-entering through the callback to call approve again, 3) State persistence between transactions where the proposal amount remains unchanged until the original call stack completes. The attack exploits the fact that state changes (zeroing the amount) occur after the external calls, and the intermediate call() provides an additional reentrancy vector before the actual payment.
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

  function add( address trustee ) public onlyTreasurer
  {
    require( trustee != treasurer ); // separate Treasurer and Trustees

    for (uint ix = 0; ix < trustees.length; ix++)
      if (trustees[ix] == trustee) return;

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

          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          // Call payee's fallback function to notify of incoming payment
          // This allows payee to prepare for receiving funds
          if ( proposals[pix].payee.call() )
          {
            // Now send the actual payment
            if ( proposals[pix].payee.send(proposals[pix].amount) )
            {
              Spent( proposals[pix].payee,
                     proposals[pix].amount,
                     proposals[pix].eref );

              proposals[pix].amount = 0; // prevent double spend
            }
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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