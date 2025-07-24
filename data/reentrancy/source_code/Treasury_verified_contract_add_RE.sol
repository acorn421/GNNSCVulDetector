/*
 * ===== SmartInject Injection Details =====
 * Function      : add
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (trustee) before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Exploitation Scenario:**
 * 1. **Transaction 1**: Treasurer calls `add()` with a malicious trustee contract
 * 2. **During External Call**: The malicious trustee contract's `validate()` function re-enters the `add()` function
 * 3. **Reentrancy Attack**: The reentrant call bypasses the duplicate check (since trustees array hasn't been updated yet) and adds the same trustee multiple times
 * 4. **State Corruption**: This results in the trustees array containing duplicate entries, and the flagged array being out of sync
 * 5. **Multi-Transaction Exploitation**: Subsequent transactions can exploit the corrupted state where the same trustee appears multiple times, potentially gaining disproportionate voting power in the approval process
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability requires the initial call to trigger the external call
 * - The reentrant call occurs during the same transaction but creates persistent state corruption
 * - The corrupted state (duplicate trustees) can only be exploited in subsequent transactions when the `approve()` function is called
 * - The exploit's impact manifests across multiple proposal/approval cycles
 * 
 * **Key Vulnerability Points:**
 * - External call made before state updates (violates Checks-Effects-Interactions)
 * - User-controlled contract can manipulate execution flow
 * - State consistency between trustees and flagged arrays can be broken
 * - No reentrancy guards protect against this attack vector
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
  constructor() public { treasurer = msg.sender; }

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

  constructor() public {}

  function() public payable {}

  function add( address trustee ) public onlyTreasurer
  {
    require( trustee != treasurer ); // separate Treasurer and Trustees

    for (uint ix = 0; ix < trustees.length; ix++)
      if (trustees[ix] == trustee) return;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // External call to validate trustee before adding - vulnerable to reentrancy
    // This call happens before state updates, allowing reentrant calls to manipulate state
    {
      uint size;
      assembly { size := extcodesize(trustee) }
      if (size > 0) {
        // Call validate function on trustee contract if it exists
        trustee.call(abi.encodeWithSignature("validate()"));
        // Continue regardless of success - this is the vulnerability
      }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
