/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by moving the external token.transfer() call BEFORE the state variable resets. This creates a window where the contract's state variables remain in their pre-reset state during the external call, allowing for cross-function reentrancy exploitation.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys a malicious token contract or exploits an upgradeable token
 * - The malicious token contract implements a transfer() function that calls back into the BETSale contract during execution
 * 
 * **Transaction 2 (Trigger):**
 * - Seller calls withdrawTokens() when total_bet_withdrawn == total_bet_purchased
 * - Function passes initial checks
 * - External call to token.transfer() occurs BEFORE state reset
 * - During token.transfer() execution, malicious token contract calls back to BETSale
 * 
 * **Transaction 3+ (Exploitation):**
 * - Inside the callback, the malicious token can call other BETSale functions like purchase() or withdraw()
 * - Since state variables haven't been reset yet, these functions see the old state values
 * - This allows manipulation of the contract's accounting and potentially draining funds
 * - The attacker can make multiple calls within the callback, each seeing inconsistent state
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation:** The vulnerability requires that total_bet_withdrawn equals total_bet_purchased, which can only happen through multiple purchase/withdraw transactions over time
 * 2. **Callback Window:** The reentrancy window only exists during the external call, requiring the malicious token to be pre-deployed and configured
 * 3. **Cross-Function Dependencies:** The exploit leverages the fact that other functions (purchase, withdraw) depend on the state variables that are temporarily in an inconsistent state
 * 
 * The vulnerability is realistic because it follows the classic "checks-effects-interactions" pattern violation, where external calls are made before state changes are finalized.
 */
pragma solidity ^0.4.11;

/*
  Allows owner/seller to deposit ETH in order to participate in
  an ICO on behalf of the contract so that users can buy directly
  from this contract with assurances that they will receive their
  tokens via a user-invoked withdrawal() call once the ICO token
  creator releases tokens for trading.

  This affords users the ability to reserve/claim tokens that they
  were not able to buy in an ICO, before they hit the exchanges.

*/
contract DaoCasinoToken {
  uint256 public CAP;
  uint256 public totalEthers;
  function proxyPayment(address participant) payable;
  function transfer(address _to, uint _amount) returns (bool success);
  function balanceOf(address _owner) constant returns (uint256 balance);
}

contract BETSale {
  // Store the amount of BET purchased by a buyer
  mapping (address => uint256) public bet_purchased;

  // Store the amount of ETH sent in by a buyer. Good to have this record just in case
  mapping (address => uint256) public eth_sent;

  // Total BET available to sell
  uint256 public total_bet_available;

  // Total BET purchased by all buyers
  uint256 public total_bet_purchased;

  // Total BET withdrawn by all buyers
  uint256 public total_bet_withdrawn;

  // BET per ETH (price)
  uint256 public price_per_eth = 900;

  //  BET token contract address (IOU offering)
  DaoCasinoToken public token = DaoCasinoToken(0x725803315519de78D232265A8f1040f054e70B98);

  // The seller's address
  address seller = 0xB00Ae1e677B27Eee9955d632FF07a8590210B366;

  // Halt further purchase ability just in case
  bool public halt_purchases;

  /*
    Safety to withdraw all tokens, ONLY if all buyers have already withdrawn their purchases
  */
  function withdrawTokens() {
    if(msg.sender != seller) throw;
    if(total_bet_withdrawn != total_bet_purchased) throw;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Transfer tokens first to allow for proper accounting
    uint256 balance = token.balanceOf(address(this));
    token.transfer(seller, balance);

    // reset everything after successful transfer
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    total_bet_available = 0;
    total_bet_purchased = 0;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    total_bet_withdrawn = 0;
  }

  /*
    Safety to withdraw ETH
  */
  function withdrawETH() {
    if(msg.sender != seller) throw;
    msg.sender.transfer(this.balance);
  }

  /*
    Initiate ICO purchase
  */
  function buyTokens() payable {
    if(msg.sender != seller) throw;
    if(token.totalEthers() < token.CAP()) {
      token.proxyPayment.value(this.balance)(address(this));
    }
  }

  /*
    Update available BET to purchase
  */
  function updateAvailability(uint256 _bet_amount) {
    if(msg.sender != seller) throw;
    total_bet_available += _bet_amount;
  }

  /*
    Update BET price
  */
  function updatePrice(uint256 _price) {
    if(msg.sender != seller) throw;
    price_per_eth = _price;
  }

  /*
    Safety to prevent anymore purchases/sales from occurring in the event of
    unforeseen issue. Buyer token withdrawals still allowed
  */
  function haltPurchases() {
    if(msg.sender != seller) throw;
    halt_purchases = true;
  }

  function resumePurchases() {
    if(msg.sender != seller) throw;
    halt_purchases = false;
  }

  function withdraw() {
    // Dismiss any early or ill attempts at withdrawing
    if(token.balanceOf(address(this)) == 0 || bet_purchased[msg.sender] == 0) throw;

    uint256 bet_to_withdraw = bet_purchased[msg.sender];

    // Clear record of buyer's BET balance before transferring out
    bet_purchased[msg.sender] = 0;

    total_bet_withdrawn += bet_to_withdraw;

    // Distribute tokens to the buyer
    if(!token.transfer(msg.sender, bet_to_withdraw)) throw;
  }

  function purchase() payable {
    if(halt_purchases) throw;

    // Determine amount of tokens user wants to/can buy
    uint256 bet_to_purchase = price_per_eth * msg.value;

    // Check if we have enough BET left to sell
    if((total_bet_purchased + bet_to_purchase) > total_bet_available) throw;

    // Update the amount of BET purchased by user. Also keep track of the total ETH they sent in
    bet_purchased[msg.sender] += bet_to_purchase;
    eth_sent[msg.sender] += msg.value;

    // Update the total amount of BET purchased by all buyers over all periods of availability
    total_bet_purchased += bet_to_purchase;

    // Tokens are clearly in the contract, therefore we can release ETH to seller's address
    seller.transfer(msg.value);
  }

  // Fallback function/entry point
  function () payable {
    if(msg.value == 0) {
      withdraw();
    }
    else {
      if(msg.sender == seller) {
        return;
      }
      purchase();
    }
  }
}