/*
 * ===== SmartInject Injection Details =====
 * Function      : purchase
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability through the following key modifications:
 * 
 * **1. Changes Made:**
 * - Added a referral bonus callback mechanism triggered when user's accumulated ETH reaches 5 ether
 * - Moved the `total_bet_purchased` state update to AFTER the external call
 * - Added a user-controlled callback using `msg.sender.call("")` that creates a reentrancy vector
 * - The callback is only triggered based on accumulated state (`eth_sent[msg.sender] >= 5 ether`)
 * 
 * **2. Multi-Transaction Exploitation Pattern:**
 * - **Transaction 1-N**: User makes multiple smaller purchases (e.g., 1 ETH each) to accumulate ETH in their `eth_sent` mapping
 * - **Transaction N+1**: When accumulated `eth_sent` reaches 5 ETH, the callback is triggered
 * - **Reentrancy Attack**: During the callback, the attacker can re-enter `purchase()` before `total_bet_purchased` is updated
 * - **State Exploitation**: The attacker can exploit the inconsistent state where their individual purchase tracking is updated but the global counter is not
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - The vulnerability requires **state accumulation** across multiple transactions to reach the 5 ETH threshold
 * - Each transaction builds up the `eth_sent[msg.sender]` mapping until the callback condition is met
 * - The reentrancy vector only becomes available after sufficient accumulated purchases
 * - Single-transaction exploitation is impossible because the callback condition depends on cumulative state from previous transactions
 * - The attacker must strategically build up their accumulated ETH balance over multiple transactions to trigger the vulnerable callback path
 * 
 * **4. Exploitation Mechanism:**
 * - The callback occurs after individual state updates but before global state updates
 * - This creates a window where `bet_purchased[msg.sender]` and `eth_sent[msg.sender]` are updated, but `total_bet_purchased` is not
 * - During reentrancy, the attacker can purchase more tokens while the availability check uses stale `total_bet_purchased` values
 * - This allows purchasing beyond the intended token limits by exploiting the state inconsistency across multiple transactions
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

    // reset everything
    total_bet_available = 0;
    total_bet_purchased = 0;
    total_bet_withdrawn = 0;

    token.transfer(seller, token.balanceOf(address(this)));
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // VULNERABILITY: Update state before external call to enable cross-transaction exploitation
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    bet_purchased[msg.sender] += bet_to_purchase;
    eth_sent[msg.sender] += msg.value;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Multi-transaction reentrancy setup: Allow referral bonus callback for accumulated purchases
    if(eth_sent[msg.sender] >= 5 ether) {
        // Callback to user-controlled contract for bonus calculation
        // This creates a reentrancy vector when user has accumulated enough ETH
        (bool success, ) = msg.sender.call("");
        if(!success) throw;
    }

    // Update the total amount of BET purchased by all buyers over all periods of availability
    // VULNERABILITY: This critical state update happens AFTER the external call
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    total_bet_purchased += bet_to_purchase;

    // Tokens are clearly in the contract, therefore we can release ETH to seller's address
    seller.transfer(msg.value);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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