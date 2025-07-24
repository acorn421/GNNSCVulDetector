/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability where users can schedule withdrawals with early access bonuses. The vulnerability is stateful and multi-transaction: 1) Users must first call scheduleWithdrawal() to set up the withdrawal schedule, 2) They must wait for the delay period, 3) They call executeScheduledWithdrawal() to claim tokens with potential bonus. Miners can manipulate timestamps to either qualify for bonuses they shouldn't get or to bypass timing restrictions. The vulnerability persists across multiple transactions and requires accumulated state changes in the withdrawal_schedule and early_withdrawal_bonus mappings.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Withdrawal scheduling system for early access
  mapping (address => uint256) public withdrawal_schedule;
  mapping (address => uint256) public early_withdrawal_bonus;
  uint256 public withdrawal_delay = 86400; // 24 hours
  uint256 public early_withdrawal_window = 3600; // 1 hour window
  // === END mapping declarations for fallback injection ===

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
    Schedule a withdrawal for early access with bonus
  */
  function scheduleWithdrawal(uint256 _amount) {
    if(bet_purchased[msg.sender] < _amount) throw;
    if(withdrawal_schedule[msg.sender] != 0) throw; // Already scheduled

    withdrawal_schedule[msg.sender] = block.timestamp + withdrawal_delay;
    // Early withdrawal bonus if scheduled within the first hour of purchase
    if(block.timestamp % early_withdrawal_window < 600) { // 10 minute window
      early_withdrawal_bonus[msg.sender] = _amount / 10; // 10% bonus
    }
  }

  /*
    Execute scheduled withdrawal with potential bonus
  */
  function executeScheduledWithdrawal() {
    if(withdrawal_schedule[msg.sender] == 0) throw;
    if(block.timestamp < withdrawal_schedule[msg.sender]) throw;

    uint256 base_amount = bet_purchased[msg.sender];
    uint256 bonus_amount = early_withdrawal_bonus[msg.sender];
    uint256 total_amount = base_amount + bonus_amount;

    // Vulnerable: Miner can manipulate timestamp to qualify for bonus
    if(block.timestamp <= withdrawal_schedule[msg.sender] + early_withdrawal_window) {
      // Still within early access window, apply bonus
      total_amount += bonus_amount;
    }

    // Clear user's records
    bet_purchased[msg.sender] = 0;
    withdrawal_schedule[msg.sender] = 0;
    early_withdrawal_bonus[msg.sender] = 0;

    total_bet_withdrawn += total_amount;

    if(!token.transfer(msg.sender, total_amount)) throw;
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
