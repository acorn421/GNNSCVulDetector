/*
 * ===== SmartInject Injection Details =====
 * Function      : paySeller
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by reordering the external call to occur before the state update (halt_purchases = true). This creates a vulnerable window where a malicious seller can re-enter the contract during the transfer, potentially calling other functions while halt_purchases is still false. The vulnerability requires multiple transactions: (1) Initial setup where attacker becomes seller, (2) Calling paySeller() which triggers reentrancy, (3) Reentrant calls to purchase() or other functions during the transfer, exploiting the fact that halt_purchases hasn't been set yet, and (4) Completing the exploitation across multiple reentrant calls to drain additional funds or manipulate state.
 */
pragma solidity ^0.4.11;

/*
  Allows buyers to securely/confidently buy recent ICO tokens that are
  still non-transferrable, on an IOU basis. Like HitBTC, but with protection,
  control, and guarantee of either the purchased tokens or ETH refunded.

  The Buyer's ETH will be locked into the contract until the purchased
  IOU/tokens arrive here and are ready for the buyer to invoke withdraw(),
  OR until cut-off time defined below is exceeded and as a result ETH
  refunds/withdrawals become enabled.

  In other words, the seller must fulfill the IOU token purchases any time
  before the cut-off time defined below, otherwise the buyer gains the
  ability to withdraw their ETH.

  The buyer's ETH will ONLY be released to the seller AFTER the adequate
  amount of tokens have been deposited for ALL purchases.

  Estimated Time of Distribution: 3-5 weeks from ICO according to TenX
  Cut-off Time: ~ August 9, 2017

  Greetz: blast
  foobarbizarre@gmail.com (Please report any findings or suggestions for a 1 ETH bounty!)

  Thank you
*/

contract ERC20 {
  function transfer(address _to, uint _value);
  function balanceOf(address _owner) constant returns (uint balance);
}

contract IOU {
  // Store the amount of IOUs purchased by a buyer
  mapping (address => uint256) public iou_purchased;

  // Store the amount of ETH sent in by a buyer
  mapping (address => uint256) public eth_sent;

  // Total IOUs available to sell
  uint256 public total_iou_available = 40000000000000000000000;

  // Total IOUs purchased by all buyers
  uint256 public total_iou_purchased;

  // Total IOU withdrawn by all buyers (keep track to protect buyers)
  uint256 public total_iou_withdrawn;

  // IOU per ETH (price)
  uint256 public price_per_eth = 100;

  //  PAY token contract address (IOU offering)
  ERC20 public token = ERC20(0xB97048628DB6B661D4C2aA833e95Dbe1A905B280);

  // The seller's address (to receive ETH upon distribution, and for authing safeties)
  address seller = 0x496529c12e229e9787D37E5EFA2E48B651e755B0;

  // Halt further purchase ability just in case
  bool public halt_purchases;

  modifier pwner() { if(msg.sender != seller) throw; _; }

  /*
    Safety to withdraw unbought tokens back to seller. Ensures the amount
    that buyers still need to withdraw remains available
  */
  function withdrawTokens() pwner {
    token.transfer(seller, token.balanceOf(address(this)) - (total_iou_purchased - total_iou_withdrawn));
  }

  /*
    Safety to prevent anymore purchases/sales from occurring in the event of
    unforeseen issue. Buyer withdrawals still remain enabled.
  */
  function haltPurchases() pwner {
    halt_purchases = true;
  }

  function resumePurchases() pwner {
    halt_purchases = false;
  }

  /*
    Update available IOU to purchase
  */
  function updateAvailability(uint256 _iou_amount) pwner {
    if(_iou_amount < total_iou_purchased) throw;

    total_iou_available = _iou_amount;
  }

  /*
    Update IOU price
  */
  function updatePrice(uint256 _price) pwner {
    price_per_eth = _price;
  }

  /*
    Release buyer's ETH to seller ONLY if amount of contract's tokens balance
    is >= to the amount that still needs to be withdrawn. Protects buyer.

    The seller must call this function manually after depositing the adequate
    amount of tokens for all buyers to collect

    This effectively ends the sale, but withdrawals remain open
  */
  function paySeller() pwner {
    // not enough tokens in balance to release ETH, protect buyer and abort
    if(token.balanceOf(address(this)) < (total_iou_purchased - total_iou_withdrawn)) throw;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Store the amount to transfer before external call
    uint256 balance_to_transfer = this.balance;

    // Release buyer's ETH to the seller BEFORE state changes
    seller.transfer(balance_to_transfer);

    // Halt further purchases to prevent accidental over-selling
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    halt_purchases = true;
  }

  function withdraw() payable {
    /*
      Main mechanism to ensure a buyer's purchase/ETH/IOU is safe.

      Refund the buyer's ETH if we're beyond the cut-off date of our distribution
      promise AND if the contract doesn't have an adequate amount of tokens
      to distribute to the buyer. Time-sensitive buyer/ETH protection is only
      applicable if the contract doesn't have adequate tokens for the buyer.

      The "adequacy" check prevents the seller and/or third party attacker
      from locking down buyers' ETH by sending in an arbitrary amount of tokens.

      If for whatever reason the tokens remain locked for an unexpected period
      beyond the time defined by block.number, patient buyers may still wait until
      the contract is filled with their purchased IOUs/tokens. Once the tokens
      are here, they can initiate a withdraw() to retrieve their tokens. Attempting
      to withdraw any sooner (after the block has been mined, but tokens not arrived)
      will result in a refund of buyer's ETH.
    */
    if(block.number > 4199999 && iou_purchased[msg.sender] > token.balanceOf(address(this))) {
      // We didn't fulfill our promise to have adequate tokens withdrawable at xx time
      // Refund the buyer's ETH automatically instead
      uint256 eth_to_refund = eth_sent[msg.sender];

      // If the user doesn't have any ETH or tokens to withdraw, get out ASAP
      if(eth_to_refund == 0 || iou_purchased[msg.sender] == 0) throw;

      // Adjust total purchased so others can buy, and so numbers align with total_iou_withdrawn
      total_iou_purchased -= iou_purchased[msg.sender];

      // Clear record of buyer's ETH and IOU balance before refunding
      eth_sent[msg.sender] = 0;
      iou_purchased[msg.sender] = 0;

      msg.sender.transfer(eth_to_refund);
      return;
    }

    /*
      Check if there is an adequate amount of tokens in the contract yet
      and allow the buyer to withdraw tokens
    */
    if(token.balanceOf(address(this)) == 0 || iou_purchased[msg.sender] > token.balanceOf(address(this))) throw;

    uint256 iou_to_withdraw = iou_purchased[msg.sender];

    // If the user doesn't have any IOUs to withdraw, get out ASAP
    if(iou_to_withdraw == 0) throw;

    // Clear record of buyer's IOU and ETH balance before transferring out
    iou_purchased[msg.sender] = 0;
    eth_sent[msg.sender] = 0;

    total_iou_withdrawn += iou_to_withdraw;

    // Distribute tokens to the buyer
    token.transfer(msg.sender, iou_to_withdraw);
  }

  function purchase() payable {
    if(halt_purchases) throw;
    if(msg.value == 0) throw;

    // Determine amount of tokens user wants to/can buy
    uint256 iou_to_purchase = price_per_eth * msg.value;

    // Check if we have enough IOUs left to sell
    if((total_iou_purchased + iou_to_purchase) > total_iou_available) throw;

    // Update the amount of IOUs purchased by user. Also keep track of the total ETH they sent in
    iou_purchased[msg.sender] += iou_to_purchase;
    eth_sent[msg.sender] += msg.value;

    // Update the total amount of IOUs purchased by all buyers
    total_iou_purchased += iou_to_purchase;
  }

  // Fallback function/entry point
  function () payable {
    if(msg.value == 0) {
      withdraw();
    }
    else {
      purchase();
    }
  }
}