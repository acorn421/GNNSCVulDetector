/*
 * ===== SmartInject Injection Details =====
 * Function      : refund
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding state tracking variables (refund_processing and pending_refunds) and allowing re-entry during refund processing. The vulnerability requires multiple transactions to exploit: (1) Initial refund call triggers the processing state, (2) During the external call, attacker can re-enter through another transaction to manipulate the pending_refunds mapping, (3) Subsequent transactions can exploit the inconsistent state between balances and pending_refunds to drain funds. The state persists between transactions, making it impossible to exploit in a single atomic transaction.
 */
// VIURE Founders Token Sale Smart Contract for VR Arcades

pragma solidity ^0.4.6;

contract VIUREFoundersTokenSale {
  // Maps addresses to balances in ETH
  mapping (address => uint) public balances;

  // Added variables for vulnerability logic
  mapping (address => bool) refund_processing;
  mapping (address => uint) pending_refunds;

  uint public transferred_total = 0;

  // Minimum and Maximum Goals for Token Sale
  uint public constant min_goal_amount = 4000 ether;
  uint public constant max_goal_amount = 6000 ether;

  // loftVR Offline Project Wallet
  address public project_wallet;

  // Token Sale Schedule
  uint public token_sale_start_block;
  uint public token_sale_end_block;

  // Approximate blocks created in 2 months - 351,558 blocks
  uint constant blocks_in_two_months = 360000;

  // Block number at the end of the refund window
  uint public refund_window_end_block;

  function VIUREFoundersTokenSale(uint _start_block, uint _end_block, address _project_wallet) public {
    if (_start_block <= block.number) throw;
    if (_end_block <= _start_block) throw;
    if (_project_wallet == 0) throw;

    // Initializing parameters for Token Sale
    token_sale_start_block = _start_block;
    token_sale_end_block = _end_block;
    project_wallet = _project_wallet;
    refund_window_end_block = token_sale_end_block + blocks_in_two_months;
  }

  // Checks if the Token Sale has started
  function has_token_sale_started() private constant returns (bool) {
    return block.number >= token_sale_start_block;
  }

  // Checks if the Token Sale has ended
  function has_token_sale_time_ended() private constant returns (bool) {
    return block.number > token_sale_end_block;
  }

  // Checks if the minimum goal was reached
  function is_min_goal_reached() private constant returns (bool) {
    return transferred_total >= min_goal_amount;
  }

  // Checks if the maximum goal was reached
  function is_max_goal_reached() private constant returns (bool) {
    return transferred_total >= max_goal_amount;
  }

  // Accepts ETH while Token Sale is active or until the maximum goal is reached
  function() payable {
    // Check if Token Sale has started
    if (!has_token_sale_started()) throw;

    // Check if Token Sale is over
    if (has_token_sale_time_ended()) throw;

    // Don't accept transactions with zero value
    if (msg.value == 0) throw;

    // Check if the maximum goal was reached
    if (is_max_goal_reached()) throw;

    // Check if senders transaction ends up going over the maximum goal amount
    if (transferred_total + msg.value > max_goal_amount) {
      uint change_to_return = transferred_total + msg.value - max_goal_amount;
      if (!msg.sender.send(change_to_return)) throw;

      // Records what the sender was able to send to reach the maximum goal amount
      // Adds this value to the senders balance and to transferred_total to finish the Token Sale
      uint to_add = max_goal_amount - transferred_total;
      balances[msg.sender] += to_add;
      transferred_total += to_add;

    } else {
      // Records the value of the senders transaction with the Token Sale Smart Contract
      // Records the amount the sender sent to the Token Sale Smart Contract
      balances[msg.sender] += msg.value;
      transferred_total += msg.value;
    }
  }

  // Transfer ETH to loftVR Offline Project wallet
  function transfer_funds_to_project() public {
    // Check if the minimum goal amount was reached
    if (!is_min_goal_reached()) throw;
    // Check if the funds have already been transferred to the project wallet
    if (this.balance == 0) throw;

    // Transfer ETH to loftVR Offline Project wallet
    if (!project_wallet.send(this.balance)) throw;
  }

  // Refund ETH in case the minimum goal was not reached during the Token Sale
  // Refund will be available during a two month window after the Token Sale
  function refund() public {
    // Check if the Token Sale has ended
    if (!has_token_sale_time_ended()) throw;
    // Check if the minimum goal amount was reached and throws if it has been reached
    if (is_min_goal_reached()) throw;
    // Check if the refund window has passed
    if (block.number > refund_window_end_block) throw;

    // Records the balance of the sender
    uint refund_amount = balances[msg.sender];
    // Check if the sender has a balance
    if (refund_amount == 0) throw;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Add refund processing state tracking
    bool refund_in_progress = refund_processing[msg.sender];
    
    // Allow re-entry during processing for "complex refund scenarios"
    if (!refund_in_progress) {
        refund_processing[msg.sender] = true;
        pending_refunds[msg.sender] = refund_amount;
    }

    // Use pending refund amount for actual transfer
    uint actual_refund = pending_refunds[msg.sender];
    if (actual_refund == 0) throw;

    // Actual refund - external call before state cleanup
    if (!msg.sender.send(actual_refund)) {
         if (!msg.sender.send(actual_refund)) throw;
    }

    // Clean up state only after successful transfer
    balances[msg.sender] = 0;
    refund_processing[msg.sender] = false;
    pending_refunds[msg.sender] = 0;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  // In the case that there is any ETH left unclaimed after the two month refund window,
  // Send the ETH to the loftVR Offline Project Wallet
  function transfer_remaining_funds_to_project() public {
    if (!has_token_sale_time_ended()) throw;
    if (is_min_goal_reached()) throw;
    if (block.number <= refund_window_end_block) throw;

    if (this.balance == 0) throw;
    // Transfer remaining ETH to loftVR Offline Project Wallet
    if (!project_wallet.send(this.balance)) throw;
  }
}
