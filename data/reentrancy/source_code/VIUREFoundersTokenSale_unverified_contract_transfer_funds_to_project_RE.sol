/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer_funds_to_project
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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added state variable tracking**: Introduced `balance_to_transfer` to store the amount being transferred
 * 2. **Moved state update after external call**: Added `transferred_total += balance_to_transfer` AFTER the external call to project_wallet.send()
 * 3. **Preserved original balance checks**: Maintained the original security checks to keep the function realistic
 * 4. **Created checks-effects-interactions violation**: External call now occurs before critical state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys malicious contract as project_wallet
 * - Token sale completes with minimum goal reached
 * - Contract holds ETH ready for transfer
 * 
 * **Transaction 2 (Initial Attack)**:
 * - Legitimate call to transfer_funds_to_project()
 * - Function passes all checks (min goal reached, balance > 0)
 * - Calls malicious project_wallet.send() 
 * - Malicious contract's fallback function triggers reentrancy
 * 
 * **Transaction 3+ (Reentrant Exploitation)**:
 * - During the send() callback, malicious contract calls transfer_funds_to_project() again
 * - Original state update (`transferred_total += balance_to_transfer`) hasn't executed yet
 * - All original checks still pass because state hasn't been updated
 * - Contract can drain additional funds through repeated reentrancy calls
 * - Each reentrant call transfers more ETH before any state updates occur
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **State Accumulation**: The vulnerability requires the token sale to complete over multiple transactions, accumulating funds and reaching minimum goal
 * 2. **Persistent State Exploitation**: The malicious project_wallet contract must be set up in previous transactions
 * 3. **Cross-Transaction State Manipulation**: The vulnerability exploits the fact that `transferred_total` is not updated until after the external call, allowing multiple transactions to see the same "clean" state
 * 4. **Sequential Dependency**: Attack requires: (1) Setup phase, (2) Initial trigger, (3) Reentrant calls - cannot be done atomically
 * 
 * **Realistic Production Scenario:**
 * This vulnerability could realistically occur when developers:
 * - Add post-transfer logging or accounting
 * - Implement recovery mechanisms after external calls
 * - Modify existing functions to track additional state
 * - Assume external calls are safe because of earlier validation checks
 * 
 * The vulnerability maintains the function's intended behavior while creating a subtle but exploitable flaw that requires multiple transactions and persistent state changes to exploit effectively.
 */
// VIURE Founders Token Sale Smart Contract for VR Arcades

pragma solidity ^0.4.6;

contract VIUREFoundersTokenSale {
  // Maps addresses to balances in ETH
  mapping (address => uint) public balances;

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

  function VIUREFoundersTokenSale(uint _start_block, uint _end_block, address _project_wallet) {
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
      // Return as change the amount that goes over the maximum goal amount
      var change_to_return = transferred_total + msg.value - max_goal_amount;
      if (!msg.sender.send(change_to_return)) throw;

      // Records what the sender was able to send to reach the maximum goal amount
      // Adds this value to the senders balance and to transferred_total to finish the Token Sale
      var to_add = max_goal_amount - transferred_total;
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
  function transfer_funds_to_project() {
    // Check if the minimum goal amount was reached
    if (!is_min_goal_reached()) throw;
    // Check if the funds have already been transferred to the project wallet
    if (this.balance == 0) throw;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Store the balance before transfer for potential recovery
    uint balance_to_transfer = this.balance;
    
    // Transfer ETH to loftVR Offline Project wallet
    // VULNERABILITY: External call before state updates - allows reentrancy
    if (!project_wallet.send(balance_to_transfer)) throw;
    
    // VULNERABILITY: State update after external call - can be bypassed by reentrancy
    // Mark funds as transferred (this should have been done before the external call)
    transferred_total += balance_to_transfer;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  // Refund ETH in case the minimum goal was not reached during the Token Sale
  // Refund will be available during a two month window after the Token Sale
  function refund() {
    // Check if the Token Sale has ended
    if (!has_token_sale_time_ended()) throw;
    // Check if the minimum goal amount was reached and throws if it has been reached
    if (is_min_goal_reached()) throw;
    // Check if the refund window has passed
    if (block.number > refund_window_end_block) throw;

    // Records the balance of the sender
    var refund_amount = balances[msg.sender];
    // Check if the sender has a balance
    if (refund_amount == 0) throw;

    // Reset balance
    balances[msg.sender] = 0;

    // Actual refund
    if (!msg.sender.send(refund_amount)) {
         if (!msg.sender.send(refund_amount)) throw;
    }
  }

  // In the case that there is any ETH left unclaimed after the two month refund window,
  // Send the ETH to the loftVR Offline Project Wallet
  function transfer_remaining_funds_to_project() {
    if (!has_token_sale_time_ended()) throw;
    if (is_min_goal_reached()) throw;
    if (block.number <= refund_window_end_block) throw;

    if (this.balance == 0) throw;
    // Transfer remaining ETH to loftVR Offline Project Wallet
    if (!project_wallet.send(this.balance)) throw;
  }
}