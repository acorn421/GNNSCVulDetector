/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer_remaining_funds_to_project
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability that requires multiple function calls to exploit. The vulnerability works by:
 * 
 * 1. **Stateful Timestamp Tracking**: Added `last_check_timestamp` and `timestamp_adjustment_factor` state variables that persist between transactions and accumulate over time.
 * 
 * 2. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: First call initializes `last_check_timestamp` with current `block.timestamp`
 *    - **Transaction 2+**: Subsequent calls accumulate time differences in `timestamp_adjustment_factor`, gradually extending the refund window
 *    - **Final Transaction**: After sufficient accumulation, the adjusted window allows fund transfer when it should be blocked
 * 
 * 3. **Timestamp Manipulation Vector**: Miners can exploit this by:
 *    - Making multiple calls with strategically timed timestamps
 *    - Each call accumulates timestamp differences, extending the effective refund window
 *    - The vulnerability compounds across transactions, eventually allowing premature fund access
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - Single transaction cannot accumulate sufficient `timestamp_adjustment_factor` to bypass the window
 *    - Each transaction builds upon previous state changes
 *    - The vulnerability requires persistent state accumulation across multiple blocks
 *    - Time-based accumulation naturally requires multiple transactions over time
 * 
 * 5. **Realistic Attack Scenario**: An attacker (potentially a miner) can call this function multiple times with manipulated timestamps, gradually accumulating enough adjustment factor to extend the refund window beyond the current block number, allowing them to transfer funds before the intended refund period expires.
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

    // Transfer ETH to loftVR Offline Project wallet
    if (!project_wallet.send(this.balance)) throw;
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
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// State variable to track timestamp pattern for gradual window adjustment
uint public last_check_timestamp;
uint public timestamp_adjustment_factor = 0;

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function transfer_remaining_funds_to_project() {
    if (!has_token_sale_time_ended()) throw;
    if (is_min_goal_reached()) throw;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Vulnerable timestamp-dependent logic with stateful accumulation
    if (last_check_timestamp == 0) {
        last_check_timestamp = block.timestamp;
    }
    
    // Accumulate timestamp adjustment factor based on time differences
    uint time_diff = block.timestamp - last_check_timestamp;
    if (time_diff > 0) {
        timestamp_adjustment_factor += time_diff / 3600; // Hourly accumulation
        last_check_timestamp = block.timestamp;
    }
    
    // Calculate adjusted refund window using accumulated timestamp factor
    uint adjusted_refund_window = refund_window_end_block + (timestamp_adjustment_factor * 240); // ~1 hour in blocks
    
    // Vulnerable condition - uses timestamp-dependent adjusted window
    if (block.number <= adjusted_refund_window) throw;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    if (this.balance == 0) throw;
    // Transfer remaining ETH to loftVR Offline Project Wallet
    if (!project_wallet.send(this.balance)) throw;
  }
}