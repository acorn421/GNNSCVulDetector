/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer_funds_to_project
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability that requires multiple function calls with specific timing to execute successfully. The vulnerability involves:
 * 
 * 1. **State Variables**: Added `last_transfer_attempt`, `transfer_cooldown_period`, and `accumulated_transfer_delay` to track transfer timing across transactions.
 * 
 * 2. **Multi-Transaction Requirement**: The function now requires at least 2 separate transactions:
 *    - First call: Sets up initial timestamp and fails (requires waiting period)
 *    - Second+ calls: Must wait for progressively longer periods based on accumulated delay
 * 
 * 3. **Timestamp Manipulation Exploitation**:
 *    - **Miner Manipulation**: Miners can manipulate `block.timestamp` to bypass cooldown periods
 *    - **Timestamp Dependency**: The progressive delay calculation depends on `block.timestamp` differences
 *    - **Probabilistic Bypass**: The timestamp hash check creates a timing-dependent bypass mechanism
 * 
 * 4. **Stateful Persistence**: State variables persist between transactions, creating accumulated vulnerability conditions that can be exploited by:
 *    - Manipulating timestamp to reduce apparent `time_elapsed`
 *    - Exploiting the 5% probabilistic bypass by timing transactions
 *    - Using timestamp manipulation to reset delays prematurely
 * 
 * 5. **Exploitation Scenarios**:
 *    - **Scenario 1**: Miner sets block.timestamp backwards to make `time_elapsed` appear longer
 *    - **Scenario 2**: Attacker times multiple calls to hit the 5% bypass window
 *    - **Scenario 3**: Coordinated timestamp manipulation across multiple blocks to circumvent progressive delays
 * 
 * The vulnerability is realistic as it mimics common patterns of implementing cooldown periods and progressive security measures, but the reliance on `block.timestamp` for critical timing logic creates exploitable conditions across multiple transactions.
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
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// State variables to track transfer attempts and timing
uint public last_transfer_attempt;
uint public transfer_cooldown_period = 1 days;
uint public accumulated_transfer_delay;

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function transfer_funds_to_project() {
    // Check if the minimum goal amount was reached
    if (!is_min_goal_reached()) throw;
    // Check if the funds have already been transferred to the project wallet
    if (this.balance == 0) throw;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // First-time transfer setup
    if (last_transfer_attempt == 0) {
        last_transfer_attempt = block.timestamp;
        accumulated_transfer_delay = 0;
        throw; // Require waiting period before actual transfer
    }

    // Calculate time since last attempt
    uint time_elapsed = block.timestamp - last_transfer_attempt;
    
    // Update accumulated delay for progressive security
    accumulated_transfer_delay += time_elapsed;
    
    // Progressive cooldown: each attempt requires longer waiting period
    uint required_delay = transfer_cooldown_period + (accumulated_transfer_delay / 10);
    
    // Check if enough time has passed since last attempt
    if (time_elapsed < required_delay) {
        last_transfer_attempt = block.timestamp; // Update timestamp for next attempt
        throw; // Not enough time has passed
    }

    // Additional timestamp-based validation using block properties
    uint timestamp_hash = uint(keccak256(block.timestamp, block.number));
    if (timestamp_hash % 100 < 5) {
        // 5% chance of requiring additional delay based on block timing
        last_transfer_attempt = block.timestamp;
        throw; // Random delay requirement
    }

    // Reset tracking state before successful transfer
    last_transfer_attempt = 0;
    accumulated_transfer_delay = 0;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    // Transfer ETH to loftVR Offline Project wallet
    if (!project_wallet.send(this.balance)) throw;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
}
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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