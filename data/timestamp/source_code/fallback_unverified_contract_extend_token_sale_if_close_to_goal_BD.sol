/*
 * ===== SmartInject Injection Details =====
 * Function      : extend_token_sale_if_close_to_goal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability exists because block.timestamp can be manipulated by miners within certain bounds. An attacker (miner) can manipulate the timestamp to bypass the 1-hour cooldown between extensions, potentially allowing them to extend the token sale multiple times in quick succession by setting timestamps that appear to be 1 hour apart. This requires: 1) First transaction to trigger initial extension, 2) Subsequent transactions with manipulated timestamps to bypass cooldown, 3) State changes persist between transactions (extension_count, last_extension_time), making it a stateful multi-transaction vulnerability.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Emergency extension mechanism if close to minimum goal
  uint public extension_count = 0;
  uint public last_extension_time = 0;
  bool public extension_enabled = true;

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

  function extend_token_sale_if_close_to_goal() {
    // Check if token sale has ended
    if (!has_token_sale_time_ended()) throw;
    // Check if we're close to minimum goal (within 500 ETH)
    if (transferred_total < min_goal_amount - 500 ether) throw;
    // Check if minimum goal already reached
    if (is_min_goal_reached()) throw;
    // Check if extensions are still enabled
    if (!extension_enabled) throw;
    // Limit to 3 extensions maximum
    if (extension_count >= 3) throw;
    // Check if enough time has passed since last extension (1 hour = ~240 blocks)
    if (last_extension_time > 0 && block.timestamp < last_extension_time + 3600) throw;
    // Extend token sale by 1 week (approximately 40,320 blocks)
    token_sale_end_block += 40320;
    refund_window_end_block += 40320;
    // Update extension tracking
    extension_count++;
    last_extension_time = block.timestamp;
    // Disable extensions after 3 uses
    if (extension_count >= 3) {
      extension_enabled = false;
    }
  }
  // === END FALLBACK INJECTION ===

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
  function transfer_remaining_funds_to_project() {
    if (!has_token_sale_time_ended()) throw;
    if (is_min_goal_reached()) throw;
    if (block.number <= refund_window_end_block) throw;
    if (this.balance == 0) throw;
    // Transfer remaining ETH to loftVR Offline Project Wallet
    if (!project_wallet.send(this.balance)) throw;
  }
}
