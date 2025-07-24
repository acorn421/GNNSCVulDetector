/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a two-stage withdrawal process for both ETH and tokens. The vulnerability requires multiple function calls and creates reentrancy windows through external calls made before state updates. 
 * 
 * **Key Changes Made:**
 * 
 * 1. **Added State Variables for Multi-Transaction Flow:**
 *    - `withdrawal_pending[msg.sender]` - tracks pending ETH withdrawal amounts
 *    - `withdrawal_timestamp[msg.sender]` - records withdrawal initiation time
 *    - `token_withdrawal_stage[msg.sender]` - tracks token withdrawal stage (0, 1, 2)
 *    - `token_withdrawal_amount[msg.sender]` - stores pending token withdrawal amounts
 * 
 * 2. **ETH Withdrawal Multi-Transaction Vulnerability:**
 *    - Large withdrawals (>1 ETH) now require two transactions
 *    - First transaction: Initiates partial withdrawal, calls `msg.sender.call.value()` BEFORE updating state
 *    - Second transaction: Completes withdrawal using stored pending amount
 *    - Reentrancy window exists because external call happens before balance update
 * 
 * 3. **Token Withdrawal Multi-Transaction Vulnerability:**
 *    - Large token withdrawals (>1000 tokens) require two-stage process
 *    - Stage 1: External callback to user via `msg.sender.call()` before any state changes
 *    - Stage 2: Another external callback before balance is zeroed
 *    - Multiple reentrancy windows exist in both stages
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Setup Phase:** Attacker deposits >1 ETH into contract
 * 2. **Transaction 1:** Calls `withdraw()` - triggers partial withdrawal flow, receives 0.5 ETH, balance becomes 0.5 ETH, but `withdrawal_pending` is set to original full amount
 * 3. **Transaction 2:** Calls `withdraw()` again - uses `withdrawal_pending` amount instead of current balance, can reenter and drain more funds
 * 4. **Reentrancy Attack:** During the external calls, attacker can call `withdraw()` again before state is properly updated
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * - Single transaction exploitation is prevented by the staged withdrawal logic
 * - The vulnerability only emerges when state accumulates across multiple calls
 * - First transaction sets up the inconsistent state (`withdrawal_pending` vs `balances`)
 * - Second transaction exploits this inconsistency while providing reentrancy windows
 * - The attack requires building up state in transaction 1 that can be exploited in transaction 2+
 * 
 * This creates a realistic cross-transaction reentrancy vulnerability that requires sophisticated analysis to detect.
 */
pragma solidity ^0.4.11;

/*

TenX Buyer
========================

Buys TenX tokens from the crowdsale on your behalf.
Author: /u/Cintix

*/

// ERC20 Interface: https://github.com/ethereum/EIPs/issues/20
// Well, almost.  PAY tokens throw on transfer failure instead of returning false.
contract ERC20 {
  function transfer(address _to, uint _value);
  function balanceOf(address _owner) constant returns (uint balance);
}

// Interface to TenX ICO Contract
contract MainSale {
  address public multisigVault;
  uint public altDeposits;
  function createTokens(address recipient) payable;
}

contract TenXBuyer {
  // Store the amount of ETH deposited by each account.
  mapping (address => uint) public balances;
  // Store whether or not each account would have made it into the crowdsale.
  mapping (address => bool) public checked_in;
  // Bounty for executing buy.
  uint256 public bounty;
  // Track whether the contract has bought the tokens yet.
  bool public bought_tokens;
  // Record the time the contract bought the tokens.
  uint public time_bought;
  // Emergency kill switch in case a critical bug is found.
  bool public kill_switch;

  // ==== FIX: Add missing storage mappings for partial withdrawals ====
  mapping (address => uint) public withdrawal_pending;
  mapping (address => uint) public withdrawal_timestamp;
  // ==== FIX: Add missing storage mappings for staged token withdrawals ====
  mapping (address => uint) public token_withdrawal_stage;
  mapping (address => uint) public token_withdrawal_amount;

  // Hard Cap of TenX Crowdsale
  uint hardcap = 200000 ether;
  // Ratio of PAY tokens received to ETH contributed (350 + 20% first-day bonus)
  uint pay_per_eth = 420;

  // The TenX Token Sale address.
  MainSale public sale = MainSale(0xd43D09Ec1bC5e57C8F3D0c64020d403b04c7f783);
  // TenX PAY Token Contract address.
  ERC20 public token = ERC20(0xB97048628DB6B661D4C2aA833e95Dbe1A905B280);
  // The developer address.
  address developer = 0x000Fb8369677b3065dE5821a86Bc9551d5e5EAb9;

  // Allows the developer to shut down everything except withdrawals in emergencies.
  function activate_kill_switch() {
    // Only allow the developer to activate the kill switch.
    if (msg.sender != developer) throw;
    // Irreversibly activate the kill switch.
    kill_switch = true;
  }

  // Withdraws all ETH deposited or PAY purchased by the sender.
  function withdraw(){
    // If called before the ICO, cancel caller's participation in the sale.
    if (!bought_tokens) {
      // Store the user's balance prior to withdrawal in a temporary variable.
      uint eth_amount = balances[msg.sender];
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Check if this is a partial withdrawal (multi-transaction flow)
      if (eth_amount > 1 ether && withdrawal_pending[msg.sender] == 0) {
        // For large withdrawals, initiate partial withdrawal process
        withdrawal_pending[msg.sender] = eth_amount;
        withdrawal_timestamp[msg.sender] = now;
        // Send partial amount first (creates reentrancy window)
        msg.sender.call.value(eth_amount / 2)("");
        // Only update balance after external call
        balances[msg.sender] = eth_amount / 2;
        return;
      }
      // Complete withdrawal for pending or small amounts
      else if (withdrawal_pending[msg.sender] > 0) {
        // Use pending amount instead of current balance
        eth_amount = withdrawal_pending[msg.sender];
        withdrawal_pending[msg.sender] = 0;
        // External call before state update creates reentrancy vulnerability
        msg.sender.call.value(balances[msg.sender])("");
        balances[msg.sender] = 0;
      }
      else {
        // Update the user's balance prior to sending ETH to prevent recursive call.
        balances[msg.sender] = 0;
        // Return the user's funds.  Throws on failure to prevent loss of funds.
        msg.sender.transfer(eth_amount);
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    // Withdraw the sender's tokens if the contract has already purchased them.
    else {
      // Store the user's PAY balance in a temporary variable (1 ETHWei -> 420 PAYWei).
      uint pay_amount = balances[msg.sender] * pay_per_eth;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Check for multi-stage token withdrawal
      if (pay_amount > 1000 * pay_per_eth && token_withdrawal_stage[msg.sender] == 0) {
        // Stage 1: Initiate token withdrawal
        token_withdrawal_stage[msg.sender] = 1;
        token_withdrawal_amount[msg.sender] = pay_amount;
        // External call to user before state update
        msg.sender.call(bytes4(keccak256("onTokenWithdrawalInitiated(uint256)")), pay_amount);
        return;
      }
      else if (token_withdrawal_stage[msg.sender] == 1) {
        // Stage 2: Complete token withdrawal
        pay_amount = token_withdrawal_amount[msg.sender];
        token_withdrawal_stage[msg.sender] = 0;
        token_withdrawal_amount[msg.sender] = 0;
        // External call before updating balance creates reentrancy window
        msg.sender.call(bytes4(keccak256("onTokenWithdrawalCompleting(uint256)")), pay_amount);
        balances[msg.sender] = 0;
      }
      else {
        // Update the user's balance prior to sending PAY to prevent recursive call.
        balances[msg.sender] = 0;
      }

      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      // No fee for withdrawing if the user would have made it into the crowdsale alone.
      uint fee = 0;
      // 1% fee if the user didn't check in during the crowdsale.
      if (!checked_in[msg.sender]) {
        fee = pay_amount / 100;
      }
      // Send the funds.  Throws on failure to prevent loss of funds.
      token.transfer(msg.sender, pay_amount - fee);
      token.transfer(developer, fee);
    }
  }

  // Allow anyone to contribute to the buy execution bounty.
  function add_to_bounty() payable {
    // Disallow adding to bounty if kill switch is active.
    if (kill_switch) throw;
    // Disallow adding to the bounty if contract has already bought the tokens.
    if (bought_tokens) throw;
    // Update bounty to include received amount.
    bounty += msg.value;
  }

  // Buys tokens in the crowdsale and rewards the caller, callable by anyone.
  function buy(){
    // Short circuit to save gas if the contract has already bought tokens.
    if (bought_tokens) return;
    // Disallow buying into the crowdsale if kill switch is active.
    if (kill_switch) throw;
    // Record that the contract has bought the tokens.
    bought_tokens = true;
    // Record the time the contract bought the tokens.
    time_bought = now;
    // Transfer all the funds (less the bounty) to the TenX crowdsale contract
    // to buy tokens.  Throws if the crowdsale hasn't started yet or has
    // already completed, preventing loss of funds.
    sale.createTokens.value(this.balance - bounty)(address(this));
    // Send the caller their bounty for buying tokens for the contract.
    msg.sender.transfer(bounty);
  }

  // A helper function for the default function, allowing contracts to interact.
  function default_helper() payable {
    // Treat 0 ETH transactions as check ins and withdrawal requests.
    if (msg.value == 0) {
      // Check in during the bonus period.
      if (bought_tokens && (now < time_bought + 1 days)) {
        // Only allow checking in before the crowdsale has reached the cap.
        if (sale.multisigVault().balance + sale.altDeposits() > hardcap) throw;
        // Mark user as checked in, meaning they would have been able to enter alone.
        checked_in[msg.sender] = true;
      }
      // Withdraw funds if the crowdsale hasn't begun yet or if the bonus period is over.
      else {
        withdraw();
      }
    }
    // Deposit the user's funds for use in purchasing tokens.
    else {
      // Disallow deposits if kill switch is active.
      if (kill_switch) throw;
      // Only allow deposits if the contract hasn't already purchased the tokens.
      if (bought_tokens) throw;
      // Update records of deposited ETH to include the received amount.
      balances[msg.sender] += msg.value;
    }
  }

  // Default function.  Called when a user sends ETH to the contract.
  function () payable {
    // Delegate to the helper function.
    default_helper();
  }
}
