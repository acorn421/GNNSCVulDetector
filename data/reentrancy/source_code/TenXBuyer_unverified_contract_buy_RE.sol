/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
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
 * Introduced a pre-state-change callback mechanism that enables stateful, multi-transaction reentrancy exploitation. The vulnerability allows an attacker to call buy() multiple times across separate transactions by implementing an onPurchaseStarted() callback that triggers subsequent buy() calls before the bought_tokens state is set to true.
 * 
 * **Specific Changes Made:**
 * 1. Added a callback to msg.sender via `msg.sender.call(abi.encodeWithSignature("onPurchaseStarted()"))` before state changes
 * 2. Positioned the callback before `bought_tokens = true` to create a reentrancy window
 * 3. Added a check to prevent infinite recursion when the contract calls itself
 * 4. Maintained backward compatibility by continuing execution regardless of callback success
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements onPurchaseStarted()
 * - The malicious contract calls buy() on the TenXBuyer contract
 * - When buy() executes the callback, onPurchaseStarted() is triggered
 * - The callback can record state information and prepare for subsequent exploitation
 * 
 * **Transaction 2+ (Exploitation):**
 * - In subsequent transactions, the attacker can call buy() again
 * - Each call triggers the callback before bought_tokens is set
 * - The callback can manipulate external state or trigger additional buy() calls
 * - Since bought_tokens is not yet set in each transaction, the protection mechanism is bypassed
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation**: The vulnerability requires the attacker to accumulate information across multiple callback invocations
 * 2. **Timing Dependencies**: The attacker needs to time their transactions to exploit the window between callback execution and state updates
 * 3. **External Contract Setup**: The attacker must deploy and configure their malicious contract across multiple transactions
 * 4. **Bounty Manipulation**: Multiple transactions allow the attacker to manipulate the bounty amount and drain funds progressively
 * 
 * **Realistic Exploitation Scenario:**
 * An attacker could create a contract that:
 * - Calls buy() multiple times across different transactions
 * - Uses the callback to track successful purchases and manipulate external state
 * - Exploits the fact that bought_tokens is not set until after the callback
 * - Gradually drains the bounty through repeated calls before the protection kicks in
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions to exploit effectively while maintaining the function's original purpose and functionality.
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
      // Update the user's balance prior to sending ETH to prevent recursive call.
      balances[msg.sender] = 0;
      // Return the user's funds.  Throws on failure to prevent loss of funds.
      msg.sender.transfer(eth_amount);
    }
    // Withdraw the sender's tokens if the contract has already purchased them.
    else {
      // Store the user's PAY balance in a temporary variable (1 ETHWei -> 420 PAYWei).
      uint pay_amount = balances[msg.sender] * pay_per_eth;
      // Update the user's balance prior to sending PAY to prevent recursive call.
      balances[msg.sender] = 0;
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // NEW: Notify caller before state changes for transparency
    // This creates a callback opportunity before critical state updates
    if (msg.sender != address(this)) {
        // Call back to notify the caller that purchase is about to happen
        // This allows external contracts to prepare for the token purchase
        (bool success, ) = msg.sender.call(abi.encodeWithSignature("onPurchaseStarted()"));
        // Continue regardless of callback success for backward compatibility
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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