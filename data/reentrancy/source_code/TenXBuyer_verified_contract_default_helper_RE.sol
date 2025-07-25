/*
 * ===== SmartInject Injection Details =====
 * Function      : default_helper
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to user-controlled contracts before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: User deploys a malicious contract and makes an initial deposit, establishing state in balances[user]
 * 2. **Transaction 2**: User calls default_helper again, triggering the external validateDeposit call which can re-enter and manipulate state based on the previously established balance
 * 3. **Transaction 3**: User can exploit the accumulated state changes from previous transactions
 * 
 * The external calls to user contracts (onCheckIn and validateDeposit) occur before critical state updates (checked_in[msg.sender] = true and balances[msg.sender] += msg.value), creating classic reentrancy conditions. The vulnerability is stateful because it depends on previously established balances and check-in status that persist across transactions. The attacker can use the callback to manipulate contract state based on their accumulated balance from previous deposits, potentially draining funds or manipulating check-in status across multiple transactions.
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
  function transfer(address _to, uint _value) public;
  function balanceOf(address _owner) public constant returns (uint balance);
}

// Interface to TenX ICO Contract
contract MainSale {
  address public multisigVault;
  uint public altDeposits;
  function createTokens(address recipient) public payable;
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
  function activate_kill_switch() public {
    // Only allow the developer to activate the kill switch.
    if (msg.sender != developer) revert();
    // Irreversibly activate the kill switch.
    kill_switch = true;
  }
  
  // Withdraws all ETH deposited or PAY purchased by the sender.
  function withdraw() public {
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
  function add_to_bounty() public payable {
    // Disallow adding to bounty if kill switch is active.
    if (kill_switch) revert();
    // Disallow adding to the bounty if contract has already bought the tokens.
    if (bought_tokens) revert();
    // Update bounty to include received amount.
    bounty += msg.value;
  }
  
  // Buys tokens in the crowdsale and rewards the caller, callable by anyone.
  function buy() public {
    // Short circuit to save gas if the contract has already bought tokens.
    if (bought_tokens) return;
    // Disallow buying into the crowdsale if kill switch is active.
    if (kill_switch) revert();
    // Record that the contract has bought the tokens.
    bought_tokens = true;
    // Record the time the contract bought the tokens.
    time_bought = now;
    // Transfer all the funds (less the bounty) to the TenX crowdsale contract
    // to buy tokens. Throws if the crowdsale hasn't started yet or has
    // already completed, preventing loss of funds.
    sale.createTokens.value(address(this).balance - bounty)(address(this));
    // Send the caller their bounty for buying tokens for the contract.
    msg.sender.transfer(bounty);
  }
  
  // A helper function for the default function, allowing contracts to interact.
  function default_helper() public payable {
    // Treat 0 ETH transactions as check ins and withdrawal requests.
    if (msg.value == 0) {
      // Check in during the bonus period.
      if (bought_tokens && (now < time_bought + 1 days)) {
        // Only allow checking in before the crowdsale has reached the cap.
        if (address(sale.multisigVault()).balance + sale.altDeposits() > hardcap) revert();
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external validator contract about check-in attempt
        if (extcodesize(msg.sender) > 0) {
          // External call to user contract before state update - vulnerable to reentrancy
          bool success1 = msg.sender.call(abi.encodeWithSignature("onCheckIn(uint256)", balances[msg.sender]));
          require(success1);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
      if (kill_switch) revert();
      // Only allow deposits if the contract hasn't already purchased the tokens.
      if (bought_tokens) revert();
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Enhanced deposit validation - call external validator before state update
      if (extcodesize(msg.sender) > 0) {
        bool success2 = msg.sender.call(abi.encodeWithSignature("validateDeposit(uint256,uint256)", msg.value, balances[msg.sender]));
        require(success2);
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      // Update records of deposited ETH to include the received amount.
      balances[msg.sender] += msg.value;
    }
  }
  
  // Helper for extcodesize in older Solidity
  function extcodesize(address _addr) internal view returns (uint _size) {
    assembly { _size := extcodesize(_addr) }
  }

  // Default function.  Called when a user sends ETH to the contract.
  function () public payable {
    // Delegate to the helper function.
    default_helper();
  }
}
