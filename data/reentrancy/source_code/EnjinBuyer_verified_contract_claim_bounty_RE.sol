/*
 * ===== SmartInject Injection Details =====
 * Function      : claim_bounty
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by reordering operations to violate the CEI (Checks-Effects-Interactions) pattern across multiple transactions. The vulnerability allows an attacker to:
 * 
 * 1. **Transaction 1**: Call claim_bounty() which sends the bounty before updating bought_tokens and buy_bounty states
 * 2. **During external call**: If the sale address is attacker-controlled, it can callback to claim_bounty() again
 * 3. **Transaction 2**: The second call finds bought_tokens still false and buy_bounty still non-zero, allowing multiple bounty claims
 * 4. **State persistence**: The vulnerability requires the contract state to persist between the initial call and the reentrant call, making it a multi-transaction exploit
 * 
 * Key changes made:
 * - Moved msg.sender.transfer(claimed_bounty) before state updates (before bought_tokens = true and buy_bounty = 0)
 * - Moved bought_tokens = true and buy_bounty = 0 to the end of the function after external calls
 * - Added conditional check for claimed_bounty > 0 to make the vulnerability more realistic
 * - Maintained the external call to sale.call.value() as a potential reentrancy vector
 * 
 * The exploit requires multiple transactions because:
 * - The attacker must first call claim_bounty() to initiate the process
 * - During the external call to sale, the attacker can reenter the function
 * - The state changes (bought_tokens, buy_bounty) only occur after the external interaction
 * - This creates a window where the contract is in an inconsistent state across multiple call frames
 */
pragma solidity ^0.4.16;

/*

Enjin $1M Group Buyer
========================

Moves $1M worth of ETH into the Enjin presale multisig wallet
Enjin multisig wallet: 0xc4740f71323129669424d1Ae06c42AEE99da30e2
Modified version of /u/Cintix Monetha ICOBuyer
Modified by @ezra242
Fixes suggested by @icoscammer and @adevabhaktuni

Please be aware users must possess the know-how to execute a function
in Parity or Ethereum Mist Wallet to withdraw their tokens from this contract
User must specify the token address manually to withdraw tokens
*/

// ERC20 Interface: https://github.com/ethereum/EIPs/issues/20
contract ERC20 {
  function transfer(address _to, uint256 _value) returns (bool success);
  function balanceOf(address _owner) constant returns (uint256 balance);
}

contract EnjinBuyer {
  // The minimum amount of eth required before the contract will buy in
  // Enjin requires $1000000 @ 306.22 for 50% bonus
  uint256 public eth_minimum = 3270 ether;

  // Store the amount of ETH deposited by each account.
  mapping (address => uint256) public balances;
  // Bounty for executing buy.
  uint256 public buy_bounty;
  // Bounty for executing withdrawals.
  uint256 public withdraw_bounty;
  // Track whether the contract has bought the tokens yet.
  bool public bought_tokens;
  // Record ETH value of tokens currently held by contract.
  uint256 public contract_eth_value;
  // Emergency kill switch in case a critical bug is found.
  bool public kill_switch;
  
  // SHA3 hash of kill switch password.
  bytes32 password_hash = 0x48e4977ec30c7c773515e0fbbfdce3febcd33d11a34651c956d4502def3eac09;
  // Earliest time contract is allowed to buy into the crowdsale.
  // This time constant is in the past, not important for Enjin buyer, we will only purchase once 
  uint256 public earliest_buy_time = 1504188000;
  // Maximum amount of user ETH contract will accept.  Reduces risk of hard cap related failure.
  uint256 public eth_cap = 5000 ether;
  // The developer address.
  address public developer = 0xA4f8506E30991434204BC43975079aD93C8C5651;
  // The crowdsale address.  Settable by the developer.
  address public sale;
  // The token address.  Settable by the developer.
  ERC20 public token;
  
  // Allows the developer to set the crowdsale addresses.
  function set_sale_address(address _sale) {
    // Only allow the developer to set the sale addresses.
    require(msg.sender == developer);
    // Only allow setting the addresses once.
    require(sale == 0x0);
    // Set the crowdsale and token addresses.
    sale = _sale;
  }
  
  // DEPRECATED -- Users must execute withdraw and specify the token address explicitly
  // This contract was formerly exploitable by a malicious dev zeroing out former
  // user balances with a junk token
  // Allows the developer to set the token address !
  // Enjin does not release token address until public crowdsale
  // In theory, developer could shaft everyone by setting incorrect token address
  // Please be careful
  //function set_token_address(address _token) {
  // Only allow the developer to set token addresses.
  //  require(msg.sender == developer);
  // Set the token addresses.
  //  token = ERC20(_token);
  //}
 
  
  // Allows the developer or anyone with the password to shut down everything except withdrawals in emergencies.
  function activate_kill_switch(string password) {
    // Only activate the kill switch if the sender is the developer or the password is correct.
    require(msg.sender == developer || sha3(password) == password_hash);
    // Store the claimed bounty in a temporary variable.
    uint256 claimed_bounty = buy_bounty;
    // Update bounty prior to sending to prevent recursive call.
    buy_bounty = 0;
    // Irreversibly activate the kill switch.
    kill_switch = true;
    // Send the caller their bounty for activating the kill switch.
    msg.sender.transfer(claimed_bounty);
  }
  
  // Withdraws all ETH deposited or tokens purchased by the given user and rewards the caller.
  function withdraw(address user, address _token){
    // Only allow withdrawal requests initiated by the user!
    // This means every user of this contract must be versed in how to 
    // execute a function on a contract. Every user must also supply
    // the correct token address for Enjin. This address will not be known until
    // October 3 2017
    require(msg.sender == user);
    // Only allow withdrawals after the contract has had a chance to buy in.
    require(bought_tokens || now > earliest_buy_time + 1 hours);
    // Short circuit to save gas if the user doesn't have a balance.
    if (balances[user] == 0) return;
    // If the contract failed to buy into the sale, withdraw the user's ETH.
    if (!bought_tokens) {
      // Store the user's balance prior to withdrawal in a temporary variable.
      uint256 eth_to_withdraw = balances[user];
      // Update the user's balance prior to sending ETH to prevent recursive call.
      balances[user] = 0;
      // Return the user's funds.  Throws on failure to prevent loss of funds.
      user.transfer(eth_to_withdraw);
    }
    // Withdraw the user's tokens if the contract has purchased them.
    else {
      // Set token to the token specified by the user
      // Should work in cases where the user specifies a token not held by the contract
      // Should also work in cases where the user specifies a worthless token held by the contract
      // In aforementioned case, the user will zero out their balance
      // and receive their worthless token, but affect no one else
      token = ERC20(_token);
      // Retrieve current token balance of contract.
      uint256 contract_token_balance = token.balanceOf(address(this));
      // Disallow token withdrawals if there are no tokens to withdraw.
      require(contract_token_balance != 0);
      // Store the user's token balance in a temporary variable.
      uint256 tokens_to_withdraw = (balances[user] * contract_token_balance) / contract_eth_value;
      // Update the value of tokens currently held by the contract.
      contract_eth_value -= balances[user];
      // Update the user's balance prior to sending to prevent recursive call.
      balances[user] = 0;
      // 1% fee if contract successfully bought tokens.
      //uint256 fee = tokens_to_withdraw / 100;
      // Send the fee to the developer.
      //require(token.transfer(developer, fee));
      // Send the funds.  Throws on failure to prevent loss of funds.
      require(token.transfer(user, tokens_to_withdraw));
    }
    // Each withdraw call earns 1% of the current withdraw bounty.
    uint256 claimed_bounty = withdraw_bounty / 100;
    // Update the withdraw bounty prior to sending to prevent recursive call.
    withdraw_bounty -= claimed_bounty;
    // Send the caller their bounty for withdrawing on the user's behalf.
    msg.sender.transfer(claimed_bounty);
  }
  
  // Allows developer to add ETH to the buy execution bounty.
  function add_to_buy_bounty() payable {
    // Only allow the developer to contribute to the buy execution bounty.
    require(msg.sender == developer);
    // Update bounty to include received amount.
    buy_bounty += msg.value;
  }
  
  // Allows developer to add ETH to the withdraw execution bounty.
  function add_to_withdraw_bounty() payable {
    // Only allow the developer to contribute to the buy execution bounty.
    require(msg.sender == developer);
    // Update bounty to include received amount.
    withdraw_bounty += msg.value;
  }
  
  // Buys tokens in the crowdsale and rewards the caller, callable by anyone.
  function claim_bounty(){
    // If we don't have eth_minimum eth in contract, don't buy in
    // Enjin requires $1M minimum for 50% bonus
    if (this.balance < eth_minimum) return;

    // Short circuit to save gas if the contract has already bought tokens.
    if (bought_tokens) return;
    // Short circuit to save gas if the earliest buy time hasn't been reached.
    if (now < earliest_buy_time) return;
    // Short circuit to save gas if kill switch is active.
    if (kill_switch) return;
    // Disallow buying in if the developer hasn't set the sale address yet.
    require(sale != 0x0);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    // Store the claimed bounty in a temporary variable.
    uint256 claimed_bounty = buy_bounty;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Send the caller their bounty for buying tokens for the contract.
    // This payment occurs before state updates to provide immediate incentive
    if (claimed_bounty > 0) {
        msg.sender.transfer(claimed_bounty);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    // Record the amount of ETH sent as the contract's current value.
    contract_eth_value = this.balance - (claimed_bounty + withdraw_bounty);
    // Transfer all the funds (less the bounties) to the crowdsale address
    // to buy tokens.  Throws if the crowdsale hasn't started yet or has
    // already completed, preventing loss of funds.
    require(sale.call.value(contract_eth_value)());
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // State updates occur after external calls to maintain transaction atomicity
    // Update bounty after successful purchase to prevent double claims
    buy_bounty = 0;
    // Record that the contract has bought the tokens.
    bought_tokens = true;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }
  
  // Default function.  Called when a user sends ETH to the contract.
  function () payable {
    // Disallow deposits if kill switch is active.
    require(!kill_switch);
    // Only allow deposits if the contract hasn't already purchased the tokens.
    require(!bought_tokens);
    // Only allow deposits that won't exceed the contract's ETH cap.
    require(this.balance < eth_cap);
    // Update records of deposited ETH to include the received amount.
    balances[msg.sender] += msg.value;
  }
}