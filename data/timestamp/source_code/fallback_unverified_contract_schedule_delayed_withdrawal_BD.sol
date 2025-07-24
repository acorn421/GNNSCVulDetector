/*
 * ===== SmartInject Injection Details =====
 * Function      : schedule_delayed_withdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a two-step withdrawal process. The vulnerability is stateful and multi-transaction: 1) User calls schedule_delayed_withdrawal() to set a timestamp, 2) User calls execute_scheduled_withdrawal() after the delay. Miners can manipulate block timestamps to allow premature withdrawals or delay legitimate ones. The state persists between transactions through the scheduled_withdrawals mapping.
 */
pragma solidity ^0.4.16;

// Original author: Cintix
// Modified by: Moonlambos, yakois

// ERC20 Interface: https://github.com/ethereum/EIPs/issues/20
contract ERC20 {
  function transfer(address _to, uint256 _value) returns (bool success);
  function balanceOf(address _owner) constant returns (uint256 balance);
}

contract RequestSale {
  // Store the amount of ETH deposited by each account.
  mapping (address => uint256) public balances;
  // Track whether the contract has bought the tokens yet.
  bool public bought_tokens;
  // Record ETH value of tokens currently held by contract.
  uint256 public contract_eth_value;
  // Maximum amount of user ETH contract will accept.
  uint256 public eth_cap = 500 ether;
  // The minimum amount of ETH that must be deposited before the buy-in can be performed.
  uint256 constant public min_required_amount = 60 ether;
  // The owner's address.
  address public owner;
  // The crowdsale address. Can be verified at: https://request.network/#/presale.
  address public sale = 0xa579E31b930796e3Df50A56829cF82Db98b6F4B3;
  
  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Mapping to store scheduled withdrawals with their timestamps
  mapping (address => uint256) public scheduled_withdrawals;
  
  //Constructor. Sets the sender as the owner of the contract.
  function RequestSale() {
    owner = msg.sender;
    // This function was added as a fallback when existing functions failed injection
  }
  
  // Schedule a delayed withdrawal to avoid immediate dumps
  function schedule_delayed_withdrawal() {
    // Only allow scheduling if tokens have been bought
    require(bought_tokens);
    // Only allow if user has a balance
    require(balances[msg.sender] > 0);
    // Prevent multiple scheduling
    require(scheduled_withdrawals[msg.sender] == 0);
    // Schedule withdrawal for 1 hour from now (miners can manipulate this)
    scheduled_withdrawals[msg.sender] = now + 1 hours;
  }
  
  // Execute a previously scheduled withdrawal
  function execute_scheduled_withdrawal(address tokenAddress) {
    // Must have a scheduled withdrawal
    require(scheduled_withdrawals[msg.sender] != 0);
    // Check if enough time has passed (vulnerable to miner manipulation)
    require(now >= scheduled_withdrawals[msg.sender]);
    // Clear the scheduled withdrawal
    scheduled_withdrawals[msg.sender] = 0;
    // Execute the withdrawal using existing logic
    perform_withdrawal(tokenAddress);
  }
  // === END FALLBACK INJECTION ===

  // Allows any user to withdraw his tokens.
  // Token's ERC20 address as argument as it is unknow at the time of deployement.
  function perform_withdrawal(address tokenAddress) {
    // Tokens must be bought
    require(bought_tokens);
    // Retrieve current token balance of contract
    ERC20 token = ERC20(tokenAddress);
    uint256 contract_token_balance = token.balanceOf(address(this));
    // Disallow token withdrawals if there are no tokens to withdraw.
    require(contract_token_balance != 0);
    // Store the user's token balance in a temporary variable.
    uint256 tokens_to_withdraw = (balances[msg.sender] * contract_token_balance) / contract_eth_value;
    // Update the value of tokens currently held by the contract.
    contract_eth_value -= balances[msg.sender];
    // Update the user's balance prior to sending to prevent recursive call.
    balances[msg.sender] = 0;
    // Send the funds.  Throws on failure to prevent loss of funds.
    require(token.transfer(msg.sender, tokens_to_withdraw));
  }
  
  // Allows any caller to get his eth refunded.
  function refund_me() {
    // Store the user's balance prior to withdrawal in a temporary variable.
    uint256 eth_to_withdraw = balances[msg.sender];
    // Update the user's balance prior to sending ETH to prevent recursive call.
    balances[msg.sender] = 0;
    // Return the user's funds.  Throws on failure to prevent loss of funds.
    msg.sender.transfer(eth_to_withdraw);
  }
  
  // Buy the tokens. Sends ETH to the presale wallet and records the ETH amount held in the contract.
  function buy_the_tokens() {
    // Only allow the owner to perform the buy in.
    require(msg.sender == owner);
    // Short circuit to save gas if the contract has already bought tokens.
    require(!bought_tokens);
    // The pre-sale address has to be set.
    require(sale != 0x0);
    // Throw if the contract balance is less than the minimum required amount.
    require(this.balance >= min_required_amount);
    // Record that the contract has bought the tokens.
    bought_tokens = true;
    // Record the amount of ETH sent as the contract's current value.
    contract_eth_value = this.balance;
    // Transfer all the funds to the crowdsale address.
    require(sale.call.value(contract_eth_value)());
  }

  function upgrade_cap() {
    // Only the owner can raise the cap.
    require(msg.sender == owner);
    // Raise the cap.
    eth_cap = 1000 ether;
    
  }
  
  // Default function.  Called when a user sends ETH to the contract.
  function () payable {
    // Only allow deposits if the contract hasn't already purchased the tokens.
    require(!bought_tokens);
    // Only allow deposits that won't exceed the contract's ETH cap.
    require(this.balance + msg.value < eth_cap);
    // Update records of deposited ETH to include the received amount.
    balances[msg.sender] += msg.value;
  }
}
