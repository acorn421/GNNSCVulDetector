/*
 * ===== SmartInject Injection Details =====
 * Function      : perform_withdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp dependence vulnerability through time-based withdrawal calculations that use block.timestamp for penalty/bonus calculations. The vulnerability creates a flawed time approximation by using block.number arithmetic and allows miners to manipulate withdrawal amounts by controlling block timestamps. This creates a multi-transaction vulnerability where: 1) Users first deposit ETH, 2) Owner calls buy_the_tokens(), 3) Users call perform_withdrawal() at different times with manipulated timestamps. The state persists across transactions as withdrawal amounts depend on accumulated time since purchase, and miners can exploit this by manipulating block.timestamp to maximize bonuses or minimize penalties across multiple withdrawal transactions.
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
  
  //Constructor. Sets the sender as the owner of the contract.
  function RequestSale() {
    owner = msg.sender;
  }
  
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Time-based withdrawal bonus calculation using block.timestamp
    uint256 withdrawal_multiplier = 1000; // Base multiplier (100.0%)
    uint256 time_since_purchase = block.timestamp - (block.number - 100) * 15; // Approximating purchase time
    
    // Early withdrawal penalty: lose 2% per day for first 30 days
    if (time_since_purchase < 30 days) {
        uint256 penalty_days = (30 days - time_since_purchase) / 1 days;
        withdrawal_multiplier -= penalty_days * 20; // 2% = 20/1000
    }
    // Late withdrawal bonus: gain 1% per day after 90 days
    else if (time_since_purchase > 90 days) {
        uint256 bonus_days = (time_since_purchase - 90 days) / 1 days;
        withdrawal_multiplier += bonus_days * 10; // 1% = 10/1000
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    // Store the user's token balance in a temporary variable.
    uint256 tokens_to_withdraw = (balances[msg.sender] * contract_token_balance) / contract_eth_value;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Apply time-based multiplier to withdrawal amount
    tokens_to_withdraw = (tokens_to_withdraw * withdrawal_multiplier) / 1000;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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