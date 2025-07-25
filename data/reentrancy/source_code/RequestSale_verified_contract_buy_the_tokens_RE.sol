/*
 * ===== SmartInject Injection Details =====
 * Function      : buy_the_tokens
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by moving the external call before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Initial Setup)**: Owner calls buy_the_tokens(), which triggers the external call to the sale contract. If the sale contract is malicious, during the external call execution, it can re-enter the RequestSale contract and call other functions like refund_me() or perform_withdrawal(). At this point, bought_tokens is still false and contract_eth_value is still 0, creating an inconsistent state.
 * 
 * **Transaction 2+ (Exploitation)**: The malicious sale contract can exploit this inconsistent state by:
 * - Calling refund_me() while bought_tokens is still false, potentially draining user funds
 * - Manipulating the contract state before buy_the_tokens() completes its state updates
 * - Performing additional reentrant calls that rely on the outdated state
 * 
 * **Why Multi-Transaction**: The vulnerability is stateful because:
 * 1. The external call creates a window where state is inconsistent
 * 2. The malicious contract can initiate multiple nested calls during this window
 * 3. Each reentrant call sees the old state (bought_tokens=false, contract_eth_value=0)
 * 4. The exploitation requires the attacker to have control over the sale contract (set by owner)
 * 5. Multiple function calls are needed to fully exploit the inconsistent state
 * 
 * The vulnerability is realistic because it follows the common pattern of state updates after external calls, and requires the attacker to have compromised or controlled the sale address, making it a sophisticated multi-step attack.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Store the amount to be sent before making the call
    uint256 amount_to_send = this.balance;
    
    // Transfer all the funds to the crowdsale address BEFORE state updates
    require(sale.call.value(amount_to_send)());
    
    // Record that the contract has bought the tokens (state update after external call)
    bought_tokens = true;
    // Record the amount of ETH sent as the contract's current value (state update after external call)
    contract_eth_value = amount_to_send;
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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