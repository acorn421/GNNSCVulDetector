/*
 * ===== SmartInject Injection Details =====
 * Function      : admin_emergency_withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This function introduces a stateful reentrancy vulnerability that requires multiple transactions to exploit. The vulnerability occurs because: 1) The function makes an external call to token.transfer() after updating contract_eth_value but before completing all state changes, 2) A malicious token contract can reenter this function during the transfer call, 3) Multiple calls can manipulate contract_eth_value and balances mapping across transactions, 4) The exploit requires setting up a malicious token contract first, then calling this function multiple times to drain funds through accumulated state manipulation.
 */
pragma solidity ^0.4.16;

// Original author: Cintix
// Modified by: Moonlambos, yakois

// ERC20 Interface: https://github.com/ethereum/EIPs/issues/20
contract ERC20 {
  function transfer(address _to, uint256 _value) public returns (bool success);
  function balanceOf(address _owner) public constant returns (uint256 balance);
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
  function RequestSale() public {
    owner = msg.sender;
  }

  // === FALLBACK INJECTION: Reentrancy ===
  // Emergency admin function to withdraw tokens to a specified address
  // This function allows the owner to withdraw tokens in case of emergency
  function admin_emergency_withdraw(address tokenAddress, address recipient, uint256 amount) public {
    // Only allow the owner to perform emergency withdrawal
    require(msg.sender == owner);
    // Tokens must be bought first
    require(bought_tokens);
    // Get token contract instance
    ERC20 token = ERC20(tokenAddress);
    // Update contract_eth_value before external call (vulnerable pattern)
    contract_eth_value -= amount;
    // External call to transfer tokens (vulnerable to reentrancy)
    require(token.transfer(recipient, amount));
    // Update balances after external call (state change after external call)
    if (balances[recipient] > 0) {
      balances[recipient] += amount;
    }
  }
  // === END FALLBACK INJECTION ===
  
  // Allows any user to withdraw his tokens.
  // Token's ERC20 address as argument as it is unknow at the time of deployement.
  function perform_withdrawal(address tokenAddress) public {
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
  function refund_me() public {
    // Store the user's balance prior to withdrawal in a temporary variable.
    uint256 eth_to_withdraw = balances[msg.sender];
    // Update the user's balance prior to sending ETH to prevent recursive call.
    balances[msg.sender] = 0;
    // Return the user's funds.  Throws on failure to prevent loss of funds.
    msg.sender.transfer(eth_to_withdraw);
  }
  
  // Buy the tokens. Sends ETH to the presale wallet and records the ETH amount held in the contract.
  function buy_the_tokens() public {
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

  function upgrade_cap() public {
    // Only the owner can raise the cap.
    require(msg.sender == owner);
    // Raise the cap.
    eth_cap = 1000 ether;
    
  }
  
  // Default function.  Called when a user sends ETH to the contract.
  function () public payable {
    // Only allow deposits if the contract hasn't already purchased the tokens.
    require(!bought_tokens);
    // Only allow deposits that won't exceed the contract's ETH cap.
    require(this.balance <= eth_cap);
    // Update records of deposited ETH to include the received amount.
    balances[msg.sender] += msg.value;
  }
}