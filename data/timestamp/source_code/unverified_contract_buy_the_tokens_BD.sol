/*
 * ===== SmartInject Injection Details =====
 * Function      : buy_the_tokens
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
 * Introduced a multi-transaction timestamp dependence vulnerability through three key modifications:
 * 
 * 1. **Time-based Purchase Window**: Added a requirement that purchases can only occur during specific 30-minute windows each hour (when block.timestamp % 3600 >= 1800). This creates a timing dependency that requires multiple transaction attempts to exploit.
 * 
 * 2. **Persistent State Tracking**: Added last_purchase_attempt state variable that stores the timestamp of each purchase attempt. This state persists between transactions and can be manipulated by attackers timing their transactions strategically.
 * 
 * 3. **Dynamic Minimum Amount**: Made the minimum required amount dependent on the current timestamp (block.timestamp % 86400), creating a sliding scale that changes throughout the day. This means the same balance might be sufficient at one time but insufficient at another.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Timing Window Manipulation**: An attacker (or miner) can observe when the purchase window is closed and wait for the favorable timing window to open, then submit their transaction at the optimal moment.
 * 
 * 2. **Sequential State Manipulation**: The last_purchase_attempt variable can be manipulated across multiple transactions to influence future purchase attempts or other contract behavior.
 * 
 * 3. **Daily Timing Arbitrage**: The dynamic minimum amount creates opportunities for attackers to time their actions when the required amount is lowest (early in the day) versus highest (late in the day).
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires monitoring and storing timestamp values in state variables that persist between transactions.
 * 
 * 2. **Timing Coordination**: Exploiting the vulnerability requires waiting for specific timestamp conditions to be met, which cannot be guaranteed in a single transaction.
 * 
 * 3. **Window-based Exploitation**: The 30-minute windows create natural barriers that require multiple attempts or coordinated timing across different blocks.
 * 
 * This creates a realistic timestamp dependence vulnerability that mirrors real-world scenarios where contracts make critical decisions based on block timestamps, leading to potential manipulation by miners or sophisticated attackers who can time their transactions strategically.
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
  // Store the purchase attempt timestamp for potential manipulation (timestamp dependence vulnerability)
  uint256 public last_purchase_attempt;

  //Constructor. Sets the sender as the owner of the contract.
  constructor() public {
    owner = msg.sender;
  }
  
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // VULNERABILITY: Time-based purchase window - only allow purchases during "favorable" times
    // This creates a timestamp dependence that can be exploited across multiple transactions
    require(block.timestamp % 3600 >= 1800);
    // VULNERABILITY: Store the purchase attempt timestamp for potential manipulation
    // This state persists between transactions and affects future behavior
    last_purchase_attempt = block.timestamp;
    // VULNERABILITY: Adjust minimum required amount based on timestamp
    // This creates a timing dependency that changes the purchase conditions
    uint256 adjusted_min_amount = min_required_amount + ((block.timestamp % 86400) * 1 ether / 86400);
    require(this.balance >= adjusted_min_amount);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    require(this.balance + msg.value < eth_cap);
    // Update records of deposited ETH to include the received amount.
    balances[msg.sender] += msg.value;
  }
}