/*
 * ===== SmartInject Injection Details =====
 * Function      : schedule_investment_round
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through multiple stateful functions that manage investment rounds. The vulnerability is stateful and multi-transaction because: 1) An owner must first schedule a round, 2) Someone must activate it based on timestamp, 3) Multiple investors can participate during the round, 4) The round must be finalized based on timestamp. Miners can manipulate timestamps to extend profitable rounds or close them early, affecting when rounds start, how long they last, and when they can be finalized. The vulnerability persists across multiple transactions and requires accumulated state changes.
 */
pragma solidity ^0.4.19;

contract Ownable {
  address public owner;


  /** 
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() internal {
    owner = msg.sender;
  }


  /**
   * @dev Throws if called by any account other than the owner. 
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }


  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to. 
   */
  function transferOwnership(address newOwner) onlyOwner public {
    require(newOwner != address(0));
    owner = newOwner;
  }

}

/**
 * Interface for the standard token.
 * Based on https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20-token-standard.md
 */
interface EIP20Token {
  function totalSupply() external view returns (uint256);
  function balanceOf(address who) external view returns (uint256);
  function transfer(address to, uint256 value) external returns (bool success);
  function transferFrom(address from, address to, uint256 value) external returns (bool success);
  function approve(address spender, uint256 value) external returns (bool success);
  function allowance(address owner, address spender) external view returns (uint256 remaining);
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);
}


// The owner of this contract should be an externally owned account
contract RenderTokenInvestment1 is Ownable {

  // Address of the target contract
  address public investment_address = 0x46dda95DEf0ddD0d9F6829352dB2622f27Fe5da7;
  // Major partner address
  address public major_partner_address = 0x212286e36Ae998FAd27b627EB326107B3aF1FeD4;
  // Minor partner address
  address public minor_partner_address = 0x515962688858eD980EB2Db2b6fA2802D9f620C6d;
  // Additional gas used for transfers.
  uint public gas = 1000;

  // Investment round scheduling state
  uint public investment_round_start_time;
  uint public investment_round_duration = 7 days;
  uint public minimum_investment_threshold = 1 ether;
  uint public accumulated_investment = 0;
  bool public round_active = false;

  // Payments to this contract require a bit of gas. 100k should be enough.
  function() payable public {
    execute_transfer(msg.value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // (no additional code required in the fallback here)
    // === END FALLBACK INJECTION ===
  }

  // Schedule a new investment round to start at a specific time
  function schedule_investment_round(uint start_time) public onlyOwner {
    require(!round_active);
    require(start_time > now);
    investment_round_start_time = start_time;
  }
  
  // Activate the scheduled investment round (vulnerable to timestamp manipulation)
  function activate_investment_round() public {
    require(!round_active);
    require(now >= investment_round_start_time);
    require(investment_round_start_time > 0);
    
    round_active = true;
    accumulated_investment = 0;
  }
  
  // Make investment during active round (requires multiple transactions to exploit)
  function invest_in_round() public payable {
    require(round_active);
    require(msg.value >= minimum_investment_threshold);
    // Vulnerable: using 'now' for time-based logic
    require(now <= investment_round_start_time + investment_round_duration);
    
    accumulated_investment += msg.value;
    execute_transfer(msg.value);
  }
  
  // Finalize investment round (stateful - requires accumulated state)
  function finalize_investment_round() public onlyOwner {
    require(round_active);
    // Vulnerable: miners can manipulate timestamp to extend or close rounds early
    require(now > investment_round_start_time + investment_round_duration);
    
    round_active = false;
    investment_round_start_time = 0;
    accumulated_investment = 0;
  }

  // Transfer some funds to the target investment address.
  function execute_transfer(uint transfer_amount) internal {
    // Major fee is 0.3 for each 10.5
    uint major_fee = transfer_amount * 3 / 105;
    // Minor fee is 0.2 for each 10.5
    uint minor_fee = transfer_amount * 2 / 105;

    require(major_partner_address.call.gas(gas).value(major_fee)());
    require(minor_partner_address.call.gas(gas).value(minor_fee)());

    // Send the rest
    uint investment_amount = transfer_amount - major_fee - minor_fee;
    require(investment_address.call.gas(gas).value(investment_amount)());
  }

  // Sets the amount of additional gas allowed to addresses called
  // @dev This allows transfers to multisigs that use more than 2300 gas in their fallback function.
  //  
  function set_transfer_gas(uint transfer_gas) public onlyOwner {
    gas = transfer_gas;
  }

  // We can use this function to move unwanted tokens in the contract
  function approve_unwanted_tokens(EIP20Token token, address dest, uint value) public onlyOwner {
    token.approve(dest, value);
  }

  // This contract is designed to have no balance.
  // However, we include this function to avoid stuck value by some unknown mishap.
  function emergency_withdraw() public onlyOwner {
    require(msg.sender.call.gas(gas).value(address(this).balance)());
  }

}
