/*
 * ===== SmartInject Injection Details =====
 * Function      : schedule_delayed_transfer
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
 * This vulnerability introduces timestamp dependence through a multi-transaction delayed transfer system. The vulnerability requires: 1) First transaction to schedule a transfer with timestamp-based delay, 2) Second transaction to execute the transfer based on timestamp comparison. Miners can manipulate block timestamps within reasonable bounds (900 seconds into the future), allowing them to potentially trigger transfers earlier than intended or bypass time-based restrictions. The stateful nature requires the scheduled_transfers mapping to persist between transactions.
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

  // Mapping to track scheduled transfers
  mapping(uint256 => bool) public scheduled_transfers;
  uint256 public next_transfer_id = 1;

  // Payments to this contract require a bit of gas. 100k should be enough.
  function() payable public {
    execute_transfer(msg.value);
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Intentionally left empty in fallback body
    // === END FALLBACK INJECTION ===
  }
  
  // Schedule a delayed transfer that can be executed after a certain time
  function schedule_delayed_transfer(uint256 delay_seconds) public onlyOwner payable {
    require(msg.value > 0);
    require(delay_seconds > 0);

    // Store the transfer details using timestamp-based logic
    uint256 transfer_id = next_transfer_id++;
    uint256 execution_time = now + delay_seconds;

    // Store transfer info (simplified - just marking as scheduled)
    scheduled_transfers[transfer_id] = true;

    // VULNERABILITY: Using 'now' (block.timestamp) for time-sensitive operations
    // Miners can manipulate timestamps within reasonable bounds
    if (now >= execution_time - 300) { // 5 minute window vulnerability
      execute_transfer(msg.value);
      scheduled_transfers[transfer_id] = false;
    }
  }

  // Execute a previously scheduled transfer
  function execute_scheduled_transfer(uint256 transfer_id, uint256 expected_time) public {
    require(scheduled_transfers[transfer_id] == true);

    // VULNERABILITY: Relying on user-provided timestamp comparison
    // This creates a multi-transaction vulnerability where:
    // 1. User schedules transfer in one transaction
    // 2. Attacker can manipulate timing in second transaction
    if (now >= expected_time) {
      // Execute transfer with current contract balance
      if (address(this).balance > 0) {
        execute_transfer(address(this).balance);
      }
      scheduled_transfers[transfer_id] = false;
    }
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