/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * STATEFUL, MULTI-TRANSACTION Reentrancy vulnerability introduced through the following mechanisms:
 * 
 * **Changes Made:**
 * 1. **Added State Variables**: 
 *    - `pendingApprovals` mapping to track approvals in progress
 *    - `approvalNotificationTargets` mapping to store user-configured notification contracts
 *    - `allowances` mapping to manage actual allowance state
 * 
 * 2. **External Calls Before State Updates**: 
 *    - Added external call to `spender` contract via `onApprovalReceived` callback
 *    - Added external call to optional notification target contract
 *    - Both calls occur BEFORE the allowance state is updated
 * 
 * 3. **Reentrancy Helper Function**: 
 *    - Added `setApprovalNotificationTarget()` to allow users to configure notification contracts
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `setApprovalNotificationTarget(maliciousContract)` to register their malicious contract as notification target
 * - This establishes persistent state for future exploitation
 * 
 * **Transaction 2 (Initial Approval):**
 * - User calls `approve(attackerContract, 1000 tokens)`
 * - Function sets `pendingApprovals[user] = 1000`
 * - External call to `attackerContract.onApprovalReceived()` is made
 * - Attacker's contract can now see the pending approval but actual allowance not yet set
 * - Attacker records this information but doesn't exploit immediately
 * 
 * **Transaction 3 (Exploitation):**
 * - User calls `approve(attackerContract, 500 tokens)` (reducing allowance)
 * - Function sets `pendingApprovals[user] = 500`
 * - External call to `attackerContract.onApprovalReceived()` triggers
 * - **REENTRANCY**: Attacker calls back into `approve()` with original amount (1000)
 * - During reentrancy, `allowances[user][attacker]` is set to 1000
 * - Original call completes, setting `allowances[user][attacker]` to 500
 * - But attacker already has access to 1000 tokens due to the reentrancy
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 1. **State Accumulation**: The vulnerability relies on the `approvalNotificationTargets` mapping being configured in a prior transaction
 * 2. **Exploitation Timing**: The attacker must wait for legitimate approval calls to trigger the reentrancy
 * 3. **Cross-Transaction State**: The `pendingApprovals` state persists between transactions, allowing the attacker to compare current vs previous approvals
 * 4. **Sequential Dependency**: Each transaction builds upon state from previous transactions - cannot be exploited atomically
 * 
 * This creates a sophisticated, realistic vulnerability that requires careful orchestration across multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.19;

contract Ownable {
  address public owner;

  /** 
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  constructor() public {
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
 * Standard token implementation with allowances and approval hooks.
 * Based on https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20-token-standard.md
 */
contract EIP20Token {
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  mapping(address => mapping(address => uint256)) public allowances;
  mapping(address => uint256) public pendingApprovals;
  mapping(address => address) public approvalNotificationTargets;

  function approve(address spender, uint256 value) public returns (bool success) {
      // Store pending approval for multi-transaction validation
      pendingApprovals[msg.sender] = value;
      
      // External call to spender for approval notification - VULNERABILITY: Before state update
      if (isContract(spender)) {
          // Call notification function on spender contract
          bool callSuccess = spender.call(abi.encodeWithSignature("onApprovalReceived(address,uint256)", msg.sender, value));
          // Continue regardless of call success to maintain functionality
      }
      
      // Call optional notification target if configured - VULNERABILITY: Additional external call
      if (approvalNotificationTargets[msg.sender] != address(0)) {
          address notificationTarget = approvalNotificationTargets[msg.sender];
          notificationTarget.call(abi.encodeWithSignature("approvalNotification(address,address,uint256)", msg.sender, spender, value));
      }
      
      // VULNERABILITY: State update happens after external calls
      // This allows reentrancy to occur before allowance is properly set
      allowances[msg.sender][spender] = value;
      
      // Clear pending approval after successful completion
      pendingApprovals[msg.sender] = 0;
      
      emit Approval(msg.sender, spender, value);
      return true;
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  function setApprovalNotificationTarget(address target) public {
      approvalNotificationTargets[msg.sender] = target;
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function allowance(address owner, address spender) public view returns (uint256 remaining) {
      return allowances[owner][spender];
  }
  function totalSupply() public view returns (uint256);
  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool success);
  function transferFrom(address from, address to, uint256 value) public returns (bool success);

  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);

  function isContract(address addr) internal view returns (bool) {
      uint256 size;
      assembly { size := extcodesize(addr) }
      return size > 0;
  }
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

  // Payments to this contract require a bit of gas. 100k should be enough.
  function() public payable {
    execute_transfer(msg.value);
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
