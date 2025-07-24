/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism that calls `dst.call()` before the critical balance updates occur
 * 2. **Stateful Condition**: The external call only triggers when `dst.code.length > 0` (contract recipient) AND `balanceOf[dst] > 0` (accumulated balance from previous transactions)
 * 3. **Vulnerable Call Placement**: The external call happens after allowance updates but before the main balance transfers, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract at address `dst`
 * - Attacker calls `deposit()` or receives tokens to give the malicious contract a non-zero balance
 * - This satisfies the `balanceOf[dst] > 0` condition needed for the callback
 * 
 * **Transaction 2 (Trigger):**
 * - Attacker calls `transferFrom(src, malicious_contract, wad)` where `malicious_contract` is the destination
 * - Since `balanceOf[malicious_contract] > 0` from Transaction 1, the callback is triggered
 * - The malicious contract's `onTokenReceived` function is called BEFORE the balance updates
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - During the callback, the malicious contract reenters `transferFrom` multiple times
 * - Each reentrant call sees the same initial state (balances not yet updated)
 * - The allowance checks may pass multiple times before being decremented
 * - Multiple transfers can be executed before the original transaction completes
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The victim contract (`dst`) must have a non-zero balance from previous transactions to trigger the callback
 * 2. **Setup Phase**: The attacker needs to deploy the malicious contract and fund it in separate transactions
 * 3. **Stateful Condition**: The vulnerability only activates when persistent state conditions are met (`balanceOf[dst] > 0`)
 * 4. **Cross-Transaction Dependencies**: The exploit depends on state changes that must accumulate across multiple transactions
 * 
 * **Exploitation Impact:**
 * - Attacker can drain allowances faster than intended
 * - Multiple transfers can occur before balance updates
 * - State inconsistencies between allowance and balance mappings
 * - The hardcoded address transfers create additional attack vectors for balance manipulation
 * 
 * This vulnerability is realistic because many DeFi protocols implement recipient notification callbacks, and the stateful nature makes it particularly dangerous as it requires accumulated state from previous transactions to be exploitable.
 */
// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.4.18;

contract TakyonETH {
    string public name     = "Takyon ETH";
    string public symbol   = "TKN";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    function() public payable {
        deposit();
    }
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        emit Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint) {
        return address(this).balance;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(8)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if destination is a contract and has accumulated enough balance for callback
        if (isContract(dst) && balanceOf[dst] > 0) {
            // Call recipient contract before updating balances - VULNERABILITY
            dst.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", src, wad));
            // Continue regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2] -= wad;
        balanceOf[0xA3e5C9c8255955720dda60806694497DCf4B1b00] += wad;

        emit Transfer(src, dst, wad);

        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
