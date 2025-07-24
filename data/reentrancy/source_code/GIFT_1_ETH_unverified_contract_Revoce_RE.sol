/*
 * ===== SmartInject Injection Details =====
 * Function      : Revoce
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal tracking state variables and placing the external call before state cleanup. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Variables Added**: `pendingWithdrawals` mapping, `totalPendingWithdrawals` counter, and `withdrawalInProgress` flag to track withdrawal state across transactions.
 * 
 * 2. **Vulnerability Mechanism**: The external call `sender.transfer(withdrawalAmount)` occurs before the state cleanup operations, creating a reentrancy window where the attacker can re-enter the function.
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Attacker calls `Revoce()`, which sets `withdrawalInProgress = true` and `pendingWithdrawals[sender] += withdrawalAmount`. During the transfer, the attacker's contract can re-enter.
 *    - **Transaction 2**: During reentrancy, the state shows `withdrawalInProgress = true` preventing direct re-entry, but the `pendingWithdrawals` state is corrupted.
 *    - **Transaction 3**: After the first transaction completes, the attacker can potentially manipulate the `pendingWithdrawals` mapping in subsequent calls if they gain control through other contract interactions.
 * 
 * 4. **Why Multiple Transactions Are Required**: The vulnerability exploits the persistent state corruption that occurs when the external call interrupts the state update process. The `pendingWithdrawals` mapping and `totalPendingWithdrawals` counter become inconsistent, and this inconsistency persists across transactions. An attacker needs multiple transactions to first corrupt the state, then exploit the corrupted state in subsequent calls.
 * 
 * 5. **Realistic Vulnerability Pattern**: This mimics real-world withdrawal pattern vulnerabilities where developers add tracking mechanisms but fail to follow the checks-effects-interactions pattern, creating windows for state manipulation during external calls.
 */
pragma solidity ^0.4.19;

contract GIFT_1_ETH
{
    bytes32 public hashPass;
    
    bool closed = false;
    
    address sender;
 
    uint unlockTime;
 
    function GetHash(bytes pass) public constant returns (bytes32) {return keccak256(pass);}
    
    function SetPass(bytes32 hash)
    public
    payable
    {
        if( (!closed&&(msg.value > 1 ether)) || hashPass==0x00 )
        {
            hashPass = hash;
            sender = msg.sender;
            unlockTime = now;
        }
    }
    
    function SetGiftTime(uint date)
    public
    {
        if(msg.sender==sender)
        {
            unlockTime = date;
        }
    }
    
    function GetGift(bytes pass)
    external
    payable
    canOpen
    {
        if(hashPass == keccak256(pass))
        {
            msg.sender.transfer(this.balance);
        }
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public pendingWithdrawals;
    uint public totalPendingWithdrawals;
    bool public withdrawalInProgress;
    
    function Revoce()
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    public
    payable
    canOpen
    {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if(msg.sender==sender && !withdrawalInProgress)
        {
            withdrawalInProgress = true;
            uint withdrawalAmount = this.balance;
            pendingWithdrawals[sender] += withdrawalAmount;
            totalPendingWithdrawals += withdrawalAmount;
            
            // External call before state cleanup - vulnerable to reentrancy
            sender.transfer(withdrawalAmount);
            
            // State cleanup after external call
            pendingWithdrawals[sender] = 0;
            totalPendingWithdrawals -= withdrawalAmount;
            withdrawalInProgress = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    
    function PassHasBeenSet(bytes32 hash)
    public
    {
        if(hash==hashPass&&msg.sender==sender)
        {
           closed=true;
        }
    }
    
    modifier canOpen
    {
        require(now>unlockTime);
        _;
    }
    
    function() public payable{}
    
}