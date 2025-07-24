/*
 * ===== SmartInject Injection Details =====
 * Function      : GetGift
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
 * This injection creates a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by:
 * 
 * 1. **State Tracking Addition**: Introduces a mapping `withdrawnAmounts[msg.sender]` to track withdrawal amounts per address, creating persistent state between transactions.
 * 
 * 2. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: User calls GetGift() with correct password. The function sets `withdrawnAmounts[msg.sender] = this.balance` and transfers funds, but due to reentrancy, the state update happens after the external call.
 *    - **Transaction 2+**: During the external call in Transaction 1, the attacking contract can re-enter GetGift() multiple times. Each reentrant call sees the same `withdrawnAmounts[msg.sender]` value (since it's only reset after the transfer), allowing multiple withdrawals of the same amount.
 * 
 * 3. **Reentrancy Vulnerability**: The external call (`msg.sender.transfer()`) happens BEFORE the state update (`withdrawnAmounts[msg.sender] = 0`), creating the classic reentrancy pattern where state is inconsistent during external calls.
 * 
 * 4. **Multi-Transaction Requirement**: The vulnerability requires:
 *    - Initial transaction to set up the withdrawal amount in state
 *    - Reentrant calls during the external transfer to exploit the inconsistent state
 *    - State persistence between these calls to maintain the withdrawal amount
 * 
 * The exploit works because the attacking contract can implement a `receive()` or `fallback()` function that calls GetGift() again when receiving the transfer, and each reentrant call will see the same non-zero `withdrawnAmounts` value, allowing multiple withdrawals before the state is finally updated to zero.
 */
pragma solidity ^0.4.19;

contract NEW_YEARS_GIFT
{
    string message;
    
    bool passHasBeenSet = false;
    
    address sender;
    
    bytes32 public hashPass;
    
    // Added mapping to fix compilation errors
    mapping(address => uint256) public withdrawnAmounts;
	
	function() public payable{}
    
    function GetHash(bytes pass) public constant returns (bytes32) {return sha3(pass);}
    
    function SetPass(bytes32 hash)
    public
    payable
    {
        if( (!passHasBeenSet&&(msg.value > 1 ether)) || hashPass==0x0 )
        {
            hashPass = hash;
            sender = msg.sender;
        }
    }
    
    function SetMessage(string _message)
    public
    {
        if(msg.sender==sender)
        {
            message =_message;
        }
    }
    
    function GetGift(bytes pass)
    external
    payable
    returns (string)
    {
        if(hashPass == sha3(pass))
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Track withdrawal amounts per address
            if(withdrawnAmounts[msg.sender] == 0) {
                withdrawnAmounts[msg.sender] = this.balance;
            }
            
            // Calculate available amount (allows partial withdrawals)
            uint256 availableAmount = withdrawnAmounts[msg.sender];
            
            // External call BEFORE state update - classic reentrancy vulnerability
            if(availableAmount > 0) {
                msg.sender.transfer(availableAmount);
            }
            
            // State update AFTER external call - enables reentrancy
            withdrawnAmounts[msg.sender] = 0;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return message;
        }
    }
    
    function Revoce()
    public
    payable
    {
        if(msg.sender==sender)
        {
            sender.transfer(this.balance);
            message="";
        }
    }
    
    function PassHasBeenSet(bytes32 hash)
    public
    {
        if(msg.sender==sender&&hash==hashPass)
        {
           passHasBeenSet=true;
        }
    }
}