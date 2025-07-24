/*
 * ===== SmartInject Injection Details =====
 * Function      : SetPass
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to msg.sender after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added external call `msg.sender.call.value(0)("")` after state modifications
 * 2. The call occurs after `hashPass` and `sender` are updated, creating a reentrancy window
 * 3. Added a realistic comment about notification callback
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls SetPass with 1+ ether, setting hashPass and sender
 * 2. **During reentrancy**: The external call triggers attacker's fallback function
 * 3. **Reentrancy call**: Attacker calls SetPass again with hashPass==0x00 condition
 * 4. **State manipulation**: Second call can overwrite hashPass/sender while first call is still executing
 * 5. **Accumulated effect**: Attacker can manipulate the password setting process across multiple overlapping transactions
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the persistent state changes (hashPass, sender) across transaction boundaries
 * - Each reentrancy call can modify state that affects subsequent calls
 * - The exploit relies on accumulated state changes from previous SetPass calls
 * - Single transaction exploitation is not possible due to the nature of state persistence and the specific conditions
 * 
 * **Realistic Integration:**
 * The external call appears as a legitimate notification mechanism, making it a subtle and realistic vulnerability that could exist in production code.
 */
pragma solidity ^0.4.19;

contract ETH_GIFT
{
    function GetGift(bytes pass)
    external
    payable
    {
        if(hashPass == keccak256(pass))
        {
            msg.sender.transfer(this.balance);
        }
    }
    
    function GetGift()
    public
    payable
    {
        if(msg.sender==reciver)
        {
            msg.sender.transfer(this.balance);
        }
    }
    
    bytes32 hashPass;
    
    bool closed = false;
    
    address sender;
    
    address reciver;
 
    function GetHash(bytes pass) public pure returns (bytes32) {return keccak256(pass);}
    
    function SetPass(bytes32 hash)
    public
    payable
    {
        if( (!closed&&(msg.value > 1 ether)) || hashPass==0x00)
        {
            hashPass = hash;
            sender = msg.sender;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify sender about successful password setting
            if(msg.sender.call.value(0)(""))
            {
                // Callback completed successfully
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
   
    function SetReciver(address _reciver)
    public
    {
        if(msg.sender==sender)
        {
            reciver = _reciver;
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
    
    function() public payable{}
    
}