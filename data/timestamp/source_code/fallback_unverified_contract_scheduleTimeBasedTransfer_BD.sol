/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimeBasedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability where the contract relies on 'now' (block.timestamp) for time-based operations. The vulnerability is stateful and multi-transaction: 1) First transaction schedules a transfer with a specific unlock time, 2) State persists between transactions with locked tokens, 3) Second transaction attempts to execute the transfer based on timestamp comparison. Miners can manipulate block timestamps within reasonable bounds to potentially execute transfers earlier than intended, or delay execution by mining blocks with earlier timestamps.
 */
// Copyright (C) 2015, 2016, 2017 Dapphub

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity ^0.4.18;

contract WETH9 {
    string public name     = "Wrapped Ether";
    string public symbol   = "WETH";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // New state variables for time-based transfers
    struct ScheduledTransfer {
        address recipient;
        uint256 amount;
        uint256 unlockTime;
        bool executed;
    }
    
    mapping(address => ScheduledTransfer) public scheduledTransfers;
    
    event TransferScheduled(address indexed from, address indexed to, uint256 amount, uint256 unlockTime);
    event ScheduledTransferExecuted(address indexed from, address indexed to, uint256 amount);
    
    // Schedule a transfer to execute at a specific time
    function scheduleTimeBasedTransfer(address recipient, uint256 amount, uint256 unlockTime) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        require(unlockTime > now, "Unlock time must be in the future");
        require(scheduledTransfers[msg.sender].amount == 0, "Already have a scheduled transfer");
        
        scheduledTransfers[msg.sender] = ScheduledTransfer({
            recipient: recipient,
            amount: amount,
            unlockTime: unlockTime,
            executed: false
        });
        
        // Lock the tokens by reducing balance
        balanceOf[msg.sender] -= amount;
        
        TransferScheduled(msg.sender, recipient, amount, unlockTime);
    }
    
    // Execute a scheduled transfer (vulnerable to timestamp manipulation)
    function executeScheduledTransfer(address sender) public {
        ScheduledTransfer storage transfer = scheduledTransfers[sender];
        require(transfer.amount > 0, "No scheduled transfer");
        require(!transfer.executed, "Transfer already executed");
        require(now >= transfer.unlockTime, "Transfer still locked");
        
        // Execute the transfer
        balanceOf[transfer.recipient] += transfer.amount;
        transfer.executed = true;
        
        Transfer(sender, transfer.recipient, transfer.amount);
        ScheduledTransferExecuted(sender, transfer.recipient, transfer.amount);
    }
    
    // Cancel a scheduled transfer (can only be done before execution)
    function cancelScheduledTransfer() public {
        ScheduledTransfer storage transfer = scheduledTransfers[msg.sender];
        require(transfer.amount > 0, "No scheduled transfer to cancel");
        require(!transfer.executed, "Transfer already executed");
        
        // Return the locked tokens
        balanceOf[msg.sender] += transfer.amount;
        
        // Clear the scheduled transfer
        delete scheduledTransfers[msg.sender];
    }
    // === END FALLBACK INJECTION ===

    function() public payable {
        deposit();
    }
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        Deposit(msg.sender, msg.value);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint) {
        return this.balance;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        Approval(msg.sender, guy, wad);
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

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        Transfer(src, dst, wad);

        return true;
    }
}

/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 ... (rest of license text unchanged) ...
*/
