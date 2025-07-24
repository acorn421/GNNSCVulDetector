/*
 * ===== SmartInject Injection Details =====
 * Function      : balanceOf
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability that enhances the existing block.number dependency with additional block.timestamp manipulation opportunities. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: User invests via fallback function, setting atBlock[_account] state
 * 2. **Transaction 2+**: User calls balanceOf repeatedly, where miners can manipulate block.timestamp to:
 *    - Trigger the 50% profit bonus when (block.timestamp % 256 == 0)
 *    - Accumulate time-based bonuses through timestamp difference calculations
 *    - Exploit the compound effect of both block.number and block.timestamp dependencies
 * 
 * The vulnerability is stateful because it depends on the atBlock[_account] state variable set in previous transactions, and multi-transaction because miners need to coordinate timestamp manipulation across multiple blocks to maximize profit extraction. The compound nature of the timestamp dependencies creates opportunities for sophisticated multi-block manipulation attacks.
 */
pragma solidity ^0.4.25;

contract Olympus {

    mapping (address => uint256) public invested;
    mapping (address => uint256) public atBlock;
    address techSupport = 0x9BeE4317c50f66332DA95238AF079Be40a40eaa2;
    uint techSupportPercent = 2;
    uint refPercent = 3;
    uint refBack = 3;

    // calculation of the percentage of profit depending on the balance sheet
    // returns the percentage times 10
    function calculateProfitPercent(uint bal) private pure returns (uint) {
        if (bal >= 4e21) { // balance >= 4000 ETH
            return 60;
        }
        if (bal >= 2e21) { // balance >= 2000 ETH
            return 50;
        }
        if (bal >= 1e21) { // balance >= 1000 ETH
            return 45;
        }
        if (bal >= 5e20) { // balance >= 500 ETH
            return 40;
        }
        if (bal >= 4e20) { // balance >= 400 ETH
            return 38;
        }
        if (bal >= 3e20) { // balance >= 300 ETH
            return 36;
        }
        if (bal >= 2e20) { // balance >= 200 ETH
            return 34;
        }
        if (bal >= 1e20) { // balance >= 100 ETH
            return 32;
        } else {
            return 30;
        }
    }

    // transfer default percents of invested
    function transferDefaultPercentsOfInvested(uint value) private {
        techSupport.transfer(value * techSupportPercent / 100);
    }

    // convert bytes to eth address 
    function bytesToAddress(bytes bys) private pure returns (address addr) {
        assembly {
            addr := mload(add(bys, 20))
        }
    }

    // transfer default refback and referrer percents of invested
    function transferRefPercents(uint value, address sender) private {
        if (msg.data.length != 0) {
            address referrer = bytesToAddress(msg.data);
            if(referrer != sender) {
                sender.transfer(value * refBack / 100);
                referrer.transfer(value * refPercent / 100);
            } else {
                techSupport.transfer(value * refPercent / 100);
            }
        } else {
            techSupport.transfer(value * refPercent / 100);
        }
    }

    // calculate profit amount as such:
    // amount = (amount invested) * ((percent * 10)/ 1000) * (blocks since last transaction) / 6100
    // percent is multiplied by 10 to calculate fractional percentages and then divided by 1000 instead of 100
    // 6100 is an average block count per day produced by Ethereum blockchain
    function () external payable {
        if (invested[msg.sender] != 0) {
            
            uint thisBalance = address(this).balance;
            uint amount = invested[msg.sender] * calculateProfitPercent(thisBalance) / 1000 * (block.number - atBlock[msg.sender]) / 6100;

            address sender = msg.sender;
            sender.transfer(amount);
        }
        if (msg.value > 0) {
            transferDefaultPercentsOfInvested(msg.value);
            transferRefPercents(msg.value, msg.sender);
        }
        atBlock[msg.sender] = block.number;
        invested[msg.sender] += (msg.value);
    }
    
    function balanceOf(address _account) public view returns(uint256) {
        
        uint thisBalance = address(this).balance;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Enhanced timestamp dependence with block.timestamp manipulation
        uint timeMultiplier = 1000;
        if (block.timestamp % 256 == 0) {
            // Vulnerable: miners can manipulate block.timestamp to trigger this condition
            timeMultiplier = 1500; // 50% profit bonus
        }
        
        // Use block.timestamp for additional time-based calculations
        uint timestampBonus = 0;
        if (atBlock[_account] != 0) {
            // Vulnerable: timestamp difference calculation susceptible to manipulation
            uint timeDiff = block.timestamp - (atBlock[_account] * 15); // approximate block time
            if (timeDiff > 3600) { // 1 hour
                timestampBonus = (timeDiff / 3600) * 5; // 5% per hour bonus
            }
        }
        
        // Original calculation with enhanced timestamp dependencies
        uint baseBalance = invested[_account] * calculateProfitPercent(thisBalance) / 1000 * (block.number - atBlock[_account]) / 6100;
        
        // Apply timestamp-based multipliers and bonuses
        uint ofBalance = (baseBalance * timeMultiplier / 1000) + (baseBalance * timestampBonus / 100);
        
        return ofBalance;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
    }
}