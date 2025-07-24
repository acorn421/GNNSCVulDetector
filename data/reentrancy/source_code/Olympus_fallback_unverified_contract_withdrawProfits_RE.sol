/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawProfits
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a classic reentrancy vulnerability where the external transfer call happens before updating the atBlock state. An attacker can create a malicious contract that calls withdrawProfits() again in its fallback function, allowing multiple withdrawals before the block number is updated. This is a stateful, multi-transaction vulnerability because: 1) The attacker must first invest funds (transaction 1), 2) Wait for blocks to accumulate profits (state persistence), 3) Deploy a malicious contract with reentrancy logic (transaction 2), 4) Call withdrawProfits() which triggers the reentrancy attack (transaction 3). The vulnerability exploits the contract's profit calculation state that persists between transactions.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Withdraw accumulated profits for the caller
    function withdrawProfits() public {
        require(invested[msg.sender] > 0, "No investment found");
        
        uint thisBalance = address(this).balance;
        uint amount = invested[msg.sender] * calculateProfitPercent(thisBalance) / 1000 * (block.number - atBlock[msg.sender]) / 6100;
        
        require(amount > 0, "No profits to withdraw");
        require(thisBalance >= amount, "Insufficient contract balance");
        
        // VULNERABILITY: External call before state update
        // This allows reentrancy attacks where the external contract
        // can call back into this function before state is updated
        msg.sender.transfer(amount);
        
        // State update happens AFTER external call - vulnerable to reentrancy
        atBlock[msg.sender] = block.number;
    }
    // === END FALLBACK INJECTION ===

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
        uint ofBalance = invested[_account]* calculateProfitPercent(thisBalance) / 1000 * (block.number - atBlock[msg.sender]) / 6100;
        return ofBalance;
        
        
    }
}
