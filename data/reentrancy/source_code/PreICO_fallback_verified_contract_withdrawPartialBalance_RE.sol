/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawPartialBalance
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack. The attack requires: 1) First calling requestWithdrawal() to set up pending withdrawal state, 2) Then calling withdrawPartialBalance() which makes an external call before clearing the pending amount, 3) The external call can reenter withdrawPartialBalance() multiple times before the state is updated, draining more funds than intended. The vulnerability is stateful because it depends on the pendingWithdrawals mapping persisting between transactions.
 */
pragma solidity ^0.4.8;

contract PreICO {
    bool public isPreIco;
    address manager;

    uint256 maxPreOrderAmount = 500000000000000000000; //in wei
    uint256 maxAmountSupply = 1875000000000000000000;

    // === FALLBACK INJECTION: Reentrancy ===
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;
    // === END FALLBACK INJECTION ===

    struct dataHolder {
        uint256 balance;
        bool init;
    }
    mapping(address => dataHolder) holders;
    address[] listHolders;

    function PreICO(){
        manager = msg.sender;
        isPreIco = false;
    }

    modifier isManager(){
        if (msg.sender!=manager) throw;
        _;
    }

    function kill() isManager {
        suicide(manager);
    }

    function getMoney() isManager {
        if(manager.send(this.balance)==false) throw;
    }

    function startPreICO() isManager {
        isPreIco = true;
    }

    function stopPreICO() isManager {
        isPreIco = false;
    }

    function countHolders() constant returns(uint256){
        return listHolders.length;
    }

    function getItemHolder(uint256 index) constant returns(address){
        if(index >= listHolders.length || listHolders.length == 0) return address(0x0);
        return listHolders[index];
    }

    function balancsHolder(address who) constant returns(uint256){
        return holders[who].balance;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    function requestWithdrawal(uint256 amount) public {
        require(isPreIco == false, "PreICO still active");
        require(holders[msg.sender].balance >= amount, "Insufficient balance");
        require(amount > 0, "Amount must be positive");

        pendingWithdrawals[msg.sender] += amount;
        holders[msg.sender].balance -= amount;
    }

    function withdrawPartialBalance() public {
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        require(withdrawalInProgress[msg.sender] == false, "Withdrawal already in progress");

        withdrawalInProgress[msg.sender] = true;
        uint256 amount = pendingWithdrawals[msg.sender];

        // Vulnerable to reentrancy: external call before state update
        if(msg.sender.call.value(amount)()) {
            pendingWithdrawals[msg.sender] = 0;
            withdrawalInProgress[msg.sender] = false;
        } else {
            withdrawalInProgress[msg.sender] = false;
            throw;
        }
    }
    // === END FALLBACK INJECTION ===

    function() payable
    {
        if(isPreIco == false) throw;

        uint256 amount = msg.value;

        uint256 return_amount = 0;

        if(this.balance + msg.value > maxAmountSupply){
            amount = maxAmountSupply - this.balance ;
            return_amount = msg.value - amount;
        }

        if(holders[msg.sender].init == false){
            listHolders.push(msg.sender);
            holders[msg.sender].init = true;
        }

        if((amount+holders[msg.sender].balance) > maxPreOrderAmount){
            return_amount += ((amount+holders[msg.sender].balance) - maxPreOrderAmount);
            holders[msg.sender].balance = maxPreOrderAmount;
        }
        else{
            holders[msg.sender].balance += amount;
        }

        if(return_amount>0){
            if(msg.sender.send(return_amount)==false) throw;
        }

        if(this.balance == maxAmountSupply){
            isPreIco = false;
        }
    }
}
