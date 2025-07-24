/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawPending
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This creates a classic reentrancy vulnerability that is stateful and requires multiple transactions. First, users must call requestWithdrawal() to accumulate pending withdrawals in their balance. Then, they call withdrawPending() which is vulnerable to reentrancy because it makes an external call before updating the state. An attacker can deploy a malicious contract that calls withdrawPending() multiple times in the fallback function, draining more funds than they're entitled to. The vulnerability requires: 1) Initial transaction to requestWithdrawal(), 2) Second transaction to withdrawPending() which can be exploited via reentrancy, and 3) The state (pendingWithdrawals mapping) persists between these transactions.
 */
pragma solidity ^0.4.21;

contract Line {
    
    address private owner;

    uint constant public jackpotNumerator = 50;
    uint constant public winNumerator = 5;
    uint constant public denominator = 100;
    
    uint public jackpot = 0;

    event Jackpot(uint line, address addr, uint date, uint prize, uint left);
    event Win(uint line, address addr, uint date, uint prize, uint left);
    event JackpotIncreased(uint date, uint jackpot);
    
    mapping(address => uint) public pendingWithdrawals; // <-- moved outside modifier

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    
    function requestWithdrawal(uint amount) public {
        require(amount > 0);
        require(amount <= this.balance / 10); // max 10% of contract balance
        pendingWithdrawals[msg.sender] += amount;
        emit JackpotIncreased(now, jackpot);
    }
    
    function withdrawPending() public {
        uint amount = pendingWithdrawals[msg.sender];
        require(amount > 0);
        require(amount <= this.balance);
        // Vulnerable to reentrancy: external call before state update
        if (msg.sender.call.value(amount)()) {
            pendingWithdrawals[msg.sender] = 0; // State update AFTER external call
        }
    }
    // === END FALLBACK INJECTION ===

    function Line() public {
        owner = msg.sender;
    }

    function waiver() private {
        delete owner;
    }

    function() payable public {
        jackpot += msg.value;
        uint token = random();
        uint prizeNumerator = 0;
        if (token == 777) {
            prizeNumerator = jackpotNumerator;
        }
        if (token == 666 || token == 555 || token == 444 
         || token == 333 || token == 222 || token == 111) {
            prizeNumerator = winNumerator;
        }
        if (prizeNumerator > 0) {
            msg.sender.transfer(0 wei); // supposed to reject contracts
            uint prize = this.balance / 100 * prizeNumerator;
            if (msg.sender.send(prize)) {
                if (prizeNumerator == jackpotNumerator) {
                    emit Jackpot(token, msg.sender, now, prize, this.balance);
                } else {
                    emit Win(token, msg.sender, now, prize, this.balance);
                }
                owner.transfer(this.balance / 100); // owners fee
            }
        } else {
            emit JackpotIncreased(now, jackpot);
        }
    }

    function reset() onlyOwner public {
        owner.transfer(this.balance);
    }

    uint nonce;

    function random() internal returns (uint) {
        uint rand = uint(keccak256(now, msg.sender, nonce)) % 778;
        nonce++;
        return rand;
    }
}
