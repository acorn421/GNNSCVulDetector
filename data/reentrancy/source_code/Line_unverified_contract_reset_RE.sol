/*
 * ===== SmartInject Injection Details =====
 * Function      : reset
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Variables Added**: 
 *    - `resetAttempts` mapping tracks how many times each address has called reset
 *    - `maxResetAttempts` limits resets to 3 per cycle
 *    - `resetCooldown` enforces a 1-hour wait between resets
 *    - `lastResetTime` tracks when each address last called reset
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - A malicious owner contract can exploit this across multiple transactions
 *    - On the first reset call, the contract passes validation and transfers funds
 *    - During the transfer, if the owner is a contract, it can re-enter reset() before state updates
 *    - The re-entrant call sees unchanged state (resetAttempts still 0, lastResetTime still old)
 *    - This allows bypassing the cooldown and attempt limits across multiple transactions
 *    - The attacker can accumulate multiple withdrawals by re-entering before state updates
 * 
 * 3. **Why Multi-Transaction Required**:
 *    - The vulnerability requires building up state over multiple legitimate resets
 *    - Each transaction appears valid individually but the sequence creates the exploit
 *    - The attacker needs to establish a pattern of resets to maximize the reentrancy window
 *    - Multiple transactions are needed to fully drain the contract while appearing to respect limits
 * 
 * 4. **Realistic Integration**:
 *    - The reset limiting mechanism is a realistic security feature
 *    - The code maintains the original function's purpose while adding vulnerability
 *    - The external call placement before state updates is a common real-world mistake
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
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public resetAttempts;
    uint public maxResetAttempts = 3;
    uint public resetCooldown = 1 hours;
    mapping(address => uint) public lastResetTime;
    
    function reset() onlyOwner public {
        require(resetAttempts[msg.sender] < maxResetAttempts, "Reset limit exceeded");
        require(block.timestamp >= lastResetTime[msg.sender] + resetCooldown, "Cooldown period not met");
        
        uint transferAmount = this.balance;
        
        // External call before state updates - reentrancy vulnerability
        owner.transfer(transferAmount);
        
        // State updates after external call
        resetAttempts[msg.sender]++;
        lastResetTime[msg.sender] = block.timestamp;
        
        // If this is the final reset attempt, clear the attempts
        if (resetAttempts[msg.sender] >= maxResetAttempts) {
            resetAttempts[msg.sender] = 0;
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    uint nonce;

    function random() internal returns (uint) {
        uint rand = uint(keccak256(now, msg.sender, nonce)) % 778;
        nonce++;
        return rand;
    }
}