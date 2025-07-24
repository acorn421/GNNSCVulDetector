/*
 * ===== SmartInject Injection Details =====
 * Function      : retrieveExcessEther
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Stateful Tracking**: Added `withdrawalAttempts` and `lastWithdrawalBlock` mappings that persist between transactions, creating exploitable state accumulation.
 * 
 * 2. **Progressive Withdrawal Limits**: Implemented a withdrawal limit system where users can only withdraw `maxWithdrawalPerTransaction` (1 ether) for their first 3 attempts, then unlimited after that.
 * 
 * 3. **Reentrancy Vulnerability**: Changed from `send()` to `call.value()("")` and moved state updates after the external call, creating a classic reentrancy vulnerability.
 * 
 * 4. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1-3**: Build up withdrawal attempts to reach the "unlimited" threshold
 *    - **Transaction 4+**: Exploit reentrancy with accumulated state to bypass intended restrictions
 *    - Each transaction increases `withdrawalAttempts[msg.sender]`, creating persistent state that enables future exploitation
 * 
 * 5. **Cross-Transaction State Manipulation**: An attacker can:
 *    - Use the first few transactions to accumulate withdrawal attempts
 *    - On the 4th+ transaction, trigger reentrancy to drain funds while the state shows "unlimited" withdrawal capability
 *    - The persistent `withdrawalAttempts` counter enables this cross-transaction exploitation
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability leverages accumulated state (`withdrawalAttempts`) that builds up over multiple calls
 * - The withdrawal limit bypass only becomes effective after 3+ transactions
 * - Single-transaction exploitation is prevented by the initial withdrawal limits
 * - The attacker must strategically build state across multiple transactions to create the exploitation window
 * 
 * This creates a realistic scenario where an attacker must carefully orchestrate multiple transactions to build up the necessary state before the final reentrancy exploitation becomes possible.
 */
pragma solidity ^0.4.23;

contract Ethervote {
    
    address feeRecieverOne = 0xa03F27587883135DA9565e7EfB523e1657A47a07;
    address feeRecieverTwo = 0x549377418b1b7030381de9aA1319E41C044467c7;

    address[] playerAddresses;
    
    uint public expiryBlock;
    
    uint public leftSharePrice = 10 finney;
    uint public rightSharePrice = 10 finney;
    
    uint public leftSharePriceRateOfIncrease = 1 finney;
    uint public rightSharePriceRateOfIncrease = 1 finney;
    
    uint public leftVotes = 0;
    uint public rightVotes = 0;
    
    uint public thePot = 0 wei;
    
    bool public betIsSettled = false;

    // === ADDED DECLARATIONS FOR COMPILATION ===
    mapping(address => uint) public withdrawalAttempts;
    mapping(address => uint) public lastWithdrawalBlock;
    uint public maxWithdrawalPerTransaction = 1 ether;
    // ==========================================

    struct Player {
        uint leftShares;
        uint rightShares;
        uint excessEther;
        bool hasBetBefore;
    }
    
    mapping(address => Player) players;
    
    
    constructor() public {
        expiryBlock = block.number + 17500;
    }
    
    function bet(bool bettingLeft) public payable {
        
        require(block.number < expiryBlock);
        
        if(!players[msg.sender].hasBetBefore){
            playerAddresses.push(msg.sender);
            players[msg.sender].hasBetBefore = true;
        }
            
            uint amountSent = msg.value;
            
            if(bettingLeft){
                require(amountSent >= leftSharePrice);
                
                while(amountSent >= leftSharePrice){
                    players[msg.sender].leftShares++;
                    leftVotes++;
                    thePot += leftSharePrice;
                    amountSent -= leftSharePrice;
                    
                    if((leftVotes % 15) == 0){//if the number of left votes is a multiple of 15
                        leftSharePrice += leftSharePriceRateOfIncrease;
                        if(leftVotes <= 45){//increase the rate at first, then decrease it to zero.
                            leftSharePriceRateOfIncrease += 1 finney;
                        }else if(leftVotes > 45){
                            if(leftSharePriceRateOfIncrease > 1 finney){
                                leftSharePriceRateOfIncrease -= 1 finney;
                            }else if(leftSharePriceRateOfIncrease <= 1 finney){
                                leftSharePriceRateOfIncrease = 0 finney;
                            }
                        }
                    }
                    
                }
                if(amountSent > 0){
                    players[msg.sender].excessEther += amountSent;
                }
                
            }
            else{//betting for the right option
                require(amountSent >= rightSharePrice);
                
                while(amountSent >= rightSharePrice){
                    players[msg.sender].rightShares++;
                    rightVotes++;
                    thePot += rightSharePrice;
                    amountSent -= rightSharePrice;
                    
                    if((rightVotes % 15) == 0){//if the number of right votes is a multiple of 15
                        rightSharePrice += rightSharePriceRateOfIncrease;
                        if(rightVotes <= 45){//increase the rate at first, then decrease it to zero.
                            rightSharePriceRateOfIncrease += 1 finney;
                        }else if(rightVotes > 45){
                            if(rightSharePriceRateOfIncrease > 1 finney){
                                rightSharePriceRateOfIncrease -= 1 finney;
                            }else if(rightSharePriceRateOfIncrease <= 1 finney){
                                rightSharePriceRateOfIncrease = 0 finney;
                            }
                        }
                    }
                    
                }
                if(amountSent > 0){
                    if(msg.sender.send(amountSent) == false)players[msg.sender].excessEther += amountSent;
                }
            }
    }
    
    
    function settleBet() public {
        require(block.number >= expiryBlock);
        require(betIsSettled == false);

        uint winRewardOne = thePot * 2;
        winRewardOne = winRewardOne / 20;
        if(feeRecieverOne.send(winRewardOne) == false) players[feeRecieverOne].excessEther = winRewardOne;//in case the tx fails, the excess ether function lets you withdraw it manually

        uint winRewardTwo = thePot * 1;
        winRewardTwo = winRewardTwo / 20;
        if(feeRecieverTwo.send(winRewardTwo) == false) players[feeRecieverTwo].excessEther = winRewardTwo;

        uint winReward = thePot * 17;
        winReward = winReward / 20;
        
        if(leftVotes > rightVotes){
            winReward = winReward / leftVotes;
            for(uint i=0;i<playerAddresses.length;i++){
                if(players[playerAddresses[i]].leftShares > 0){
                    if(playerAddresses[i].send(players[playerAddresses[i]].leftShares * winReward) == false){
                        //if the send fails
                        players[playerAddresses[i]].excessEther = players[playerAddresses[i]].leftShares * winReward;
                    }
                }
            }
        }else if(rightVotes > leftVotes){
            winReward = winReward / rightVotes;
            for(uint u=0;u<playerAddresses.length;u++){
                if(players[playerAddresses[u]].rightShares > 0){
                    if(playerAddresses[u].send(players[playerAddresses[u]].rightShares * winReward) == false){
                        //if the send fails
                        players[playerAddresses[u]].excessEther = players[playerAddresses[u]].rightShares * winReward;
                    }
                }
            }
        }else if(rightVotes == leftVotes){//split it in a tie
            uint rightWinReward = (winReward / rightVotes) / 2;
            for(uint q=0;q<playerAddresses.length;q++){
                if(players[playerAddresses[q]].rightShares > 0){
                    if(playerAddresses[q].send(players[playerAddresses[q]].rightShares * rightWinReward) == false){
                        //if the send fails
                        players[playerAddresses[q]].excessEther = players[playerAddresses[q]].rightShares * rightWinReward;
                    }
                }
            }

            uint leftWinReward = winReward / leftVotes;
            for(uint l=0;l<playerAddresses.length;l++){
                if(players[playerAddresses[l]].leftShares > 0){
                    if(playerAddresses[l].send(players[playerAddresses[l]].leftShares * leftWinReward) == false){
                        //if the send fails
                        players[playerAddresses[l]].excessEther = players[playerAddresses[l]].leftShares * leftWinReward;
                    }
                }
            }

        }

        betIsSettled = true;
    }
    
    
    function retrieveExcessEther() public {
        assert(players[msg.sender].excessEther > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add withdrawal tracking state (these would be added to contract state)
        // mapping(address => uint) public withdrawalAttempts;
        // mapping(address => uint) public lastWithdrawalBlock;
        // uint public maxWithdrawalPerTransaction = 1 ether;
        
        // Track withdrawal attempts across transactions
        withdrawalAttempts[msg.sender]++;
        
        // Calculate withdrawal amount based on accumulated attempts
        uint withdrawalAmount = players[msg.sender].excessEther;
        
        // Progressive withdrawal limits that can be bypassed through reentrancy
        if (withdrawalAttempts[msg.sender] <= 3) {
            withdrawalAmount = withdrawalAmount > maxWithdrawalPerTransaction ? maxWithdrawalPerTransaction : withdrawalAmount;
        }
        
        // External call before state update - classic reentrancy vulnerability
        if(msg.sender.call.value(withdrawalAmount)("")){
            // State update after external call - vulnerable to reentrancy
            players[msg.sender].excessEther -= withdrawalAmount;
            lastWithdrawalBlock[msg.sender] = block.number;
            
            // Reset withdrawal attempts only after successful full withdrawal
            if (players[msg.sender].excessEther == 0) {
                withdrawalAttempts[msg.sender] = 0;
            }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    
    function viewMyShares(bool left) public view returns(uint){
        if(left)return players[msg.sender].leftShares;
        return players[msg.sender].rightShares;
    }
}
