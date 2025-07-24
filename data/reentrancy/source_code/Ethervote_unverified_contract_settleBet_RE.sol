/*
 * ===== SmartInject Injection Details =====
 * Function      : settleBet
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
 * Introduced a multi-transaction reentrancy vulnerability by modifying the state update logic. The vulnerability works by:
 * 
 * 1. **State Modification Timing**: Changed the logic to only clear player shares (leftShares/rightShares) AFTER successful external calls, creating a window where shares remain non-zero during reentrancy.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls settleBet() and reenters during their send() call. Since betIsSettled is still false and their shares haven't been cleared yet, they can trigger additional settlement logic or manipulate contract state.
 *    - **Transaction 2**: Attacker can call settleBet() again if they prevented betIsSettled from being set to true in the first transaction, or exploit the remaining non-zero shares.
 *    - **Transaction 3**: Normal settlement completion with corrupted state.
 * 
 * 3. **Why Multi-Transaction**: 
 *    - The vulnerability requires the attacker to first establish a position by betting (previous transaction)
 *    - Then exploit the timing window during settlement (first settleBet call)
 *    - Finally extract additional value through the corrupted state (subsequent calls)
 * 
 * 4. **Realistic Attack Vector**: An attacker can deploy a malicious contract that:
 *    - Receives the send() call during settlement
 *    - Reenters settleBet() while shares are still non-zero
 *    - Manipulates the settlement process to extract more funds than entitled
 *    - Requires multiple transactions to set up the attack state and exploit it
 * 
 * The vulnerability maintains the original function's intended behavior while introducing a subtle timing issue that can be exploited across multiple transactions through careful state manipulation.
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
                    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                    // Store the reward amount before the external call
                    uint rewardAmount = players[playerAddresses[i]].leftShares * winReward;
                    // Make external call BEFORE updating state
                    if(playerAddresses[i].send(rewardAmount) == false){
                        //if the send fails
                        players[playerAddresses[i]].excessEther = rewardAmount;
                    } else {
                        // Only clear shares after successful send - this creates the vulnerability window
                        players[playerAddresses[i]].leftShares = 0;
                    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                    }
                }
            }
        }else if(rightVotes > leftVotes){
            winReward = winReward / rightVotes;
            for(uint u=0;u<playerAddresses.length;u++){
                if(players[playerAddresses[u]].rightShares > 0){
                    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                    // Store the reward amount before the external call
                    uint rewardAmountU = players[playerAddresses[u]].rightShares * winReward;
                    // Make external call BEFORE updating state
                    if(playerAddresses[u].send(rewardAmountU) == false){
                        //if the send fails
                        players[playerAddresses[u]].excessEther = rewardAmountU;
                    } else {
                        // Only clear shares after successful send - this creates the vulnerability window
                        players[playerAddresses[u]].rightShares = 0;
                    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                    }
                }
            }
        }else if(rightVotes == leftVotes){//split it in a tie
            uint rightWinReward = (winReward / rightVotes) / 2;
            for(uint q=0;q<playerAddresses.length;q++){
                if(players[playerAddresses[q]].rightShares > 0){
                    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                    // Store the reward amount before the external call
                    uint rewardAmountQ = players[playerAddresses[q]].rightShares * rightWinReward;
                    // Make external call BEFORE updating state
                    if(playerAddresses[q].send(rewardAmountQ) == false){
                        //if the send fails
                        players[playerAddresses[q]].excessEther = rewardAmountQ;
                    } else {
                        // Only clear shares after successful send - this creates the vulnerability window
                        players[playerAddresses[q]].rightShares = 0;
                    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                    }
                }
            }

            uint leftWinReward = winReward / leftVotes;
            for(uint l=0;l<playerAddresses.length;l++){
                if(players[playerAddresses[l]].leftShares > 0){
                    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                    // Store the reward amount before the external call
                    uint rewardAmountL = players[playerAddresses[l]].leftShares * leftWinReward;
                    // Make external call BEFORE updating state
                    if(playerAddresses[l].send(rewardAmountL) == false){
                        //if the send fails
                        players[playerAddresses[l]].excessEther = rewardAmountL;
                    } else {
                        // Only clear shares after successful send - this creates the vulnerability window
                        players[playerAddresses[l]].leftShares = 0;
                    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                    }
                }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            }
        }

        betIsSettled = true;
    }
    
    
    function retrieveExcessEther() public {
        assert(players[msg.sender].excessEther > 0);
        if(msg.sender.send(players[msg.sender].excessEther)){
            players[msg.sender].excessEther = 0;
        }
    }
    
    function viewMyShares(bool left) public view returns(uint){
        if(left)return players[msg.sender].leftShares;
        return players[msg.sender].rightShares;
    }
}