/*
 * ===== SmartInject Injection Details =====
 * Function      : retrieveExcessEther
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
 * Introduced a timestamp-dependent withdrawal delay mechanism that requires multiple transactions to exploit. The vulnerability allows miners to manipulate block.timestamp to bypass the 24-hour withdrawal delay for large amounts. 
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: User calls retrieveExcessEther() with >= 1 ether excess, which sets withdrawalRequestTime = block.timestamp and returns
 * 2. **Transaction 2**: User calls retrieveExcessEther() again after the delay period - but miners can manipulate block.timestamp to make it appear that 24 hours have passed
 * 
 * **Vulnerability Details:**
 * - The function relies on block.timestamp for time-based access control
 * - Miners can manipulate block.timestamp by up to ~15 minutes in either direction
 * - This allows bypassing the withdrawal delay by manipulating the timestamp in the second transaction
 * - The vulnerability requires persistent state (withdrawalRequestTime) and multiple function calls to exploit
 * 
 * **Why Multi-Transaction is Required:**
 * - The first transaction must set the withdrawal request timestamp
 * - The second transaction checks against this stored timestamp
 * - The vulnerability cannot be exploited in a single transaction because the delay check depends on the previously stored timestamp
 * - State accumulation across transactions is essential for the exploit to work
 * 
 * Note: This assumes the Player struct would need to include `uint withdrawalRequestTime;` field, which would be added to the contract state.
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
        uint withdrawalRequestTime; // <-- ADDED missing field
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Add withdrawal delay mechanism for large amounts
        if(players[msg.sender].excessEther >= 1 ether) {
            if(players[msg.sender].withdrawalRequestTime == 0) {
                // First call: initiate withdrawal request
                players[msg.sender].withdrawalRequestTime = block.timestamp;
                return;
            }
            
            // Second call: check if delay period has passed
            require(block.timestamp >= players[msg.sender].withdrawalRequestTime + 24 hours, "Withdrawal delay not met");
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if(msg.sender.send(players[msg.sender].excessEther)){
            players[msg.sender].excessEther = 0;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            players[msg.sender].withdrawalRequestTime = 0;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
    }
    
    function viewMyShares(bool left) public view returns(uint){
        if(left)return players[msg.sender].leftShares;
        return players[msg.sender].rightShares;
    }
}