/*
 * ===== SmartInject Injection Details =====
 * Function      : extendBettingPeriod
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability that is stateful and requires multiple transactions to exploit. The vulnerability stems from using block.timestamp for timing validation instead of block.number. A malicious miner can manipulate the timestamp within a reasonable window (~900 seconds) to bypass the delay restrictions between extension requests. The exploit requires: 1) First transaction to set the lastExtensionRequest timestamp, 2) State persistence of this timestamp, and 3) Subsequent transactions where the miner manipulates block.timestamp to bypass the delay check. This creates a multi-transaction attack vector that depends on accumulated state changes.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    mapping(address => uint) public lastExtensionRequest;
    uint public extensionRequestCount = 0;
    uint public minExtensionDelay = 100; // minimum blocks between extensions

    function extendBettingPeriod(uint blocksToAdd) public {
        require(block.number < expiryBlock, "Betting period already expired");
        require(blocksToAdd > 0 && blocksToAdd <= 5000, "Invalid extension amount");
        require(players[msg.sender].hasBetBefore, "Must have bet before requesting extension");
        
        // Vulnerable timestamp dependence - using block.timestamp for timing validation
        // This creates a multi-transaction vulnerability where:
        // 1. First transaction: user calls this function when block.timestamp is favorable
        // 2. State persists the lastExtensionRequest timestamp
        // 3. Second+ transactions: user can manipulate timing to bypass delay restrictions
        
        if (lastExtensionRequest[msg.sender] != 0) {
            // Vulnerable: miners can manipulate block.timestamp within ~900 second window
            // This allows bypassing the intended delay between extension requests
            require(block.timestamp > lastExtensionRequest[msg.sender] + (minExtensionDelay * 15), "Must wait between extension requests");
        }
        
        // Update state that persists between transactions
        lastExtensionRequest[msg.sender] = block.timestamp;
        extensionRequestCount++;
        
        // Only allow extension if enough unique players have requested it
        if (extensionRequestCount >= (playerAddresses.length / 2)) {
            expiryBlock += blocksToAdd;
            extensionRequestCount = 0; // Reset for next round of extensions
        }
    }
    // === END FALLBACK INJECTION ===

    
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
        if(msg.sender.send(players[msg.sender].excessEther)){
            players[msg.sender].excessEther = 0;
        }
    }
    
    function viewMyShares(bool left) public view returns(uint){
        if(left)return players[msg.sender].leftShares;
        return players[msg.sender].rightShares;
    }
}
