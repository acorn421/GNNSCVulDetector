/*
 * ===== SmartInject Injection Details =====
 * Function      : bet
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 5 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 * 3. reentrancy-eth (SWC-107)
 * ... and 2 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding callback notifications to user-controlled contracts before state modifications. The vulnerability allows attackers to:
 * 
 * 1. **Initial Setup (Transaction 1)**: Attacker deploys a malicious contract and calls bet() with sufficient funds to trigger the callback
 * 2. **Reentrancy Exploitation (Transaction 2+)**: During the callback, the attacker can re-enter bet() multiple times while the original transaction's state changes are still incomplete
 * 3. **State Manipulation**: The attacker can manipulate vote counts, share prices, and accumulate shares at inconsistent prices across multiple betting rounds
 * 
 * **Multi-Transaction Exploitation Pattern**:
 * - **Transaction 1**: Attacker calls bet() with enough ETH to get close to a price increase threshold (e.g., 14 votes)
 * - **Transaction 2**: Attacker calls bet() again, triggering the callback before state updates
 * - **Reentrant Calls**: During callback, attacker can call bet() multiple times, exploiting the fact that:
 *   - Share prices haven't been updated yet from previous calls
 *   - Vote counts are inconsistent between transactions
 *   - Price increase thresholds can be manipulated
 * 
 * **Key Vulnerability Mechanisms**:
 * 1. **Callback Before State Updates**: The external call happens before the critical state modifications (shares, votes, pot, prices)
 * 2. **Price Manipulation**: Attacker can accumulate shares at old prices while manipulating vote counts
 * 3. **State Inconsistency**: Multiple transactions can exploit the gap between callback and state updates
 * 4. **Persistent State Exploitation**: Price changes and vote counts persist between transactions, enabling compound exploitation
 * 
 * The vulnerability is realistic as it appears to be a legitimate "notification system" but creates a window for multi-transaction reentrancy exploitation through accumulated state manipulation.
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // Notify betting callback before state changes
                if(msg.sender.call.value(0)(bytes4(keccak256("onBetPlaced(bool,uint256)")), bettingLeft, amountSent)){
                    // Callback successful
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                
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
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Notify betting callback before state changes
                if(msg.sender.call.value(0)(bytes4(keccak256("onBetPlaced(bool,uint256)")), bettingLeft, amountSent)){
                    // Callback successful
                }
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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