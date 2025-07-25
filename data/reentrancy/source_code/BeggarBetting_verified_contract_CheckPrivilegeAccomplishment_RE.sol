/*
 * ===== SmartInject Injection Details =====
 * Function      : CheckPrivilegeAccomplishment
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to user-controlled contracts before state updates. The vulnerability requires users to accumulate winnings across multiple betting transactions to reach privilege thresholds (3, 8, 15, or 21 wins), and then exploit the external call to manipulate privilege counters during the achievement notification process.
 * 
 * **Specific Changes Made:**
 * 1. Added external calls using `msg.sender.call.value(0)()` before each state increment
 * 2. The external calls notify the user's contract about privilege achievements
 * 3. State updates (numOfPanhandler++, etc.) occur AFTER the external calls
 * 4. Used low-level call to allow user-controlled contract execution
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase** (Multiple transactions): Attacker places bets and wins games to accumulate exactly 3, 8, 15, or 21 wins through multiple betting transactions
 * 2. **State Accumulation**: Each win increments betterNumWinning[attacker] until reaching a privilege threshold
 * 3. **Exploitation Transaction**: When CheckPrivilegeAccomplishment is called with the threshold value, the attacker's contract receives the external call
 * 4. **Reentrancy Attack**: During the external call, the attacker re-enters CheckPrivilegeAccomplishment before the privilege counter is incremented
 * 5. **State Manipulation**: The attacker can increment privilege counters multiple times for the same achievement level
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires accumulating wins across multiple betting sessions to reach privilege thresholds
 * - Users must go through the complete betting process (placeBet → claimPrizes → afterClaim → CheckPrivilegeAccomplishment) multiple times
 * - The reentrancy can only be exploited when the user has legitimately earned the exact number of wins (3, 8, 15, or 21)
 * - The state from previous transactions (accumulated wins) is essential for triggering the vulnerable code path
 * - Single-transaction exploitation is impossible because the winning count must be built up over time through the betting system
 */
pragma solidity ^0.4.18;

contract BeggarBetting {

    struct MatchBettingInfo {    
        address better;
        uint256 matchId;
        uint homeTeamScore;
        uint awayTeamScore;     
        uint bettingPrice;  
    }

    struct BetterBettingInfo {    
        uint256 matchId;
        uint homeTeamScore;
        uint awayTeamScore;     
        uint bettingPrice;
        bool isWinner; 
        bool hasReceivedPrize;
        uint256 winningPrize;
        uint numOfWinners;   
        uint numOfBetters;   
    }

    address public owner;
    mapping(uint256 => MatchBettingInfo[]) public matchBettingInfo;  
    mapping(address => BetterBettingInfo[]) public betterBettingInfo;
    mapping(address => uint256) public betterBalance;
    mapping(address => uint) public betterNumWinning;
    uint numOfPanhandler;
    uint numOfVagabond;
    uint numOfTramp;
    uint numOfMiddleClass;

    /**
     * Constructor function
     *
     * Create the owner of the contract on first initialization
     */
    function BeggarBetting() {
        owner = msg.sender;
    }

    /**
     * Fallback function
     */
    function () payable {}

    /**
     * Store betting data submitted by the user
     *
     * Send `msg.value` to this contract
     *
     * @param _matchId The matchId to store
     * @param _homeTeamScore The home team score to store
     * @param _awayTeamScore The away team score to store
     * @param _bettingPrice The betting price to store
     */  
    function placeBet(uint256 _matchId, uint _homeTeamScore, uint _awayTeamScore, uint _bettingPrice) public payable returns (bool) {  
        require(_bettingPrice == msg.value); // Check ether send by sender is equal to bet amount
        bool result = checkDuplicateMatchId(msg.sender, _matchId, _bettingPrice);    
        // Revert if the sender has already placed this bet
        if (result) {
            revert();
        }                                                                                                  
        matchBettingInfo[_matchId].push(MatchBettingInfo(msg.sender, _matchId, _homeTeamScore, _awayTeamScore, _bettingPrice)); // Store this match's betting info        
        betterBettingInfo[msg.sender].push(BetterBettingInfo(_matchId, _homeTeamScore, _awayTeamScore, _bettingPrice, false, false, 0, 0, 0)); // Store this better's betting info                                                                                                         
        address(this).transfer(msg.value); // Send the user's betting price to this contract
        return true;
    }
 
    /**
     * Claim winning prize by the user
     *
     * Send `winningPrize` to 'msg.sender' from this contract
     *
     * @param _matchId The matchId to find winners
     * @param _homeTeamScore The home team score to find matching score
     * @param _awayTeamScore The away team score to find matching score
     * @param _bettingPrice The betting price to find matching price
     */  
    function claimPrizes(uint256 _matchId, uint _homeTeamScore, uint _awayTeamScore, uint _bettingPrice) public returns (bool) {
        uint totalNumBetters = matchBettingInfo[_matchId].length;  
        uint numOfBetters = 0;
        uint numOfWinners = 0;
        uint256 winningPrize = 0;
        uint commissionToOwner = 0;  
        bool result = checkPrizeAlreadyReceived(msg.sender, _matchId, _bettingPrice);        
        // Revert if the sender has already received the prize
        if (result) {
            revert();
        }          
        // Find matching scores among betters who betted for this match & price
        for (uint j = 0; j < totalNumBetters; j++) {  
            if (matchBettingInfo[_matchId][j].bettingPrice == _bettingPrice) {
                numOfBetters++;
                if (matchBettingInfo[_matchId][j].homeTeamScore == _homeTeamScore && matchBettingInfo[_matchId][j].awayTeamScore == _awayTeamScore) {          
                    numOfWinners++;
                }    
            }
        }   
        // msg.sender is the only winner, gets all the prize and gives a 7% commission to the owner
        if (numOfWinners == 1) {      
            commissionToOwner = _bettingPrice * numOfBetters * 7 / 100;  
            betterBalance[msg.sender] = (_bettingPrice * numOfBetters) - commissionToOwner;
            winningPrize = (_bettingPrice * numOfBetters) - commissionToOwner;
        // One more winner, divide it equally and gives a 7% commission to the owner
        } else if (numOfWinners > 1) {
            commissionToOwner = ((_bettingPrice * numOfBetters) / numOfWinners) * 7 / 100;  
            betterBalance[msg.sender] = ((_bettingPrice * numOfBetters) / numOfWinners) - commissionToOwner;
            winningPrize = ((_bettingPrice * numOfBetters) / numOfWinners) - commissionToOwner;   
        }
    
        sendCommissionToOwner(commissionToOwner);
        withdraw();
        afterClaim(_matchId, _bettingPrice, winningPrize, numOfWinners, numOfBetters);
    
        return true;
    }

    /**
     * Send 7% commission to the contract owner
     *
     * Send `_commission` to `owner` from the winner's prize
     *
     * @param _commission The commission to be sent to the contract owner
     */
    function sendCommissionToOwner(uint _commission) private {    
        require(address(this).balance >= _commission); 
        owner.transfer(_commission);
    }

    /**
     * Send winning prize to the winner
     *
     * Send `balance` to `msg.sender` from the contract
     */
    function withdraw() private {
        uint256 balance = betterBalance[msg.sender];    
        require(address(this).balance >= balance); 
        betterBalance[msg.sender] -= balance;
        msg.sender.transfer(balance);
    }

    /**
     * Modify winner's betting information after receiving the prize
     *
     * Change hasReceivedPrize to true to process info panel
     *
     * @param _matchId The matchId to find msg.sender's info to modify
     * @param _bettingPrice The betting price to find msg.sender's info to modify
     * @param _winningPrize The winning prize to assign value to msg.sender's final betting info
     * @param _numOfWinners The number of winners to assign value to msg.sender's final betting info
     * @param _numOfBetters The number of betters to assign value to msg.sender's final betting info
     */ 
    function afterClaim(uint256 _matchId, uint _bettingPrice, uint256 _winningPrize, uint _numOfWinners, uint _numOfBetters) private {
        uint numOfBettingInfo = betterBettingInfo[msg.sender].length;

        for (uint i = 0; i < numOfBettingInfo; i++) {
            if (betterBettingInfo[msg.sender][i].matchId == _matchId && betterBettingInfo[msg.sender][i].bettingPrice == _bettingPrice) {
                betterBettingInfo[msg.sender][i].hasReceivedPrize = true;
                betterBettingInfo[msg.sender][i].winningPrize = _winningPrize;
                betterBettingInfo[msg.sender][i].numOfWinners = _numOfWinners;
                betterBettingInfo[msg.sender][i].numOfBetters = _numOfBetters;
            }
        }    

        betterNumWinning[msg.sender] += 1;
        CheckPrivilegeAccomplishment(betterNumWinning[msg.sender]);        
    }

    /**
     * Find the msg.sender's number of winnings and increment the privilege if it matches
     *
     * Increment one of the privileges if numWinning matches
     */
    function CheckPrivilegeAccomplishment(uint numWinning) public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if user has reached a privilege milestone and notify external achievement system
        if (numWinning == 3) {
            // Notify external achievement tracking contract before updating state
            if (msg.sender.call.value(0)(bytes4(keccak256("onPrivilegeAchieved(uint256,uint256)")), 1, numOfPanhandler)) {
                // External call succeeded - continue with state update
            }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            numOfPanhandler++;
        }
        if (numWinning == 8) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify external achievement tracking contract before updating state
            if (msg.sender.call.value(0)(bytes4(keccak256("onPrivilegeAchieved(uint256,uint256)")), 2, numOfVagabond)) {
                // External call succeeded - continue with state update
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            numOfVagabond++;
        }
        if (numWinning == 15) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify external achievement tracking contract before updating state
            if (msg.sender.call.value(0)(bytes4(keccak256("onPrivilegeAchieved(uint256,uint256)")), 3, numOfTramp)) {
                // External call succeeded - continue with state update
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            numOfTramp++;
        }
        if (numWinning == 21) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify external achievement tracking contract before updating state
            if (msg.sender.call.value(0)(bytes4(keccak256("onPrivilegeAchieved(uint256,uint256)")), 4, numOfMiddleClass)) {
                // External call succeeded - continue with state update
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            numOfMiddleClass++;
        }
    }

    /**
     * Prevent the user from submitting the same bet again
     *
     * Send `_commission` to `owner` from the winner's prize
     *
     * @param _better The address of the sender
     * @param _matchId The matchId to find the msg.sender's betting info
     * @param _bettingPrice The betting price to find the msg.sender's betting info
     */
    function checkDuplicateMatchId(address _better, uint256 _matchId, uint _bettingPrice) public view returns (bool) {
        uint numOfBetterBettingInfo = betterBettingInfo[_better].length;
      
        for (uint i = 0; i < numOfBetterBettingInfo; i++) {
            if (betterBettingInfo[_better][i].matchId == _matchId && betterBettingInfo[_better][i].bettingPrice == _bettingPrice) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add extra security to prevent the user from trying to receive the winning prize again
     *
     * @param _better The address of the sender
     * @param _matchId The matchId to find the msg.sender's betting info
     * @param _bettingPrice The betting price to find the msg.sender's betting info
     */
    function checkPrizeAlreadyReceived(address _better, uint256 _matchId, uint _bettingPrice) public view returns (bool) {
        uint numOfBetterBettingInfo = betterBettingInfo[_better].length;
        // Find if the sender address has already received the prize
        for (uint i = 0; i < numOfBetterBettingInfo; i++) {
            if (betterBettingInfo[_better][i].matchId == _matchId && betterBettingInfo[_better][i].bettingPrice == _bettingPrice) {
                if (betterBettingInfo[_better][i].hasReceivedPrize) {
                    return true;
                }
            }
        }

        return false;
    }    

    /**
     * Constant function to return the user's previous records
     *
     * @param _better The better's address to search betting info
     */
    function getBetterBettingInfo(address _better) public view returns (uint256[], uint[], uint[], uint[]) {
        uint length = betterBettingInfo[_better].length;
        uint256[] memory matchId = new uint256[](length);
        uint[] memory homeTeamScore = new uint[](length);
        uint[] memory awayTeamScore = new uint[](length);
        uint[] memory bettingPrice = new uint[](length);   

        for (uint i = 0; i < length; i++) {
            matchId[i] = betterBettingInfo[_better][i].matchId;
            homeTeamScore[i] = betterBettingInfo[_better][i].homeTeamScore;
            awayTeamScore[i] = betterBettingInfo[_better][i].awayTeamScore;
            bettingPrice[i] = betterBettingInfo[_better][i].bettingPrice;   
        }

        return (matchId, homeTeamScore, awayTeamScore, bettingPrice);
    }

    /**
     * Constant function to return the user's previous records
     *
     * @param _better The better's address to search betting info
     */
    function getBetterBettingInfo2(address _better) public view returns (bool[], bool[], uint256[], uint[], uint[]) {
        uint length = betterBettingInfo[_better].length;  
        bool[] memory isWinner = new bool[](length);
        bool[] memory hasReceivedPrize = new bool[](length);
        uint256[] memory winningPrize = new uint256[](length);
        uint[] memory numOfWinners = new uint[](length);
        uint[] memory numOfBetters = new uint[](length);

        for (uint i = 0; i < length; i++) {     
            isWinner[i] = betterBettingInfo[_better][i].isWinner;
            hasReceivedPrize[i] = betterBettingInfo[_better][i].hasReceivedPrize;
            winningPrize[i] = betterBettingInfo[_better][i].winningPrize;
            numOfWinners[i] = betterBettingInfo[_better][i].numOfWinners;
            numOfBetters[i] = betterBettingInfo[_better][i].numOfBetters;
        }

        return (isWinner, hasReceivedPrize, winningPrize, numOfWinners, numOfBetters);
    }

    /**
     * Load the number of participants for the same match and betting price
     *
     * @param _matchId The matchId to find number of participants
     * @param _bettingPrice The betting price to find number of participants
     */
    function getNumOfBettersForMatchAndPrice(uint _matchId, uint _bettingPrice) public view returns(uint) {
        uint numOfBetters = matchBettingInfo[_matchId].length;    
        uint count = 0;

        for (uint i = 0; i < numOfBetters; i++) {   
            if (matchBettingInfo[_matchId][i].bettingPrice == _bettingPrice) {
                count++;
            }
        }
    
        return count;    
    }

    /**
     * Get the number of winnings of the user
     *
     * @param _better The address of the user
     */
    function getBetterNumOfWinnings(address _better) public view returns(uint) {
        return betterNumWinning[_better];    
    }

    /**
     * Return the current number of accounts who have reached each privileges
     */
    function getInfoPanel() public view returns(uint, uint, uint, uint) {      
        return (numOfPanhandler, numOfVagabond, numOfTramp, numOfMiddleClass);    
    }
}