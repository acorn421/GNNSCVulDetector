/*
 * ===== SmartInject Injection Details =====
 * Function      : setGameEndTime
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a timestamp dependence vulnerability through a timed lottery system. The vulnerability is stateful and multi-transaction: (1) Admin sets game end time using setGameEndTime(), (2) Players place bets over multiple transactions, (3) The forceDrawIfExpired() function uses block.timestamp (now) to determine if the game should end, which miners can manipulate within reasonable bounds. This allows malicious miners to potentially trigger early game endings when it benefits them, especially if they have placed bets and want to force a draw before more competitors join.
 */
pragma solidity ^0.4.23;
/**
 * @title WinEtherPot11 ver 1.0 Prod
 * @dev The WinEtherPot contract is an ETH lottery contract
 * that allows unlimited entries at the cost of 0.1 ETH per entry.
 * Winners are rewarded the pot.
 */
contract WinEtherPot11 {
 
    address public owner;                    // Contract Creator
    uint private latestBlockNumber;         // Latest Block Number on BlockChain
    bytes32 private cumulativeHash;             
    address[] private bets;                 // address list of people applied for current game
    mapping(address => uint256) winners;    // Winners
    
    uint256 ownerShare = 5;
    uint256 winnerShare = 95;
    bool splitAllowed = true;
    
    uint256 public gameRunCounter = 0;
    
    uint256 incremental = 1;
    
    uint256 public minEntriesRequiredPerGame = 3;
    uint256 playerCount = 0;
    uint256 public potSize;
    
    bool autoDistributeWinning = true;   // when manual withdraw happens, distribute winnings also
    
    bool autoWithdrawWinner = true;   // autoWithdrawWinner and distribute winnings also
        
    bool isRunning = true;
    
    uint256 public minEntryInWei = (1/10) * 1e18; // 0.1 Ether
     
    uint256 public gameEndTime;
    bool public timedGameMode = false;
    
    // Bet placing events
    event betPlaced(address thePersonWhoBet, uint moneyInWei, uint blockNumber );
    event betStarted(address thePersonWhoBet, uint moneyInWei );
    event betAccepted(address thePersonWhoBet, uint moneyInWei, uint blockNumber );
    event betNotPlaced(address thePersonWhoBet, uint moneyInWei, uint blockNumber );
      
    // winner draw events
    event startWinnerDraw(uint256 randomInt, address winner, uint blockNumber , uint256 amountWonByThisWinner );    
    
    // amount won
    event amountWonByOwner(address ownerWithdrawer,  uint256 amount);
    event amountWonByWinner(address winnerWithdrawer,  uint256 amount);
    
    // withdraw events
    event startWithDraw(address withdrawer,  uint256 amount);
    event successWithDraw(address withdrawer,  uint256 amount);
    event rollbackWithDraw(address withdrawer,  uint256 amount);
    
    event showParticipants(address[] thePersons);
    event showBetNumber(uint256 betNumber, address better);
    
    event calledConstructor(uint block, address owner);
    
    event successDrawWinner(bool successFlag ); 
    event notReadyDrawWinner(bool errorFlag ); 
 
    /**
    *    @dev Constructor only called once
    **/ 
    constructor() public {
        owner = msg.sender;
        latestBlockNumber = block.number;
        cumulativeHash = bytes32(0);
        emit calledConstructor(latestBlockNumber, owner);
    }
 
    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
 
    /**
     * @dev Send 0.1 ETHER Per Bet.
     */
    function placeBet() public payable returns (bool) {
        
        if( isRunning == true ) {
        
            uint _wei = msg.value;
                   
            emit betStarted(msg.sender , msg.value);
            //require(_wei >= 0.1 ether);
            assert(_wei >= minEntryInWei);
            cumulativeHash = keccak256(abi.encodePacked(blockhash(latestBlockNumber), cumulativeHash));
            
            emit betPlaced(msg.sender , msg.value , block.number);
            
            latestBlockNumber = block.number;
            bets.push(msg.sender);
            
            emit betAccepted(msg.sender , msg.value , block.number);
            
            potSize = potSize + msg.value;
        }else {
            
            emit betNotPlaced(msg.sender , msg.value , block.number);
        }
        
        if( autoWithdrawWinner == true ) {
            
            if( bets.length >= minEntriesRequiredPerGame ) {
                bool successDrawWinnerFlag = drawAutoWinner();
                emit successDrawWinner(successDrawWinnerFlag);
                gameRunCounter = gameRunCounter + incremental;
            }else {
                emit notReadyDrawWinner(false);
            }
        }
        return true;
    }
 
    function drawAutoWinner() private returns (bool) {
        
        bool boolSuccessFlag = false;
        
        assert( bets.length >= minEntriesRequiredPerGame );
        
        latestBlockNumber = block.number;
        
        bytes32 _finalHash = keccak256(abi.encodePacked(blockhash(latestBlockNumber-1), cumulativeHash));
        
        uint256 _randomInt = uint256(_finalHash) % bets.length;
        
        address _winner = bets[_randomInt];
        
        uint256 amountWon = potSize ;
        
        uint256 ownerAmt = amountWon * ownerShare /100 ;
        
        uint256 winnerAmt = amountWon * winnerShare / 100 ;
        
        if( splitAllowed == true ) {
        
            emit startWinnerDraw(_randomInt, _winner, latestBlockNumber , winnerAmt );
            winners[_winner] = winnerAmt;
            owner.transfer(ownerAmt);
            emit amountWonByOwner(owner, ownerAmt);
            
            if( autoDistributeWinning == true ) {
               
                winners[_winner] = 0;
                
                if( _winner.send(winnerAmt)) {
                   emit successWithDraw(_winner, winnerAmt);
                   emit amountWonByWinner(_winner, winnerAmt);
                   
                }
                else {
                  winners[_winner] = winnerAmt;
                  emit rollbackWithDraw(_winner, winnerAmt);
                  
                }
            }
            
        } else {
        
            emit startWinnerDraw(_randomInt, _winner, latestBlockNumber , amountWon );
            winners[_winner] = amountWon;
            
            if( autoDistributeWinning == true ) {
               
                winners[_winner] = 0;
                
                if( _winner.send(amountWon)) {
                   emit successWithDraw(_winner, amountWon);
                   emit amountWonByWinner(_winner, amountWon);
                }
                else {
                  winners[_winner] = amountWon;
                  emit rollbackWithDraw(_winner, amountWon);
                }
            }
        }
                
        cumulativeHash = bytes32(0);
        delete bets;
        
        potSize = 0;
        
        boolSuccessFlag = true;
        
        return boolSuccessFlag;
    }
    
    
    function drawWinner() private onlyOwner returns (address) {
        
        assert( bets.length >= minEntriesRequiredPerGame );
        
        latestBlockNumber = block.number;
        
        bytes32 _finalHash = keccak256(abi.encodePacked(blockhash(latestBlockNumber-1), cumulativeHash));
        
        uint256 _randomInt = uint256(_finalHash) % bets.length;
        
        address _winner = bets[_randomInt];
        
        uint256 amountWon = potSize ;
        
        uint256 ownerAmt = amountWon * ownerShare /100 ;
        
        uint256 winnerAmt = amountWon * winnerShare / 100 ;
        
        if( splitAllowed == true ) {
            winners[_winner] = winnerAmt;
            owner.transfer(ownerAmt);
            emit amountWonByOwner(owner, ownerAmt);
            
            if( autoDistributeWinning == true ) {
               
                winners[_winner] = 0;
                
                if( _winner.send(winnerAmt)) {
                   emit successWithDraw(_winner, winnerAmt);
                   emit amountWonByWinner(_winner, winnerAmt);
                   
                }
                else {
                  winners[_winner] = winnerAmt;
                  emit rollbackWithDraw(_winner, winnerAmt);
                  
                }
            }
            
        } else {
            winners[_winner] = amountWon;
            
            if( autoDistributeWinning == true ) {
               
                winners[_winner] = 0;
                
                if( _winner.send(amountWon)) {
                   emit successWithDraw(_winner, amountWon);
                   emit amountWonByWinner(_winner, amountWon);
                }
                else {
                  winners[_winner] = amountWon;
                  emit rollbackWithDraw(_winner, amountWon);
                }
            }
        }
                
        cumulativeHash = bytes32(0);
        delete bets;
        
        potSize = 0;
        
        emit startWinnerDraw(_randomInt, _winner, latestBlockNumber , winners[_winner] );
        
        return _winner;
    }
    
 
    /**
     * @dev Withdraw your winnings yourself
     */
    function withdraw() private returns (bool) {
        uint256 amount = winners[msg.sender];
        
        emit startWithDraw(msg.sender, amount);
            
        winners[msg.sender] = 0;
        
        if (msg.sender.send(amount)) {
        
            emit successWithDraw(msg.sender, amount);
            return true;
        } else {
            winners[msg.sender] = amount;
            
            emit rollbackWithDraw(msg.sender, amount);
            
            return false;
        }
    }
 
    /**
     * @dev List of Participants
     */
    function _onlyAdmin_GetGameInformation() public onlyOwner returns (address[]) {
       emit showParticipants(bets);
       return bets;
    }
    
    /**
     * @dev Start / Stop the game
     */
    function _onlyAdmin_ToggleGame() public onlyOwner returns (bool) {
        
       if( isRunning == false ) {
            isRunning = true;
       }else {
            isRunning = false;
       }
       
       return isRunning;
    }
 
    /**
     * @dev Set min number of enteried - dupe entried allowed
     */
    function _onlyAdmin_SetMinEntriesRequiredPerGame(uint256 entries) public onlyOwner returns (bool) {
        
        minEntriesRequiredPerGame = entries;
        return true;
    }
    
    /**
     * @dev Set Min bet in wei
     */
    function _onlyAdmin_setMinBetAmountInWei(uint256 amount) public onlyOwner returns (bool) {
        
        minEntryInWei = amount ;
        return true;
    }
    
    /**
     * @dev Get address for Bet
     */
    function getBet(uint256 betNumber) private returns (address) {
        
        emit showBetNumber(betNumber,bets[betNumber]);
        return bets[betNumber];
    }
 
    /**
     * @dev Get no of Entries in Contract
     */
    function getNumberOfBets() public view returns (uint256) {
        return bets.length;
    }
    
    /**
     * @dev Get min Entries required to start the draw
     */
    function minEntriesRequiredPerGame() public view returns (uint256) {
        return minEntriesRequiredPerGame;
    }
    
    /**
     * @dev Destroy Contract
     */
    function _onlyAdmin_Destroy() onlyOwner public { 
        uint256 potAmount =  potSize;
        owner.transfer(potAmount);
        selfdestruct(owner);  
    }

    /**
     * @dev Set game end time for timed lottery mode
     */
    function setGameEndTime(uint256 _hoursFromNow) public onlyOwner returns (bool) {
        require(_hoursFromNow > 0 && _hoursFromNow <= 168); // Max 1 week
        gameEndTime = now + (_hoursFromNow * 1 hours);
        timedGameMode = true;
        return true;
    }
    
    /**
     * @dev Check if game has ended based on timestamp
     */
    function isGameExpired() public view returns (bool) {
        if (!timedGameMode) {
            return false;
        }
        return now >= gameEndTime;
    }
    
    /**
     * @dev Force draw if game time has expired (vulnerable to timestamp manipulation)
     */
    function forceDrawIfExpired() public returns (bool) {
        require(timedGameMode, "Timed game mode not enabled");
        require(bets.length > 0, "No bets placed");
        
        // VULNERABILITY: Using block.timestamp (now) for critical game logic
        // Miners can manipulate timestamp within reasonable bounds (~15 minutes)
        // This creates a multi-transaction vulnerability where:
        // 1. Game is set with end time
        // 2. Bets are placed over time
        // 3. Malicious miner can manipulate timestamp to trigger early draw
        if (now >= gameEndTime) {
            bool successDrawWinnerFlag = drawAutoWinner();
            gameRunCounter = gameRunCounter + incremental;
            timedGameMode = false; // Reset timed mode
            return successDrawWinnerFlag;
        }
        return false;
    }

}
