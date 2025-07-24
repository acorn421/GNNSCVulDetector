/*
 * ===== SmartInject Injection Details =====
 * Function      : placeBet
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
 * Introduced a multi-transaction timestamp dependence vulnerability through three key mechanisms:
 * 
 * 1. **Time-based Betting Windows**: Added timestamp-dependent multipliers that create "lucky" and "penalty" windows based on block.timestamp % 120, affecting pot contributions over time.
 * 
 * 2. **Timestamp State Persistence**: Modified latestBlockNumber to store block.timestamp instead of block.number, creating persistent timestamp-dependent state that affects future transactions.
 * 
 * 3. **Time-dependent Winner Drawing**: Added a 60-second waiting period from the last bet before winners can be drawn, using the stored timestamp.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1-N**: Attackers monitor timestamp cycles and place bets during "lucky windows" (timeWindow < 30) to get bonus contributions
 * 2. **State Accumulation**: Each bet stores block.timestamp in latestBlockNumber, creating timestamp-dependent state
 * 3. **Transaction N+1**: Miners or sophisticated attackers manipulate block timestamps to either extend/shorten the 60-second waiting period or influence the cumulative hash calculation
 * 4. **Winner Selection**: The stored timestamps affect both when winners can be drawn and the randomness seed used in drawAutoWinner()
 * 
 * **Why Multi-Transaction:**
 * - Requires multiple bets to accumulate enough entries for winner drawing
 * - Timestamp-dependent bonuses/penalties compound across multiple betting transactions  
 * - The 60-second delay means the vulnerability spans multiple blocks/transactions
 * - Miners must manipulate timestamps across several blocks to maximize exploitation
 * - State persistence of timestamps creates dependencies between transactions separated by time
 */
pragma solidity ^0.4.23;
/**
 * @title WinEtherPot11 ver 1.0 Prod
 * @dev The WinEtherPot contract is an ETH lottery contract
 * that allows unlimited entries at the cost of 0.1 ETH per entry.
 * Winners are rewarded the pot.
 */
contract WinEtherPot11 {
 
     
    address public owner; 					// Contract Creator
    uint private latestBlockNumber;         // Latest Block Number on BlockChain
    bytes32 private cumulativeHash;			
    address[] private bets;					// address list of people applied for current game
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
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			
			// Time-based betting window vulnerability
			uint256 timeWindow = block.timestamp % 120; // 2-minute cycles
			uint256 storedTimestamp = latestBlockNumber; // Reusing variable to store timestamp
			
			// Apply timestamp-dependent multiplier that accumulates over time
			if (timeWindow < 30) {
				// "Lucky window" - increases pot size by timestamp-dependent amount
				uint256 timeBonus = (block.timestamp % 15) * _wei / 100;
				_wei = _wei + timeBonus;
			} else if (timeWindow > 90) {
				// "Penalty window" - reduces effective bet
				uint256 timePenalty = ((block.timestamp % 20) + 5) * _wei / 100;
				_wei = _wei > timePenalty ? _wei - timePenalty : _wei / 2;
			}
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
				   
			emit betStarted(msg.sender , msg.value);
			//require(_wei >= 0.1 ether);
			assert(_wei >= minEntryInWei);
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			
			// Inject timestamp into cumulative hash for "better randomness"
			cumulativeHash = keccak256(abi.encodePacked(blockhash(latestBlockNumber), cumulativeHash, block.timestamp));
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
			
			emit betPlaced(msg.sender , msg.value , block.number);
			
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			// Store timestamp in latestBlockNumber for later use (state persistence)
			latestBlockNumber = block.timestamp; // Vulnerability: storing timestamp as "block number"
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
			bets.push(msg.sender);
			
			emit betAccepted(msg.sender , msg.value , block.number);
			
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			potSize = potSize + _wei; // Use modified wei amount
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
		}else {
			
			emit betNotPlaced(msg.sender , msg.value , block.number);
		}
		
		if( autoWithdrawWinner == true ) {
			
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			// Time-dependent winner drawing with stored timestamp
			if( bets.length >= minEntriesRequiredPerGame && 
			    (block.timestamp - latestBlockNumber) >= 60 ) { // Wait 1 minute from last bet
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
}