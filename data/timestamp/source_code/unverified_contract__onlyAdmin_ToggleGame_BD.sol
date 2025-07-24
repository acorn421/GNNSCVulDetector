/*
 * ===== SmartInject Injection Details =====
 * Function      : _onlyAdmin_ToggleGame
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
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Added Timestamp-Based Logic**: Introduced `currentHour = (block.timestamp / 3600) % 24` to calculate the current hour based on block timestamp
 * 2. **Implemented State Persistence**: Added `lastToggleTimestamp` state variable to track when the function was last called
 * 3. **Created Predictable Time Windows**: Game automatically becomes active during "business hours" (8 AM - 8 PM UTC) when cooldown period has passed
 * 4. **Added Cooldown Mechanism**: 1-hour cooldown period between automatic state changes using timestamp comparison
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Transaction 1 (Setup Phase):**
 * - Attacker calls `_onlyAdmin_ToggleGame()` to initialize `lastToggleTimestamp`
 * - This sets the baseline for future timestamp-dependent behavior
 * - No immediate exploitation possible in this transaction
 * 
 * **Transaction 2 (Timing Attack):**
 * - Attacker waits for the 1-hour cooldown to expire
 * - Calls the function again during the transition from "non-business hours" to "business hours" (around 8 AM UTC)
 * - Due to predictable timestamp logic, attacker knows exactly when the game will become active
 * 
 * **Transaction 3 (Exploitation):**
 * - Once the game is predictably active, attacker immediately calls `placeBet()` 
 * - Since they know the exact timing of state changes, they can front-run other players
 * - Miners can manipulate block timestamps (±15 seconds) to control the exact moment of state transition
 * 
 * **WHY MULTIPLE TRANSACTIONS ARE REQUIRED:**
 * 
 * 1. **State Accumulation**: The `lastToggleTimestamp` must be set in a previous transaction to enable the time-based logic
 * 2. **Timing Windows**: Attackers need to wait for specific time conditions (cooldown expiry + business hours) which cannot happen atomically
 * 3. **Predictability Exploitation**: The vulnerability requires observing the timestamp-dependent pattern over multiple blocks/transactions to predict future state changes
 * 4. **Miner Manipulation**: Block timestamp manipulation requires coordination across multiple blocks, making single-transaction exploitation impossible
 * 
 * **VULNERABILITY IMPACT:**
 * - **Predictable Game State**: Attackers can predict exactly when the lottery will be active/inactive
 * - **Front-Running Opportunities**: Known timing allows attackers to place bets immediately when favorable conditions are met
 * - **Unfair Advantage**: Regular users cannot predict the timestamp-dependent state changes, giving sophisticated attackers an edge
 * - **Miner Manipulation**: Miners can slightly adjust timestamps to control game state transitions for their benefit
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
    address[] private bets;				// address list of people applied for current game
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

    // ===== Added declaration for missing variable =====
    uint256 private lastToggleTimestamp;
    // ===============================================
	
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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Add timestamp-based auto-toggle mechanism with predictable timing
        uint256 currentHour = (block.timestamp / 3600) % 24;
        
        // Store the timestamp when toggle was last called for cooldown calculation
        if (lastToggleTimestamp == 0) {
            lastToggleTimestamp = block.timestamp;
        }
        
        // If it's been more than 1 hour since last toggle, allow automatic state change
        if (block.timestamp >= lastToggleTimestamp + 3600) {
            // Predictable time-based logic: game runs during "business hours" (8 AM - 8 PM UTC)
            if (currentHour >= 8 && currentHour < 20) {
                isRunning = true;
            } else {
                isRunning = false;
            }
            lastToggleTimestamp = block.timestamp;
        } else {
            // Manual toggle if within cooldown period
            if( isRunning == false ) {
                isRunning = true;
            }else {
                isRunning = false;
            }
            lastToggleTimestamp = block.timestamp;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	   
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