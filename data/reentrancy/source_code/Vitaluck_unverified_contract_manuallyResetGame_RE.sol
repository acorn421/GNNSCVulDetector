/*
 * ===== SmartInject Injection Details =====
 * Function      : manuallyResetGame
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Splitting the reset process into two phases**: The first transaction handles the transfer and partial state updates, while the second transaction completes the state cleanup.
 * 
 * 2. **Creating a vulnerable state window**: Between the first and second transactions, the contract exists in an inconsistent state where:
 *    - The jackpot transfer has occurred
 *    - currentWinningAddress has been reset to address(this)
 *    - But currentJackpot and other critical state variables haven't been updated yet
 * 
 * 3. **Multi-transaction exploitation path**:
 *    - Transaction 1: CEO calls manuallyResetGame() - triggers transfer to malicious winner contract
 *    - During transfer: Malicious contract's fallback function can call other contract functions or external contracts
 *    - The malicious contract can exploit the inconsistent state where the transfer happened but jackpot accounting hasn't been updated
 *    - Transaction 2: CEO calls manuallyResetGame() again to complete the reset
 *    - Between these transactions, the malicious contract can manipulate game state or extract additional value
 * 
 * 4. **State persistence requirement**: The vulnerability requires the state inconsistency to persist between transactions, making it impossible to exploit atomically. The malicious contract must coordinate across multiple transactions to fully exploit the vulnerability.
 * 
 * 5. **Realistic attack vector**: A malicious winner could coordinate with external contracts or use the state window to manipulate other game mechanics before the reset completes.
 */
pragma solidity ^0.4.18;

/*
 _    _      _                              _        
| |  | |    | |                            | |       
| |  | | ___| | ___ ___  _ __ ___   ___    | |_ ___  
| |/\| |/ _ | |/ __/ _ \| '_ ` _ \ / _ \   | __/ _ \ 
\  /\  |  __| | (_| (_) | | | | | |  __/   | || (_) |
 \/  \/ \___|_|\___\___/|_| |_| |_|\___|    \__\___/            


$$\    $$\ $$\   $$\               $$\                     $$\       
$$ |   $$ |\__|  $$ |              $$ |                    $$ |      
$$ |   $$ |$$\ $$$$$$\    $$$$$$\  $$ |$$\   $$\  $$$$$$$\ $$ |  $$\ 
\$$\  $$  |$$ |\_$$  _|   \____$$\ $$ |$$ |  $$ |$$  _____|$$ | $$  |
 \$$\$$  / $$ |  $$ |     $$$$$$$ |$$ |$$ |  $$ |$$ /      $$$$$$  / 
  \$$$  /  $$ |  $$ |$$\ $$  __$$ |$$ |$$ |  $$ |$$ |      $$  _$$<  
   \$  /   $$ |  \$$$$  |\$$$$$$$ |$$ |\$$$$$$  |\$$$$$$$\ $$ | \$$\ 
    \_/    \__|   \____/  \_______|\__| \______/  \_______|\__|  \__|
*/

contract Vitaluck {
    
    // Admin
    address ceoAddress = 0x46d9112533ef677059c430E515775e358888e38b;
    address cfoAddress = 0x23a49A9930f5b562c6B1096C3e6b5BEc133E8B2E;
    string MagicKey;
    uint256 minBetValue = 50000000000000000;
    uint256 currentJackpot;
    
    modifier onlyCeo() {
        require (msg.sender == ceoAddress);
        _;
    }
    
    //
    // Events
    //
    
    event NewPlay(address player, uint number, bool won);

    //
    // GAME
    //

    struct Bet {
        uint number;            // The number given to the user
        bool isWinner;          // Has this bet won the jackpot
        address player;         // We save the address of the player
        uint32 timestamp;       // We save the timestamp of this bet
        uint256 JackpotWon;     // The amount won if the user won the jackpot
    }
    Bet[] bets;

    mapping (address => uint) public ownerBetsCount;    // How many bets have this address made

    // Stats
    uint totalTickets;          // The total amount of bets
    uint256 amountWon;          // The total amount of ETH won by users
    uint256 amountPlayed;       // The total amount of ETH played by users

    // The countdown time will be used to reset the winning number after 48 hours if there aren't any new winning number
    uint cooldownTime = 1 days;

    // To track the current winner
    address currentWinningAddress;
    uint currentWinningNumber;
    uint currentResetTimer;

    // Random numbers that can be modified by the CEO to make the game completely random
    uint randomNumber = 178;
    uint randomNumber2;
    
    function() public payable { 
        Play();
    }
    
    /*
    This is the main function of the game. 
    It is called when a player sends ETH to the contract or play using Metamask.
    It calculates the amount of tickets bought by the player (according to the amount received by the contract) and generates a random number for each ticket.
    We keep the best number of all. -> 1 ticket = 0.01 ETH 
    */
    function Play() public payable {
        // We don't run the function if the player paid less than 0.01 ETH
        require(msg.value >= minBetValue);
        
        // If this is the first ticket ever
        if(totalTickets == 0) {
            // We save the current Jackpot value
            totalTickets++;
            currentJackpot = currentJackpot + msg.value;
            return;
        }

        uint _thisJackpot = currentJackpot;
        // here we count the number of tickets purchased by the user (each ticket costs 0.01ETH)
        uint _finalRandomNumber = 0;
        
        // We save the current Jackpot value
        currentJackpot = currentJackpot + msg.value;
        
        // We generate a random number for each ticket purchased by the player
        // Example: 1 ticket costs 0.01 ETH, if a user paid 1 ETH, we will run this function 100 times and save the biggest number of all as its result
        _finalRandomNumber = (uint(now) - 1 * randomNumber * randomNumber2 + uint(now))%1000 + 1;
        randomNumber = _finalRandomNumber;

        // We keep track of the amount played by the users
        amountPlayed = amountPlayed + msg.value;
        totalTickets++;
        ownerBetsCount[msg.sender]++;

        // We calculate and transfer to the owner a commission of 10%
        uint256 MsgValue10Percent = msg.value / 10;
        cfoAddress.transfer(MsgValue10Percent);
        
        
        // We save the current Jackpot value
        currentJackpot = currentJackpot - MsgValue10Percent;

        // Now that we have the biggest number of the player we check if this is better than the previous winning number
        if(_finalRandomNumber > currentWinningNumber) {
            
            // we update the cooldown time (when the cooldown time is expired, the owner will be able to reset the game)
            currentResetTimer = now + cooldownTime;

            // The player is a winner and wins the jackpot (he/she wins 90% of the balance, we keep some funds for the next game)
            uint256 JackpotWon = _thisJackpot;
            
            msg.sender.transfer(JackpotWon);
            
            // We save the current Jackpot value
            currentJackpot = currentJackpot - JackpotWon;
        
            // We keep track of the amount won by the users
            amountWon = amountWon + JackpotWon;
            currentWinningNumber = _finalRandomNumber;
            currentWinningAddress = msg.sender;

            // We save this bet in the blockchain
            bets.push(Bet(_finalRandomNumber, true, msg.sender, uint32(now), JackpotWon));
            NewPlay(msg.sender, _finalRandomNumber, true);
            
            // If the user's number is equal to 100 we reset the max number
            if(_finalRandomNumber >= 900) {
                // We reset the winning address and set the current winning number to 1 (the next player will have 99% of chances to win)
                currentWinningAddress = address(this);
                currentWinningNumber = 1;
            }
        } else {
            // The player is a loser, we transfer 10% of the bet to the current winner and save the rest in the jackpot
            currentWinningAddress.transfer(MsgValue10Percent);
        
            // We save the current Jackpot value
            currentJackpot = currentJackpot - MsgValue10Percent;
        
            // We save this bet in the blockchain
            bets.push(Bet(_finalRandomNumber, false, msg.sender, uint32(now), 0));
            NewPlay(msg.sender, _finalRandomNumber, false);
        }
    }
    
    function TestRandomNumber() public view returns (uint, uint, uint) {
        uint _randomNumber1;
        uint _randomNumber2;
        uint _randomNumber3;
        
        _randomNumber1 = (uint(now) - 1 * randomNumber * randomNumber2 + uint(now))%1000 + 1;
        _randomNumber2 = (uint(now) - 2 * _randomNumber1 * randomNumber2 + uint(now))%1000 + 1;
        _randomNumber3 = (uint(now) - 3 * _randomNumber2 * randomNumber2 + uint(now))%1000 + 1;
        
        return(_randomNumber1,_randomNumber2,_randomNumber3);
    }

    /*
    This function can be called by the contract owner (24 hours after the last game) if the game needs to be reset
    Example: the last number is 99 but the jackpot is too small for players to want to play.
    When the owner reset the game it:
        1. Transfers automatically the remaining jackpot (minus 10% that needs to be kept in the contract for the new jackpot) to the last winner 
        2. It resets the max number to 5 which will motivate new users to play again
    
    It can only be called by the owner 24h after the last winning game.
    */
    function manuallyResetGame() public onlyCeo {
        // We verifiy that 24h have passed since the beginning of the game
        require(currentResetTimer < now);

        // The current winning address wins the jackpot (he/she wins 90% of the balance, we keep 10% to fund the next turn)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        uint256 JackpotWon = currentJackpot - minBetValue;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Create a pending reset state to track multi-transaction reset process
        if (currentWinningAddress != address(this)) {
            // Transfer to winner first (external call before state updates)
            currentWinningAddress.transfer(JackpotWon);
            
            // Mark as pending reset - vulnerable state persists between transactions
            currentWinningAddress = address(this);
            
            // Set a flag that the reset process has started but not completed
            currentResetTimer = now + 1 hours; // Reset timer for next phase
            
            // DON'T update jackpot and other state yet - this creates the vulnerability window
            return;
        }
        
        // Second transaction: Complete the reset process
        // At this point, currentWinningAddress is already set to address(this)
        // But the jackpot and other state haven't been updated yet
        
        // We save the current Jackpot value (this should have been done before external call)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        currentJackpot = currentJackpot - JackpotWon;

        // We keep track of the amount won by the users
        amountWon = amountWon + JackpotWon;

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // We reset the winning number to 1 (the next player will have 99% of chances to win)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        currentWinningNumber = 1;
    }

    /*
    Those functions are useful to return some important data about the game.
    */
    function GetCurrentNumbers() public view returns(uint, uint256, uint) {
        uint _currentJackpot = currentJackpot;
        return(currentWinningNumber, _currentJackpot, bets.length);
    }
    function GetWinningAddress() public view returns(address) {
        return(currentWinningAddress);
    }
    
    function GetStats() public view returns(uint, uint256, uint256) {
        return(totalTickets, amountPlayed, amountWon);
    }

    // This will returns the data of a bet
    function GetBet(uint _betId) external view returns (
        uint number,            // The number given to the user
        bool isWinner,          // Has this bet won the jackpot
        address player,         // We save the address of the player
        uint32 timestamp,       // We save the timestamp of this bet
        uint256 JackpotWon     // The amount won if the user won the jackpot
    ) {
        Bet storage _bet = bets[_betId];

        number = _bet.number;
        isWinner = _bet.isWinner;
        player = _bet.player;
        timestamp = _bet.timestamp;
        JackpotWon = _bet.JackpotWon;
    }

    // This function will return only the bets id of a certain address
    function GetUserBets(address _owner) external view returns(uint[]) {
        uint[] memory result = new uint[](ownerBetsCount[_owner]);
        uint counter = 0;
        for (uint i = 0; i < bets.length; i++) {
          if (bets[i].player == _owner) {
            result[counter] = i;
            counter++;
          }
        }
        return result;
    }
    // This function will return only the bets id of a certain address
    function GetLastBetUser(address _owner) external view returns(uint[]) {
        uint[] memory result = new uint[](ownerBetsCount[_owner]);
        uint counter = 0;
        for (uint i = 0; i < bets.length; i++) {
          if (bets[i].player == _owner) {
            result[counter] = i;
            counter++;
          }
        }
        return result;
    }
    /*
    Those functions are useful to modify some values in the game
    */
    function modifyRandomNumber2(uint _newRdNum) public onlyCeo {
        randomNumber2 = _newRdNum;
    }
    function modifyCeo(address _newCeo) public onlyCeo {
        require(msg.sender == ceoAddress);
        ceoAddress = _newCeo;
    }
    function modifyCfo(address _newCfo) public onlyCeo {
        require(msg.sender == ceoAddress);
        cfoAddress = _newCfo;
    }
}