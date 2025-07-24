/*
 * ===== SmartInject Injection Details =====
 * Function      : joinGame
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
 * Introduced a timestamp dependence vulnerability through early bird player positioning logic that uses block.timestamp for determining player array placement. The vulnerability is stateful and multi-transaction because:
 * 
 * 1. **Specific Changes Made:**
 *    - Added `uint joinTime = block.timestamp` to capture the block timestamp for each join
 *    - Implemented early bird logic for the first 3 players that uses timestamp-based positioning
 *    - Used `(joinTime % 7) + counter` to determine array placement, creating timestamp dependence
 *    - Modified t0 assignment to use the captured timestamp instead of `now` directly
 * 
 * 2. **Multi-Transaction Exploitation:**
 *    - **State Accumulation Required:** The vulnerability requires multiple players to join across different transactions to exploit the early bird positioning
 *    - **Sequential Dependency:** Each of the first 3 joinGame() calls uses timestamp-dependent logic that affects the players array state
 *    - **Miner Manipulation:** Miners can manipulate block timestamps across the sequence of join transactions to:
 *      * Control which array positions early players occupy
 *      * Influence the modulo calculation to place their own address in advantageous positions
 *      * Coordinate with accomplices to secure multiple favorable positions through timestamp manipulation
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - **Stateful Progression:** The vulnerability only affects the first 3 players (counter < 3), requiring at least 3 separate join transactions to fully exploit
 *    - **Cross-Transaction State Dependency:** Each join builds upon the previous state (counter value, existing players array), and the timestamp-dependent positioning can only be exploited as players join sequentially
 *    - **Accumulated Advantage:** The full impact requires multiple controlled joins to dominate the early positions, which affects the game's outcome through the endGame() function that uses these stored positions
 * 
 * The vulnerability is realistic because it appears to implement a legitimate "early bird" feature but introduces timestamp dependence that allows miners or coordinated attackers to manipulate player positioning across multiple transactions.
 */
pragma solidity ^0.4.18;


/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }


  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }


  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}




contract Draw is Ownable {

    address[9] private players;
    address public last_winner;
    uint public draw_number;
    uint public slots_left;
    uint private MAX_PLAYERS = players.length;
    uint private counter = 0;
    uint private t0 = now;
    uint private tdelta;
    uint private index;
    uint private owner_balance = 0 finney;

    function Draw() public {
        initGame();
        draw_number = 1;
        last_winner = address(0);
    }

    function initGame() internal {
        counter = 0;
        slots_left = MAX_PLAYERS;
        draw_number++;
        for (uint i = 0; i < players.length; i++) {
            players[i] = address(0);
        }
    }

    function () external payable {
        for (uint i = 0; i < players.length; i++) {
            require(players[i] != msg.sender);
        }
        joinGame();
    }

    function joinGame() public payable {
        require(msg.sender != owner);
        require(msg.value == 100 finney);
        require(counter < MAX_PLAYERS);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store join timestamp for each player to enable time-based ordering
        uint joinTime = block.timestamp;
        
        // Early bird advantage: First 3 players get priority based on exact timing
        if (counter < 3) {
            // Store timestamp in unused state variable for later use in endGame
            if (counter == 0) t0 = joinTime;
            // Use timestamp for player ordering - this creates timestamp dependence
            uint adjustedIndex = (joinTime % 7) + counter; // Use modulo for pseudo-randomness
            if (adjustedIndex < MAX_PLAYERS && players[adjustedIndex] == address(0)) {
                players[adjustedIndex] = msg.sender;
            } else {
                players[counter] = msg.sender;
            }
        } else {
            players[counter] = msg.sender;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        counter++;
        slots_left = MAX_PLAYERS - counter;

        if (counter >= MAX_PLAYERS) {
            last_winner = endGame();
        }
    }

    function endGame() internal returns (address winner) {
        require(this.balance - owner_balance >= 900 finney);
        tdelta = now - t0;
        index = uint(tdelta % MAX_PLAYERS);
        t0 = now;
        winner = players[index];
        initGame();
        winner.transfer(855 finney);
        owner_balance = owner_balance + 45 finney;
    }

    function getBalance() public view onlyOwner returns (uint) {
        return owner_balance;
    }

    function withdrawlBalance() public onlyOwner {
        msg.sender.transfer(owner_balance);
        owner_balance = 0;
    }

}