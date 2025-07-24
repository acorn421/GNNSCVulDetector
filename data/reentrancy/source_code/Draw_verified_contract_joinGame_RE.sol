/*
 * ===== SmartInject Injection Details =====
 * Function      : joinGame
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the previous player before state updates. This creates a callback mechanism that allows manipulation of the game state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the previous player using `call.value(0)()` with a callback function signature
 * 2. The call is made BEFORE critical state updates (players array assignment and counter increment)
 * 3. The callback provides both the new player address and current counter value
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract and joins the game normally
 * 2. **Transaction 2**: Victim joins the game, triggering the external call to the attacker's contract
 * 3. **During Callback**: The attacker's contract receives the callback and re-enters joinGame()
 * 4. **State Manipulation**: Since state isn't updated until after the callback, the attacker can:
 *    - Join multiple times with the same counter value
 *    - Manipulate the players array to occupy multiple slots
 *    - Influence winner selection by controlling multiple player positions
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * - The vulnerability requires at least two players to trigger (attacker must join first, then victim)
 * - State from the first transaction (attacker's position in players array) is used in the second transaction
 * - The reentrancy exploits the persistent state accumulated across multiple joinGame() calls
 * - Cannot be exploited in a single transaction as it requires interaction between different players
 * 
 * **Realistic Nature:**
 * - The callback mechanism appears to be a legitimate "notification" feature
 * - External calls to players are common in gaming contracts for event notifications
 * - The vulnerability is subtle and would likely pass basic security reviews
 * - Maintains all original functionality while introducing the security flaw
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
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify previous player before updating state
        if (counter > 0) {
            address prevPlayer = players[counter - 1];
            prevPlayer.call.value(0)(bytes4(keccak256("onPlayerJoin(address,uint256)")), msg.sender, counter);
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        players[counter] = msg.sender;
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