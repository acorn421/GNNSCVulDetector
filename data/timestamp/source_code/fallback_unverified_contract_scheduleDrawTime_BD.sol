/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleDrawTime
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
 * This vulnerability creates a multi-transaction timestamp dependence attack. The owner first calls scheduleDrawTime() to set a future timestamp, then any player can call checkScheduledDraw() once that time is reached. Malicious miners can manipulate block timestamps within a 15-second window to either prevent or trigger the scheduled draw at advantageous times. An attacker could: 1) Wait until they're in a favorable position (few competitors), 2) Manipulate timestamp to trigger early draw, or 3) Delay timestamp to prevent draws when unfavorable. The vulnerability requires multiple transactions (schedule + trigger) and maintains state between them (scheduled_draw_time, time_based_draw_enabled).
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables must be declared at contract scope, not inside constructor
    uint public scheduled_draw_time;
    bool public time_based_draw_enabled = false;
    // === END FALLBACK INJECTION ===

    function Draw() public {
        initGame();
        draw_number = 1;
        last_winner = address(0);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function scheduleDrawTime(uint _delay_hours) public onlyOwner {
        require(_delay_hours > 0 && _delay_hours <= 168); // Max 1 week
        scheduled_draw_time = now + (_delay_hours * 1 hours);
        time_based_draw_enabled = true;
    }

    function checkScheduledDraw() public {
        require(time_based_draw_enabled);
        require(now >= scheduled_draw_time);
        require(counter >= 3); // Minimum 3 players needed

        // Force end the current game regardless of player count
        last_winner = endGame();
        time_based_draw_enabled = false;
        scheduled_draw_time = 0;
    }
    // === END FALLBACK INJECTION ===

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