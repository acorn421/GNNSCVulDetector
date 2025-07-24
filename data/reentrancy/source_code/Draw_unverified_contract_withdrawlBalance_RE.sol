/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawlBalance
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Check Before External Call**: Added a condition `if (owner_balance > 0)` that checks the state before making the external call, creating a window for reentrancy exploitation.
 * 
 * 2. **Temporary Variable Assignment**: Introduced `uint amount = owner_balance;` that captures the balance before the external call, but the actual state reset still occurs after the transfer.
 * 
 * 3. **Maintained Check-Effects-Interactions Violation**: The external call `msg.sender.transfer(amount)` still occurs before the state update `owner_balance = 0`, preserving the reentrancy vulnerability.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * This vulnerability requires multiple transactions to be fully exploitable:
 * 
 * **Transaction 1 (Setup)**: Owner accumulates balance through normal game operations (endGame() calls that increment owner_balance).
 * 
 * **Transaction 2 (Exploit Initiation)**: Malicious owner deploys a contract with a fallback function that calls withdrawlBalance() again, then calls withdrawlBalance() from this contract.
 * 
 * **Reentrancy Chain Within Transaction 2**:
 * - Initial call: withdrawlBalance() → owner_balance > 0 → transfer(amount) → triggers fallback
 * - Fallback call: withdrawlBalance() → owner_balance still > 0 (not reset yet) → transfer(amount) again
 * - This can continue until gas runs out or contract balance is drained
 * 
 * **Why Multi-Transaction Nature is Required:**
 * 
 * 1. **State Accumulation**: The owner_balance must be accumulated from previous transactions (through endGame() calls) before the exploit can be effective.
 * 
 * 2. **Contract Deployment**: The malicious owner needs to deploy a contract with a reentrancy-capable fallback function in a separate transaction.
 * 
 * 3. **Balance Dependency**: The vulnerability is only exploitable when owner_balance > 0, requiring prior transactions to build up this state.
 * 
 * 4. **Persistent State Exploitation**: Each reentrancy call reads the same persisted owner_balance state that was set in previous transactions, making the exploit dependent on accumulated state.
 * 
 * The vulnerability creates a realistic scenario where an owner can drain more than their legitimate balance by exploiting the reentrancy during the transfer operation, but only after the necessary state has been built up through multiple prior transactions.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (owner_balance > 0) {
            uint amount = owner_balance;
            msg.sender.transfer(amount);
            owner_balance = 0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

}