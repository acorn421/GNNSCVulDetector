/*
 * ===== SmartInject Injection Details =====
 * Function      : playBps
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 14 findings
 * Total Found   : 22 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 11 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Caching**: Introduced `originalLastMove` and `originalLastPlayer` variables that store the initial state, creating inconsistency between cached and live state during reentrancy.
 * 
 * 2. **Maintained External Calls Before State Updates**: Kept all external token transfers before `setGame()` calls, violating the Checks-Effects-Interactions pattern and creating reentrancy windows.
 * 
 * 3. **Mixed State Usage**: Used both live state (`lastMove`, `lastPlayer`) and cached state (`originalLastMove`, `originalLastPlayer`) in different branches, creating exploitable inconsistencies.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Player A makes a move (e.g., choice=1), setting `lastMove=1` and `lastPlayer=PlayerA`.
 * 
 * **Transaction 2 (Exploit)**: Attacker deploys malicious ERC20 token contracts and calls `playBps(choice=2)`:
 * - Function reads `lastMove=1` (paper beats rock)
 * - Function calls `pCoin.transfer(attacker, oneCoin)` - this triggers reentrancy in malicious token
 * - **During reentrancy**: Attacker calls `playBps(choice=3)` again
 *   - Reads `lastMove=1` (scissors loses to rock)
 *   - But uses `originalLastMove=1` in some branches
 *   - Can manipulate which tokens are transferred by exploiting state inconsistency
 * - **After reentrancy**: Original call continues with potentially modified state
 * 
 * **Transaction 3 (Benefit)**: Attacker can repeat the exploit or cash out manipulated tokens.
 * 
 * **Why Multi-Transaction Required:**
 * - **State Dependency**: Requires prior game state (previous player's move) to be established
 * - **Reentrancy Window**: Needs external call to malicious contract to trigger reentrancy
 * - **State Accumulation**: Each successful exploit modifies game state, enabling further exploitation
 * - **Cross-Transaction State**: The vulnerability exploits the persistent state between different players' moves
 * 
 * The vulnerability is realistic because it appears to be a minor optimization (caching state) but creates a critical security flaw that can only be exploited through carefully orchestrated multi-transaction attacks.
 */
pragma solidity ^0.4.3;

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
  constructor() public {
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
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

// ----------------------------------------------------------------------------
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20-token-standard.md
// ----------------------------------------------------------------------------
contract ERC20Interface {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}

contract BlockPaperScissors is Ownable {

  using SafeMath for uint256;

    ERC20Interface bCoin;
    ERC20Interface pCoin;
    ERC20Interface sCoin;
    ERC20Interface tCoin;

    address public rpsDev = msg.sender;
    uint8 public lastMove = 1; // last played move; 1=rock, 2=paper, 3=scissor
    address public lastPlayer = msg.sender;
    uint public oneCoin = 1000000000000000000;

//FUNCTIONS setting and retrieving global variables that impact gameplay

    function setBCoinContractAddress(address _address) external onlyOwner {
      bCoin = ERC20Interface(_address);
    }
    function setPCoinContractAddress(address _address) external onlyOwner {
      pCoin = ERC20Interface(_address);
    }
    function setSCoinContractAddress(address _address) external onlyOwner {
      sCoin = ERC20Interface(_address);
    }
    function setTCoinContractAddress(address _address) external onlyOwner {
      tCoin = ERC20Interface(_address);
    }

//EVENTS

    event newMove(uint8 move);
    event newWinner(address winner);

// FUNCTIONS interacting with the swine structs in contract

    function playBps(uint8 _choice) public returns (uint8) {
      require (_choice == 1 || _choice == 2 || _choice == 3);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Store original state before any external calls
      uint8 originalLastMove = lastMove;
      address originalLastPlayer = lastPlayer;
      
      if (_choice == lastMove) {
        // External call before state update - vulnerable to reentrancy
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        tCoin.transfer(msg.sender, oneCoin);
        tCoin.transfer(lastPlayer, oneCoin);// send tie token to each player
        setGame(_choice, msg.sender);
        return 3; // it's a tie
      }
      if (_choice == 1) { //choice is block
        if (lastMove == 3) {
          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          // External call can trigger reentrancy, allowing state manipulation
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
          bCoin.transfer(msg.sender, oneCoin);
          emit newWinner(msg.sender);
          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          // State update happens after external call - vulnerable window
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          // External call using potentially stale lastPlayer state
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
          pCoin.transfer(lastPlayer, oneCoin);
          emit newWinner(lastPlayer);
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
      if (_choice == 2) { // choice is paper
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (originalLastMove == 1) {
          // External call with opportunity for reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
          pCoin.transfer(msg.sender, oneCoin);
          emit newWinner(msg.sender);
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          // Using original state that can be manipulated during reentrancy
          sCoin.transfer(originalLastPlayer, oneCoin);
          emit newWinner(originalLastPlayer);
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
      if (_choice == 3) { // choice is scissors
        if (lastMove == 2) {
          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          // External call creates reentrancy opportunity
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
          sCoin.transfer(msg.sender, oneCoin);
          emit newWinner(msg.sender);
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          // External call before state update - vulnerable to manipulation
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
          bCoin.transfer(lastPlayer, oneCoin);
          emit newWinner(lastPlayer);
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
    }

    function setGame(uint8 _move, address _player) private {
      lastMove = _move;
      lastPlayer = _player;
      emit newMove(_move);
    }

}

library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }

}