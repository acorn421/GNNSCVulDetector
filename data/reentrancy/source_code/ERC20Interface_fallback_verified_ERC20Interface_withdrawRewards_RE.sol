/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 26 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a multi-transaction reentrancy vulnerability where: 1) Users first call claimReward() to accumulate rewards in pendingRewards mapping, 2) Then call withdrawRewards() which makes an external call before updating state, 3) A malicious contract can re-enter withdrawRewards() during the external call to drain more funds than intended. The vulnerability requires multiple transactions - first to build up rewards state, then to exploit during withdrawal.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public rewardWithdrawalInProgress;

    function claimReward() public {
        require(pendingRewards[msg.sender] > 0, "No rewards to claim");
        pendingRewards[msg.sender] = pendingRewards[msg.sender].add(oneCoin);
    }
    
    function withdrawRewards() public {
        require(pendingRewards[msg.sender] > 0, "No rewards to withdraw");
        require(!rewardWithdrawalInProgress[msg.sender], "Withdrawal already in progress");
        
        rewardWithdrawalInProgress[msg.sender] = true;
        uint256 reward = pendingRewards[msg.sender];
        
        // External call before state update - vulnerable to reentrancy
        if (msg.sender.call.value(reward)()) {
            pendingRewards[msg.sender] = 0;
            rewardWithdrawalInProgress[msg.sender] = false;
        } else {
            rewardWithdrawalInProgress[msg.sender] = false;
        }
    }
    // === END FALLBACK INJECTION ===

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
      if (_choice == lastMove) {
        tCoin.transfer(msg.sender, oneCoin);
        tCoin.transfer(lastPlayer, oneCoin);// send tie token to each player
        setGame(_choice, msg.sender);
        return 3; // it's a tie
      }
      if (_choice == 1) { //choice is block
        if (lastMove == 3) {
          bCoin.transfer(msg.sender, oneCoin);
          newWinner(msg.sender);
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          pCoin.transfer(lastPlayer, oneCoin);
          newWinner(lastPlayer);
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
      if (_choice == 2) { // choice is paper
        if (lastMove == 1) {
          pCoin.transfer(msg.sender, oneCoin);
          newWinner(msg.sender);
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          sCoin.transfer(lastPlayer, oneCoin);
          newWinner(lastPlayer);
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
      if (_choice == 3) { // choice is scissors
        if (lastMove == 2) {
          sCoin.transfer(msg.sender, oneCoin);
          newWinner(msg.sender);
          setGame(_choice, msg.sender);
          return 1;// win
          } else {
          bCoin.transfer(lastPlayer, oneCoin);
          newWinner(lastPlayer);
          setGame(_choice, msg.sender);
          return 2;//lose
          }
      }
    }

    function setGame(uint8 _move, address _player) private {
      lastMove = _move;
      lastPlayer = _player;
      newMove(_move);
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
