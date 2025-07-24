/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
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
 * 1. **Added State Variables**: Introduced `withdrawalInProgress` boolean and `pendingWithdrawals` mapping to track withdrawal state across transactions.
 * 
 * 2. **Checks-Effects-Interactions Violation**: Moved critical state updates (`withdrawalInProgress = false` and `pendingWithdrawals[_to] = 0`) to occur AFTER the external `transfer()` call, creating a reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Admin calls `withdraw()` with a malicious contract address
 *    - **During Transaction 1**: The malicious contract's fallback function is triggered by `transfer()` and can call back into the contract
 *    - **Transaction 2**: While `withdrawalInProgress` is still `true` and `pendingWithdrawals` is set, the malicious contract can exploit the inconsistent state
 *    - **State Persistence**: The vulnerability depends on state that persists between the external call and the state cleanup
 * 
 * 4. **Multi-Transaction Requirement**: The vulnerability cannot be exploited in a single transaction because:
 *    - The initial state setup (`withdrawalInProgress = true`, `pendingWithdrawals[_to] = balance`) happens before the external call
 *    - The reentrancy window exists between the external call and state cleanup
 *    - An attacker needs the state to be in an inconsistent state across multiple call frames
 *    - The malicious contract can use the persistent state to call other functions or manipulate contract behavior during the reentrancy
 * 
 * 5. **Realistic Implementation**: The changes appear to be legitimate improvements (adding withdrawal tracking and progress flags) but introduce a critical security flaw through improper state management order.
 */
pragma solidity ^0.4.18;

contract FortuneToken {
    address public admin;

    uint ethereumTokenInitValue = 5 ether;

    uint fortuneInitValue = 1 ether;

    struct EtherFortuneToken {
        address owner;
        uint price;
    }

    struct Fortune {
        address owner;
        address buyer1;
        address buyer2;
        uint price;
        uint buyers;
    }

    EtherFortuneToken private EthereumToken;

    Fortune[] private fortunes;

    // Added missing state variables for reentrancy vulnerability
    mapping(address => uint) public pendingWithdrawals;
    bool public withdrawalInProgress;

    modifier onlyDev() {
        require(msg.sender == admin);
        _;
    }

    // Updated constructor style
    constructor() public {
        admin = msg.sender;

        Fortune memory _fortune = Fortune({
            owner: address(this),
            buyer1: address(0),
            buyer2: address(0),
            price: fortuneInitValue,
            buyers: 0
        });

        fortunes.push(_fortune);

        EtherFortuneToken memory _fortuneEthereumToken = EtherFortuneToken({
            owner: address(this),
            price: ethereumTokenInitValue
        });

        EthereumToken = _fortuneEthereumToken;
    }

    function getFortune(uint id) public view returns (address owner, address buyer1, address buyer2, uint price, uint buyers) {
        Fortune storage _fortune = fortunes[id];
        owner = _fortune.owner;
        buyer1 = _fortune.buyer1;
        buyer2 = _fortune.buyer2;
        price = _fortune.price;
        buyers = _fortune.buyers;
    }

    function payFortune(uint id) public payable{
        Fortune storage _fortune = fortunes[id];
        require(_fortune.buyer1 == address(0) || _fortune.buyer2 == address(0));
        require(msg.value == _fortune.price);
        if (_fortune.buyer1 == address(0)) {
            _fortune.buyer1 = msg.sender;
            _fortune.buyers++;
        } else {
            _fortune.buyer2 = msg.sender;
            Fortune memory newFortune1 = Fortune({
                owner: _fortune.buyer1,
                buyer1: address(0),
                buyer2: address(0),
                price: SafeMath.div(SafeMath.mul(_fortune.price, 100), 90),
                buyers: 0
            });
            Fortune memory newFortune2 = Fortune({
                owner: _fortune.buyer2,
                buyer1: address(0),
                buyer2: address(0),
                price: SafeMath.div(SafeMath.mul(_fortune.price, 100), 90),
                buyers: 0
            });
            fortunes.push(newFortune1);
            fortunes.push(newFortune2);
            _fortune.buyers++;
        }
        if (_fortune.owner != address(this)) {
            uint256 payment = SafeMath.div(SafeMath.mul(_fortune.price, 90), 100);
            _fortune.owner.transfer(payment);
        }
        if (EthereumToken.owner != address(this)) {
            uint256 paymentEthereumTokenFortune = SafeMath.div(SafeMath.mul(_fortune.price, 5), 100);
            EthereumToken.owner.transfer(paymentEthereumTokenFortune);
        }
    }

    function buyEthereumToken() public payable {
        require(EthereumToken.price == msg.value);
        require(EthereumToken.owner != msg.sender);
        address newOwner = msg.sender;
        if (EthereumToken.owner != address(this)) {
            uint256 payment = SafeMath.div(SafeMath.mul(EthereumToken.price, 90), 100);
            EthereumToken.owner.transfer(payment);
        }
        EthereumToken.owner = newOwner;
        EthereumToken.price = SafeMath.div(SafeMath.mul(EthereumToken.price, 120), 90);

    }

    function getEthereumToken() public view returns (address owner, uint price) {
        EtherFortuneToken storage _fortuneEthereumToken = EthereumToken;
        owner = _fortuneEthereumToken.owner;
        price = _fortuneEthereumToken.price;
    }

    function totalFortunes() public view returns (uint) {
        return fortunes.length;
    }

    function getBalance() public view returns (uint) {
        return this.balance;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State variables to add to the contract:
// mapping(address => uint) public pendingWithdrawals;
// bool public withdrawalInProgress;

    function withdraw(address _to) public onlyDev {
        require(!withdrawalInProgress);
        
        withdrawalInProgress = true;
        
        if (_to != address(0)) {
            // Set pending withdrawal amount before external call
            pendingWithdrawals[_to] = this.balance;
            
            // External call that allows reentrancy
            _to.transfer(this.balance);
            
            // State update after external call - VULNERABLE
            withdrawalInProgress = false;
            pendingWithdrawals[_to] = 0;
        } else {
            pendingWithdrawals[admin] = this.balance;
            
            // External call that allows reentrancy
            admin.transfer(this.balance);
            
            // State update after external call - VULNERABLE
            withdrawalInProgress = false;
            pendingWithdrawals[admin] = 0;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
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
