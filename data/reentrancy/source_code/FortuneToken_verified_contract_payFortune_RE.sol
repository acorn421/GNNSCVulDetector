/*
 * ===== SmartInject Injection Details =====
 * Function      : payFortune
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Moved External Calls Before State Updates**: Changed the order so that external calls to _fortune.owner and EthereumToken.owner happen before state modifications, creating a reentrancy window.
 * 
 * 2. **Replaced transfer() with call.value()**: Changed from the safer transfer() method to the vulnerable call.value() method which forwards all available gas and allows for reentrancy.
 * 
 * 3. **State Persistence Exploitation**: The vulnerability exploits the fact that state changes (buyer assignments, fortune creation) happen after external calls, allowing an attacker to manipulate the fortune state across multiple transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract and becomes the owner of a fortune through normal purchase flow.
 * 
 * **Transaction 2 (Trigger)**: When another user calls payFortune() to buy the attacker's fortune:
 * - The function calculates payment and calls the attacker's contract
 * - Attacker's contract receives the call and can now re-enter payFortune()
 * - During reentrant call, the state hasn't been updated yet, so the original conditions still hold
 * - Attacker can manipulate buyer assignments or create multiple fortune purchases
 * 
 * **Transaction 3+ (Repeated Exploitation)**: The attacker can continue to exploit the inconsistent state across multiple transactions, potentially:
 * - Receiving multiple payments for the same fortune
 * - Manipulating buyer slots to their advantage
 * - Creating duplicate fortunes by exploiting the state inconsistency
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first become a fortune owner (Transaction 1)
 * - The actual exploitation happens when someone else triggers the payment (Transaction 2)
 * - The full impact requires multiple reentrant calls to accumulate profits/manipulate state
 * - State changes from previous transactions enable the vulnerability in subsequent calls
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions and persistent state manipulation to be fully exploited.
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

    modifier onlyDev() {
    require(msg.sender == admin);
    _;
    }

    function FortuneToken() public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store original state before external calls
        bool wasBuyer1Empty = (_fortune.buyer1 == address(0));
        address originalOwner = _fortune.owner;
        
        // Make external calls before state updates (vulnerable pattern)
        if (_fortune.owner != address(this)) {
            uint256 payment = SafeMath.div(SafeMath.mul(_fortune.price, 90), 100);
            _fortune.owner.call.value(payment)("");
        }
        
        if (EthereumToken.owner != address(this)) {
            uint256 paymentEthereumTokenFortune = SafeMath.div(SafeMath.mul(_fortune.price, 5), 100);
            EthereumToken.owner.call.value(paymentEthereumTokenFortune)("");
        }
        
        // State updates after external calls (creates reentrancy window)
        if (wasBuyer1Empty) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function withdraw(address _to) public onlyDev{
        if (_to != address(0)) {
            _to.transfer(this.balance);
        } else {
            admin.transfer(this.balance);
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