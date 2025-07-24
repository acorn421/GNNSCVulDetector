/*
 * ===== SmartInject Injection Details =====
 * Function      : payFortune
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based discount mechanisms that rely on block.timestamp and persist state across transactions. The vulnerability requires multiple transactions to exploit: 1) First transaction establishes the timestamp baseline, 2) Attacker waits or manipulates time, 3) Second transaction exploits the accumulated time-based discount. The lastPurchaseTime field in Fortune struct maintains state between transactions, and the discount calculation uses block.timestamp for critical pricing logic. Miners can manipulate block timestamps to exploit discounts, and the timestamp-based pricing seed for new fortunes creates additional manipulation opportunities.
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
        uint lastPurchaseTime; // <-- Added missing field
    }

    EtherFortuneToken private EthereumToken;

    Fortune[] private fortunes;

    modifier onlyDev() {
    require(msg.sender == admin);
    _;
    }

    constructor() public { // <-- Changed deprecated constructor syntax
      admin = msg.sender;

      Fortune memory _fortune = Fortune({
          owner: address(this),
          buyer1: address(0),
          buyer2: address(0),
          price: fortuneInitValue,
          buyers: 0,
          lastPurchaseTime: 0 // <-- Initialize new field
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Apply time-based discount if fortune has been available for more than 1 hour
        uint256 effectivePrice = _fortune.price;
        if (_fortune.buyers == 0) {
            // Store initial listing timestamp on first interaction
            _fortune.lastPurchaseTime = block.timestamp;
        } else {
            // Calculate time-based discount for subsequent purchases
            uint256 timeSinceLastPurchase = block.timestamp - _fortune.lastPurchaseTime;
            if (timeSinceLastPurchase > 3600) { // 1 hour
                uint256 discountPercent = SafeMath.div(timeSinceLastPurchase, 3600); // 1% per hour
                if (discountPercent > 50) discountPercent = 50; // Max 50% discount
                effectivePrice = SafeMath.div(SafeMath.mul(_fortune.price, SafeMath.sub(100, discountPercent)), 100);
            }
        }
        
        // Refund excess payment if discounted price is lower
        if (msg.value > effectivePrice) {
            msg.sender.transfer(msg.value - effectivePrice);
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (_fortune.buyer1 == address(0)) {
            _fortune.buyer1 = msg.sender;
            _fortune.buyers++;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            _fortune.lastPurchaseTime = block.timestamp;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        } else {
            _fortune.buyer2 = msg.sender;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            _fortune.lastPurchaseTime = block.timestamp;
            
            // Use stored timestamp for new fortune pricing
            uint256 newFortunePrice = SafeMath.div(SafeMath.mul(effectivePrice, 100), 90);
            uint256 timestampSeed = _fortune.lastPurchaseTime % 1000;
            if (timestampSeed > 500) {
                newFortunePrice = SafeMath.div(SafeMath.mul(newFortunePrice, 110), 100);
            }
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            Fortune memory newFortune1 = Fortune({
                owner: _fortune.buyer1,
                buyer1: address(0),
                buyer2: address(0),
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                price: newFortunePrice,
                buyers: 0,
                lastPurchaseTime: 0
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            });
            Fortune memory newFortune2 = Fortune({
                owner: _fortune.buyer2,
                buyer1: address(0),
                buyer2: address(0),
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                price: newFortunePrice,
                buyers: 0,
                lastPurchaseTime: 0
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            });
            fortunes.push(newFortune1);
            fortunes.push(newFortune2);
            _fortune.buyers++;
        }
        if (_fortune.owner != address(this)) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            uint256 payment = SafeMath.div(SafeMath.mul(effectivePrice, 90), 100);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            _fortune.owner.transfer(payment);
        }
        if (EthereumToken.owner != address(this)) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            uint256 paymentEthereumTokenFortune = SafeMath.div(SafeMath.mul(effectivePrice, 5), 100);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
