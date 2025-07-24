/*
 * ===== SmartInject Injection Details =====
 * Function      : buyEthereumToken
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding time-based discount and pricing mechanisms that depend on block.timestamp modulo operations. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added time-based discount system using `block.timestamp % 60` that provides 10% discount in first 30 seconds of each minute
 * 2. Modified payment calculation to apply timestamp-dependent discounts to previous owner payments
 * 3. Introduced dynamic pricing based on `block.timestamp % 120` that creates 2-minute cycles with different price multipliers
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1 (Setup)**: Attacker observes current timestamp patterns and identifies upcoming discount/pricing windows
 * 2. **Transaction 2 (Timing Attack)**: Attacker times purchase during favorable timestamp windows (first 30 seconds of minute for discount)
 * 3. **Transaction 3 (Profit)**: Attacker exploits predictable pricing cycles to buy at lower effective prices or sell at higher prices
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires observing timestamp patterns across multiple blocks to identify exploitation windows
 * - State changes from previous transactions (price increases) compound with timestamp-dependent calculations
 * - Miners can manipulate block.timestamp within 15-second windows across multiple transactions to consistently hit favorable timing
 * - The discount system creates predictable 30-second windows that require precise timing across multiple transactions
 * 
 * **Exploitation Example:**
 * - Transaction 1: Buy token at timestamp ending in :45 (no discount, standard pricing)
 * - Transaction 2: Sell/transfer when timestamp is :15 (10% discount applied to payments, favorable pricing cycle)
 * - This creates a systematic advantage that compounds over multiple transactions
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based discount system that creates predictable exploitation windows
        uint256 timeBasedDiscount = 0;
        if (block.timestamp % 60 < 30) {
            timeBasedDiscount = 10; // 10% discount in first 30 seconds of each minute
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        address newOwner = msg.sender;
        if (EthereumToken.owner != address(this)) {
            uint256 payment = SafeMath.div(SafeMath.mul(EthereumToken.price, 90), 100);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Apply time-based discount to payment - vulnerability point
            if (timeBasedDiscount > 0) {
                payment = SafeMath.div(SafeMath.mul(payment, SafeMath.sub(100, timeBasedDiscount)), 100);
            }
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            EthereumToken.owner.transfer(payment);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        EthereumToken.owner = newOwner;
        
        // Price calculation now depends on block timestamp for "dynamic pricing"
        uint256 basePrice = SafeMath.div(SafeMath.mul(EthereumToken.price, 120), 90);
        
        // Timestamp-dependent price adjustment - creates manipulation opportunity
        if (block.timestamp % 120 < 60) {
            // Price increases more during first half of 2-minute cycles
            EthereumToken.price = SafeMath.div(SafeMath.mul(basePrice, 110), 100);
        } else {
            // Standard price during second half
            EthereumToken.price = basePrice;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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