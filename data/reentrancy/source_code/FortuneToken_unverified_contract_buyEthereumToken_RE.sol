/*
 * ===== SmartInject Injection Details =====
 * Function      : buyEthereumToken
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
 * 1. **Added state tracking**: `reentrantCallCount[msg.sender]` tracks the number of calls per address across transactions
 * 2. **Preserved external call placement**: The `transfer()` call remains before state updates, maintaining the reentrancy opportunity
 * 3. **Created multi-transaction dependency**: The vulnerability depends on accumulated call count from previous transactions
 * 4. **Introduced state inconsistency**: When `previousCallCount > 0`, the function returns early after payment but before ownership transfer, creating exploitable state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * Transaction 1: Attacker calls `buyEthereumToken()` with a contract that has a fallback function. During the `transfer()` call, the fallback triggers but `reentrantCallCount[attacker] = 1` now. The first call completes normally.
 * 
 * Transaction 2: Attacker calls `buyEthereumToken()` again. Now `previousCallCount = 1`, so when the `transfer()` happens and reentrancy is triggered, the function returns early after payment but before updating ownership and price. This allows the attacker to:
 * - Receive payment for the "sale" without transferring ownership
 * - Keep the price artificially low by preventing the price update
 * - Potentially drain funds through repeated exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the accumulated state (`reentrantCallCount`) from previous transactions
 * - A single transaction cannot exploit this because `previousCallCount` starts at 0
 * - The attacker needs multiple transactions to build up the call count that triggers the vulnerable early return path
 * - The state persistence between transactions is what makes the vulnerability exploitable
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

    // ADDED missing state variable for vulnerability (reentrancy tracking)
    mapping(address => uint256) reentrantCallCount;

    modifier onlyDev() {
    require(msg.sender == admin);
    _;
    }

    // SOLIDITY 0.4: Use constructor syntax per warning
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track reentrancy attempts across transactions
        uint256 previousCallCount = reentrantCallCount[msg.sender];
        reentrantCallCount[msg.sender] = reentrantCallCount[msg.sender] + 1;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        address newOwner = msg.sender;
        if (EthereumToken.owner != address(this)) {
            uint256 payment = SafeMath.div(SafeMath.mul(EthereumToken.price, 90), 100);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Vulnerable: External call before state updates, with accumulated state dependency
            EthereumToken.owner.transfer(payment);
            
            // Multi-transaction vulnerability: Only update if not first call in sequence
            if (previousCallCount > 0) {
                // Skip ownership transfer for accumulated calls, creating state inconsistency
                return;
            }
        }
        
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        EthereumToken.owner = newOwner;
        EthereumToken.price = SafeMath.div(SafeMath.mul(EthereumToken.price, 120), 90);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Reset counter after successful purchase (but after state changes)
        reentrantCallCount[msg.sender] = 0;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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