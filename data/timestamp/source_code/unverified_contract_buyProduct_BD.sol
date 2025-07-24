/*
 * ===== SmartInject Injection Details =====
 * Function      : buyProduct
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through:
 * 
 * 1. **Time-based Dynamic Pricing**: The function now calculates prices based on `block.timestamp` using hourly variations. The price changes every hour based on `(timeSinceStart % 86400) / 3600`, creating a 24-hour cycle where prices fluctuate predictably.
 * 
 * 2. **Quota Reset Mechanism**: Added a daily purchase limit system that resets based on `block.timestamp`. The `lastQuotaReset` and `dailyPurchaseCount` state variables track when quotas reset and how many items each user has purchased.
 * 
 * 3. **Persistent State Dependencies**: The vulnerability requires multiple state variables (`lastQuotaReset`, `dailyPurchaseCount`, `orders[].purchaseTimestamp`) that persist between transactions and depend on timestamp values.
 * 
 * **Multi-Transaction Exploitation:**
 * - **Price Manipulation**: Miners can manipulate `block.timestamp` to get favorable pricing across multiple purchase transactions
 * - **Quota Reset Abuse**: Attackers can force premature quota resets by manipulating timestamps, allowing them to exceed daily limits through multiple transactions
 * - **Timing Attacks**: Users can time their purchases to exploit price cycles and quota resets
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction cannot accumulate purchase history needed for quota exploitation
 * - Price manipulation benefits require multiple purchases to be profitable
 * - Quota reset exploitation requires building up purchase history in earlier transactions, then manipulating timestamp in later transactions to reset limits
 * - The vulnerability emerges from the interaction between historical state and current timestamp-dependent calculations
 * 
 * This creates a realistic vulnerability where the timestamp dependence interacts with stateful purchase tracking, making it exploitable only through coordinated multi-transaction attacks.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-06-19
*/

pragma solidity ^0.4.24;

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

library SafeMath {

  
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

 
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract NewEscrow is Ownable {

    enum OrderStatus { Pending, Completed, Refunded, Disputed }

    event PaymentCreation(uint indexed orderId, address indexed customer, uint value);
    event PaymentCompletion(uint indexed orderId, address indexed customer, uint value, OrderStatus status);
    
    uint orderCount;

    // === ADDED for daily quota mechanism ===
    mapping(address => uint256) public dailyPurchaseCount;
    uint256 public lastQuotaReset;
    // =======================================
    
    struct Order {
        uint orderId;
        address customer;
        uint value;
        OrderStatus status;
        uint quantity;
        uint itemId;
        address disputeCreatedBy;
        bool paymentStatus;
        bool paymentMade;
        // ADDED property for purchase tracking per order
        uint256 purchaseTimestamp;
        
    }
    
    struct Item {
        uint quantity;
        string name;
        uint price;
    }
    
    mapping(uint => Item) public items;
    mapping(uint => Order) public orders;
    
    address public admin;
    address public seller;    
    
    modifier onlyDisputed(uint256 _orderID) {
        require(orders[_orderID].status != OrderStatus.Disputed);
        _;
    }
    
    modifier onlySeller() {
        require(msg.sender == seller);
        _;
    }
    
    modifier onlyDisputeEnder(uint256 _orderID,address _caller) {
        require(_caller == admin || _caller == orders[_orderID].disputeCreatedBy);
        _;
    }
    
    modifier onlyDisputeCreater(uint256 _orderID,address _caller) {
        require(_caller == seller || _caller == orders[_orderID].customer);
        _;
    }
    
     modifier onlyAdminOrBuyer(uint256 _orderID, address _caller) {
        require( _caller == admin || _caller == orders[_orderID].customer);
        _;
    }
    
     modifier onlyBuyer(uint256 _orderID, address _caller) {
        require(_caller == orders[_orderID].customer);
        _;
    }
    
    
    modifier onlyAdminOrSeller(address _caller) {
        require(_caller == admin || _caller == seller);
        _;
    }
    
    constructor (address _seller) public {
        admin = 0x382468fb5070Ae19e9D82ec388e79AE4e43d890D;
        seller = _seller;
        orderCount = 1;
        lastQuotaReset = block.timestamp;
    }
    
    function buyProduct(uint _itemId, uint _itemQuantity) public payable {
        require(msg.value > 0);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        require(msg.sender != seller && msg.sender != admin);
        
        // Time-based dynamic pricing that creates timestamp dependency
        uint timeSinceStart = block.timestamp - 1560000000; // Contract deployment timestamp
        uint priceMultiplier = 100 + (timeSinceStart % 86400) / 3600; // Price varies by hour of day
        uint dynamicPrice = (items[_itemId].price * priceMultiplier) / 100;
        
        require(msg.value == (dynamicPrice * _itemQuantity));
        require(!orders[orderCount].paymentMade);
        
        // Store timestamp for quota reset mechanism
        if (block.timestamp >= lastQuotaReset + 86400) {
            dailyPurchaseCount[msg.sender] = 0;
            lastQuotaReset = block.timestamp;
        }
        
        // Check daily purchase limit
        require(dailyPurchaseCount[msg.sender] + _itemQuantity <= 10);
        
        orders[orderCount].paymentMade = true;
        orders[orderCount].purchaseTimestamp = block.timestamp;
        dailyPurchaseCount[msg.sender] += _itemQuantity;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        createPayment(_itemId, msg.sender, _itemQuantity);
    }
    
    function createPayment(uint _itemId, address _customer, uint _itemQuantity) internal {
       
        require(items[_itemId].quantity >= _itemQuantity);
    
        orders[orderCount].orderId = orderCount;
        
        items[_itemId].quantity = items[_itemId].quantity - _itemQuantity;
        
        uint totalPrice = _itemQuantity * items[_itemId].price;
        
        orders[orderCount].value = totalPrice;
        orders[orderCount].quantity = _itemQuantity;
        orders[orderCount].customer = _customer;
        orders[orderCount].itemId = _itemId;
        orders[orderCount].status = OrderStatus.Pending;
        
        emit PaymentCreation(orderCount, _customer, totalPrice);
        orderCount = orderCount + 1;
    }
    
    function addItem(uint _itemId, string _itemName, uint _quantity, uint _price) external onlySeller  {

        items[_itemId].name = _itemName;
        items[_itemId].quantity = _quantity;
        items[_itemId].price = _price;
    }
    
    
    function release(uint _orderId) public onlyDisputed(_orderId) onlyAdminOrBuyer(_orderId,msg.sender) {
    
        completePayment(_orderId, seller, OrderStatus.Completed);
        
    }
    
    function refund(uint _orderId, uint _itemId) public onlyDisputed(_orderId) onlyAdminOrSeller(msg.sender){
        
        items[_itemId].quantity = items[_itemId].quantity + orders[_orderId].quantity;
        
        incompletePayment(_orderId, orders[_orderId].customer, OrderStatus.Refunded);
    }


    function completePayment(uint _orderId, address _receiver, OrderStatus _status) private {
        require(orders[_orderId].paymentStatus != true);
        
        Order storage payment = orders[_orderId];
     
        uint adminSupply = SafeMath.div(SafeMath.mul(orders[_orderId].value, 7), 100);
        
        uint sellerSupply = SafeMath.div(SafeMath.mul(orders[_orderId].value, 93), 100);
        
        _receiver.transfer(sellerSupply);
        
        admin.transfer(adminSupply);
        
        orders[_orderId].status = _status;
        
        orders[_orderId].paymentStatus = true;
        
        emit PaymentCompletion(_orderId, _receiver, payment.value, _status);
    }
    
    function incompletePayment(uint _orderId, address _receiver, OrderStatus _status) private {
        require(orders[_orderId].paymentStatus != true);                        
        
        Order storage payment = orders[_orderId];
        
        _receiver.transfer(orders[_orderId].value);
       
        orders[_orderId].status = _status;
        
        orders[_orderId].paymentStatus = true;
        
        emit PaymentCompletion(_orderId, _receiver, payment.value, _status);
    }
    
     function openDispute (uint256 _orderID) external onlyDisputeCreater(_orderID,msg.sender){ 
        orders[_orderID].status = OrderStatus.Disputed;
        orders[_orderID].disputeCreatedBy = msg.sender;
    }
    
    function closeDispute (uint256 _orderID,uint256 _itemId, address _paymentSendTo) external onlyDisputeEnder(_orderID,msg.sender){
        if (msg.sender == admin)
        {
            if (_paymentSendTo == orders[_orderID].customer)
            {
                orders[_orderID].status = OrderStatus.Refunded;
                refund(_orderID, _itemId);
            }
            else if (_paymentSendTo == seller)
            {
                orders[_orderID].status = OrderStatus.Completed;
                release(_orderID);
            }
        }
        else if (msg.sender == orders[_orderID].customer)
        {
            orders[_orderID].status = OrderStatus.Completed;
            release(_orderID);
        }
        else if (msg.sender == seller)
        {
            orders[_orderID].status = OrderStatus.Refunded;
            refund(_orderID, _itemId);
        }
    }

}
