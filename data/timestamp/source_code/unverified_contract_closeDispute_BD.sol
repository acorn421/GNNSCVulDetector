/*
 * ===== SmartInject Injection Details =====
 * Function      : closeDispute
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding timing-dependent dispute resolution logic. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Initial State Setup**: The openDispute function must first be called to set orders[_orderID].disputeCreatedTime (requires contract modification to store this timestamp)
 * 
 * 2. **Time-Based Logic**: Added block.timestamp dependency for:
 *    - Admin override capabilities after 24 hours
 *    - Pseudo-random dispute resolution using timestamp modulo
 *    - Customer resolution restrictions based on elapsed time
 *    - Seller resolution outcomes based on timestamp parity
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Create dispute (sets disputeCreatedTime)
 *    - **Transaction 2**: Wait for favorable timestamp conditions
 *    - **Transaction 3**: Exploit timing-dependent resolution logic
 *    
 * 4. **Miner Manipulation**: Miners can manipulate block.timestamp (±900 seconds) to influence dispute outcomes, especially the modulo operations that determine resolution direction
 * 
 * The vulnerability is stateful because it depends on disputeCreatedTime stored in previous transactions and current block.timestamp comparisons. It's multi-transaction because the exploit requires dispute creation, time passage, and resolution attempts across separate transactions with specific timing conditions.
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
        uint256 disputeCreatedTime; // <-- Added missing field
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
    }
    
    function buyProduct(uint _itemId, uint _itemQuantity) public payable {
        require(msg.value > 0);
        require(msg.value == (items[_itemId].price * _itemQuantity));
        require(!orders[orderCount].paymentMade);
        require(msg.sender != seller && msg.sender != admin);
        orders[orderCount].paymentMade = true;
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
        orders[orderCount].disputeCreatedTime = 0; // <-- Initialize with zero
        
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
        orders[_orderID].disputeCreatedTime = block.timestamp; // <-- Set dispute created time
    }
    
    function closeDispute (uint256 _orderID,uint256 _itemId, address _paymentSendTo) external onlyDisputeEnder(_orderID,msg.sender){
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store dispute resolution attempt timestamp for timing-dependent logic
        uint256 resolutionAttemptTime = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (msg.sender == admin)
        {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Admin can override any dispute resolution after 24 hours
            if (resolutionAttemptTime > orders[_orderID].disputeCreatedTime + 86400) {
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
            // Within 24 hours, admin decisions are timestamp-dependent
            else {
                // Use block timestamp for pseudo-randomness in dispute resolution
                uint256 timeBasedDecision = block.timestamp % 2;
                if (timeBasedDecision == 0) {
                    orders[_orderID].status = OrderStatus.Refunded;
                    refund(_orderID, _itemId);
                } else {
                    orders[_orderID].status = OrderStatus.Completed;
                    release(_orderID);
                }
            }
        }
        else if (msg.sender == orders[_orderID].customer)
        {
            // Customer can only close dispute if sufficient time has passed
            if (resolutionAttemptTime > orders[_orderID].disputeCreatedTime + 172800) { // 48 hours
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                orders[_orderID].status = OrderStatus.Completed;
                release(_orderID);
            }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
        else if (msg.sender == seller)
        {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Seller resolution depends on timing - favor seller on odd timestamps
            if (block.timestamp % 2 == 1) {
                orders[_orderID].status = OrderStatus.Completed;
                release(_orderID);
            } else {
                orders[_orderID].status = OrderStatus.Refunded;
                refund(_orderID, _itemId);
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
    }

}
