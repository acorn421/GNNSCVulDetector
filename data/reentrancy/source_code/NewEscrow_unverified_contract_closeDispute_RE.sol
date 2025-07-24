/*
 * ===== SmartInject Injection Details =====
 * Function      : closeDispute
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
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Reordered Operations**: Moved external function calls (refund() and release()) to occur BEFORE state updates (orders[_orderID].status modifications)
 * 2. **Violated Checks-Effects-Interactions Pattern**: The original code properly updated state before external calls, but the modified version reverses this order
 * 3. **Created Reentrancy Window**: Between the external call and state update, there's now a vulnerability window where the contract state is inconsistent
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Phase 1 - Setup (Transaction 1):**
 * - Dispute is created using openDispute() function
 * - Order status is set to OrderStatus.Disputed
 * - disputeCreatedBy is set to msg.sender
 * 
 * **Phase 2 - Initial Exploitation (Transaction 2):**
 * - Attacker (who is the disputeCreatedBy) calls closeDispute()
 * - Function passes onlyDisputeEnder modifier check
 * - External call to refund() or release() is made BEFORE status update
 * - During the external call (which contains transfer operations), the attacker can reenter
 * 
 * **Phase 3 - Reentrancy Attack (Still within Transaction 2):**
 * - During the external call, attacker's contract receives control
 * - Order status is still OrderStatus.Disputed (not yet updated)
 * - Attacker can call closeDispute() again or other functions that depend on the current order status
 * - This creates inconsistent state where multiple payments might be processed
 * 
 * **Phase 4 - State Corruption (Transaction 3+):**
 * - After the reentrancy, the order status finally gets updated
 * - However, the contract state is now corrupted due to the reentrancy
 * - Future transactions will operate on this corrupted state
 * - Attacker can potentially claim both refund and release, or manipulate item quantities
 * 
 * **WHY MULTI-TRANSACTION DEPENDENCY IS REQUIRED:**
 * 
 * 1. **Dispute Setup Requirement**: The vulnerability requires a prior transaction to create the dispute (openDispute), setting the contract in the vulnerable state
 * 2. **State Persistence**: The dispute state persists between transactions, and the vulnerability exploits this persistent state
 * 3. **Authorization Dependencies**: The onlyDisputeEnder modifier checks against state set in previous transactions
 * 4. **External Call Complexity**: The refund/release functions contain transfer operations that provide the reentrancy opportunity, but the full exploitation requires the order state to be in a specific condition from prior transactions
 * 5. **Accumulated State Effects**: The vulnerability becomes more severe when combined with multiple orders and items created in previous transactions
 * 
 * **REALISTIC EXPLOITATION IMPACT:**
 * - Double spending: Attacker could receive both refund and payment release
 * - Item quantity manipulation: Inventory could be corrupted across multiple orders
 * - Order status inconsistency: Orders could be marked as both completed and refunded simultaneously
 * - Multi-order attacks: The vulnerability could be chained across multiple disputed orders to amplify the impact
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // External call before state update - vulnerable to reentrancy
                refund(_orderID, _itemId);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                orders[_orderID].status = OrderStatus.Refunded;
            }
            else if (_paymentSendTo == seller)
            {
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // External call before state update - vulnerable to reentrancy
                release(_orderID);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                orders[_orderID].status = OrderStatus.Completed;
            }
        }
        else if (msg.sender == orders[_orderID].customer)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call before state update - vulnerable to reentrancy
            release(_orderID);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            orders[_orderID].status = OrderStatus.Completed;
        }
        else if (msg.sender == seller)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call before state update - vulnerable to reentrancy
            refund(_orderID, _itemId);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            orders[_orderID].status = OrderStatus.Refunded;
        }
    }

}