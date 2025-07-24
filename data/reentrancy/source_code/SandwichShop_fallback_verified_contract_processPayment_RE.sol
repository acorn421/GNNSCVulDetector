/*
 * ===== SmartInject Injection Details =====
 * Function      : processPayment
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This function introduces a reentrancy vulnerability through the use of call.value() to send refunds. The vulnerability is stateful and multi-transaction because: 1) First transaction sets up the payment processing state with pendingPayments and paymentProcessing mappings, 2) The call.value() allows the recipient to re-enter the function before the state is cleared, 3) Multiple transactions can manipulate the payment processing state to drain funds. The vulnerability requires the attacker to first add items to cart, then call processPayment, and during the refund callback, re-enter to exploit the uncleared state.
 */
pragma solidity ^0.4.11;

contract mortal
{
    address owner;

    function mortal() { owner = msg.sender; }
    function kill() { if(msg.sender == owner) selfdestruct(owner); }
}

contract SandwichShop is mortal
{

    struct Sandwich
    {
        uint sandwichID;
        string sandwichName;
        string sandwichDesc;
        string calories;
        uint price;
        uint availableQuantity;
    }

    struct OrderedSandwich
    {
        uint sandID;
        string notes;
        uint price;
    }

    Sandwich[5] shopSandwich;
    mapping( address => OrderedSandwich[] ) public cart; 

    function SandwichShop() public
    {
        shopSandwich[0].sandwichID = 0;
        shopSandwich[0].sandwichName = "100: Ham & Swiss";
        shopSandwich[0].sandwichDesc = "Ham Swiss Mustard Rye";
        shopSandwich[0].calories = "450 calories";
        shopSandwich[0].price = 5;
        shopSandwich[0].availableQuantity = 200;

        shopSandwich[1].sandwichID = 1;
        shopSandwich[1].sandwichName = "101: Turkey & Pepperjack";
        shopSandwich[1].sandwichDesc = "Turkey Pepperjack Mayo White Bread";
        shopSandwich[1].calories = "500 calories";
        shopSandwich[1].price = 5;
        shopSandwich[1].availableQuantity = 200;

        shopSandwich[2].sandwichID = 2;
        shopSandwich[2].sandwichName = "102: Roast Beef & American";
        shopSandwich[2].sandwichDesc = "Roast Beef Havarti Horseradish White Bread";
        shopSandwich[2].calories = "600 calories";
        shopSandwich[2].price = 5;
        shopSandwich[2].availableQuantity = 200;

        shopSandwich[3].sandwichID = 3;
        shopSandwich[3].sandwichName = "103: Reuben";
        shopSandwich[3].sandwichDesc = "Corned Beef Sauerkraut Swiss Rye";
        shopSandwich[3].calories = "550 calories";
        shopSandwich[3].price = 5;
        shopSandwich[3].availableQuantity = 200;

        shopSandwich[4].sandwichID = 4;
        shopSandwich[4].sandwichName = "104: Italian";
        shopSandwich[4].sandwichDesc = "Salami Peppers Provolone Oil Vinegar White";
        shopSandwich[4].calories = "500 calories";
        shopSandwich[4].price = 5;
        shopSandwich[4].availableQuantity = 200;
    }

    function getMenu() constant returns (string, string, string, string, string)
    {
        return (shopSandwich[0].sandwichName, shopSandwich[1].sandwichName,
                shopSandwich[2].sandwichName, shopSandwich[3].sandwichName,
                shopSandwich[4].sandwichName );
    }

    function getSandwichInfoCaloriesPrice(uint _sandwich) constant returns (string, string, string, uint)
    {
        if( _sandwich > 4 )
        {
            return ( "wrong ID", "wrong ID", "zero", 0);
        }
        else
        {
            return (shopSandwich[_sandwich].sandwichName, shopSandwich[_sandwich].sandwichDesc,
                shopSandwich[_sandwich].calories, shopSandwich[_sandwich].price);
        }
    }

    function addToCart(uint _orderID, string _notes) returns (uint)
    {
        OrderedSandwich memory newOrder;
        newOrder.sandID = _orderID;
        newOrder.notes = _notes;
        newOrder.price = shopSandwich[_orderID].price;

        return cart[msg.sender].push(newOrder);
    }

    function getCartLength() constant returns (uint)
    {
        return cart[msg.sender].length;
    }

    function readFromCart(uint _spot) constant returns (string)
    {
        return cart[msg.sender][_spot].notes;
    }

    function emptyCart() public
    {
        delete cart[msg.sender];
    }


    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint) public pendingPayments;
    mapping(address => bool) public paymentProcessing;
    
    function processPayment() public payable {
        require(cart[msg.sender].length > 0, "Cart is empty");
        require(!paymentProcessing[msg.sender], "Payment already being processed");
        
        uint totalAmount = 0;
        for(uint i = 0; i < cart[msg.sender].length; i++) {
            totalAmount += cart[msg.sender][i].price;
        }
        
        require(msg.value >= totalAmount, "Insufficient payment");
        
        paymentProcessing[msg.sender] = true;
        pendingPayments[msg.sender] = msg.value - totalAmount; // Store refund amount
        
        // Process the order (vulnerable to reentrancy)
        if(msg.sender.call.value(pendingPayments[msg.sender])()) {
            // Payment successful, clear the cart
            delete cart[msg.sender];
            paymentProcessing[msg.sender] = false;
            pendingPayments[msg.sender] = 0;
        }
    }
    // === END FALLBACK INJECTION ===

}