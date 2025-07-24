/*
 * ===== SmartInject Injection Details =====
 * Function      : addToCart
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based dynamic pricing and loyalty rewards system. The vulnerability includes:
 * 
 * 1. **Happy Hour Discount**: Uses block.timestamp to determine if orders placed between 2-4 PM get 20% discount, allowing miners to manipulate timestamps for favorable pricing.
 * 
 * 2. **Rapid Order Loyalty System**: Tracks order timing intervals and provides progressive discounts (5% per rapid order, max 50%) for orders placed within 300 seconds of the previous order. This creates a stateful vulnerability where:
 *    - customerLastOrderTime[msg.sender] stores the timestamp of each user's last order
 *    - customerRapidOrderCount[msg.sender] accumulates the count of rapid orders
 *    - Both values persist between transactions and influence future pricing
 * 
 * **Multi-Transaction Exploitation**:
 * - First transaction establishes the base timestamp in customerLastOrderTime
 * - Subsequent transactions within 300 seconds build up rapidOrderCount for increasing discounts
 * - Miners can manipulate block.timestamp across multiple transactions to:
 *   a) Ensure all orders fall within happy hour pricing
 *   b) Maintain the 300-second rapid order window across multiple blocks
 *   c) Accumulate maximum loyalty discounts through timestamp manipulation
 * 
 * **State Variables Required** (to be added to contract):
 * ```solidity
 * mapping(address => uint) customerLastOrderTime;
 * mapping(address => uint) customerRapidOrderCount;
 * ```
 * 
 * The vulnerability is realistic as time-based pricing and loyalty programs are common in food service, but the dependence on manipulable block.timestamp creates genuine security risks that require multiple transactions to fully exploit.
 */
pragma solidity ^0.4.11;

contract mortal
{
    address owner;

    function mortal() public { owner = msg.sender; }
    function kill() public { if(msg.sender == owner) selfdestruct(owner); }
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
    mapping( address => uint ) public customerLastOrderTime;
    mapping( address => uint ) public customerRapidOrderCount;

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

    function getMenu() public constant returns (string, string, string, string, string)
    {
        return (shopSandwich[0].sandwichName, shopSandwich[1].sandwichName,
                shopSandwich[2].sandwichName, shopSandwich[3].sandwichName,
                shopSandwich[4].sandwichName );
    }

    function getSandwichInfoCaloriesPrice(uint _sandwich) public constant returns (string, string, string, uint)
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

    function addToCart(uint _orderID, string _notes) public returns (uint)
    {
        OrderedSandwich memory newOrder;
        newOrder.sandID = _orderID;
        newOrder.notes = _notes;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based dynamic pricing with loyalty rewards
        uint basePrice = shopSandwich[_orderID].price;
        uint finalPrice = basePrice;
        
        // Apply time-of-day discount (vulnerable to timestamp manipulation)
        uint hourOfDay = (block.timestamp / 3600) % 24;
        if (hourOfDay >= 14 && hourOfDay <= 16) {
            finalPrice = basePrice * 8 / 10; // 20% happy hour discount
        }
        
        // Multi-order loyalty discount based on timestamp intervals
        if (cart[msg.sender].length > 0) {
            uint lastOrderTime = customerLastOrderTime[msg.sender];
            uint timeSinceLastOrder = block.timestamp - lastOrderTime;
            
            // Rapid order bonus: orders within 300 seconds get progressive discounts
            if (timeSinceLastOrder <= 300) {
                uint rapidOrderCount = customerRapidOrderCount[msg.sender] + 1;
                customerRapidOrderCount[msg.sender] = rapidOrderCount;
                
                // Progressive discount: 5% off per rapid order, max 50%
                uint rapidDiscount = (rapidOrderCount * 5 < 50) ? rapidOrderCount * 5 : 50;
                finalPrice = finalPrice * (100 - rapidDiscount) / 100;
            } else {
                customerRapidOrderCount[msg.sender] = 0; // Reset counter
            }
        }
        
        newOrder.price = finalPrice;
        customerLastOrderTime[msg.sender] = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        return cart[msg.sender].push(newOrder);
    }

    function getCartLength() public constant returns (uint)
    {
        return cart[msg.sender].length;
    }

    function readFromCart(uint _spot) public constant returns (string)
    {
        return cart[msg.sender][_spot].notes;
    }

    function emptyCart() public
    {
        delete cart[msg.sender];
    }

}
